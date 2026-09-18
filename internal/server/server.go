// Package server exposes TrustGate as an MCP server.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trustgate/internal/attest"
	"trustgate/internal/canon"
	"trustgate/internal/receipts"
	"trustgate/internal/registry"
	"trustgate/internal/runtime"
	"trustgate/internal/verify"
)

// Config wires the server's dependencies.
type Config struct {
	Tenant   string
	Registry *registry.Registry
	Signer   *receipts.Signer
	Provider attest.Provider
	// DevTrust is set only in dev mode so verify_receipt can check dev docs.
	DevTrust []byte
	// Token, if non-empty, is required as a Bearer token on /mcp.
	Token string
}

// Server holds runtime state.
type Server struct {
	cfg         Config
	attestation []byte
	jobs        *jobStore
}

// New creates the server and obtains the boot attestation document that binds
// the receipt-signing key to this environment.
func New(cfg Config) (*Server, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	doc, err := cfg.Provider.Attest(cfg.Signer.PublicKey(), nonce)
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	s := &Server{cfg: cfg, attestation: doc}
	s.jobs = newJobStore(s)
	return s, nil
}

type ExecuteInput struct {
	Workload  string   `json:"workload" jsonschema:"workload name or sha256:<hex> from list_workloads"`
	Input     string   `json:"input,omitempty" jsonschema:"UTF-8 text passed to the workload on stdin (use input_b64 for binary data; set only one)"`
	InputB64  string   `json:"input_b64,omitempty" jsonschema:"base64-encoded bytes passed to the workload on stdin, for binary data (set only one of input and input_b64)"`
	Args      []string `json:"args,omitempty" jsonschema:"command-line arguments for the workload"`
	MemoryMB  uint32   `json:"memory_mb,omitempty" jsonschema:"memory limit in MB; defaults to and may not exceed the workload manifest maximum"`
	TimeoutMS uint32   `json:"timeout_ms,omitempty" jsonschema:"time limit in ms; defaults to and may not exceed the workload manifest maximum"`
}

// stdin returns the raw input bytes described by the request.
func stdinBytes(text, b64 string) ([]byte, error) {
	if text != "" && b64 != "" {
		return nil, errors.New("set only one of input and input_b64")
	}
	if b64 == "" {
		return []byte(text), nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("input_b64 is not valid base64: %w", err)
	}
	return raw, nil
}

type ExecuteOutput struct {
	Status  string         `json:"status"`
	Output  string         `json:"output"`
	Stderr  string         `json:"stderr,omitempty"`
	Receipt map[string]any `json:"receipt_bundle" jsonschema:"signed receipt plus attestation; pass to verify_receipt, replay or the trustgate CLI"`
}

// prepared is a validated execution request.
type prepared struct {
	wl    *registry.Workload
	lim   runtime.Limits
	stdin []byte
	args  []string
}

// prepare validates a request without running anything, so bad requests are
// rejected up front (including for async jobs).
func (s *Server) prepare(in ExecuteInput) (*prepared, error) {
	wl, ok := s.cfg.Registry.Get(in.Workload)
	if !ok {
		return nil, fmt.Errorf("unknown workload %q", in.Workload)
	}
	m := wl.Manifest
	lim := runtime.Limits{MemoryMB: m.MaxMemoryMB, TimeoutMS: m.MaxTimeoutMS}
	if in.MemoryMB != 0 {
		if in.MemoryMB > m.MaxMemoryMB {
			return nil, fmt.Errorf("memory_mb %d exceeds workload maximum %d", in.MemoryMB, m.MaxMemoryMB)
		}
		lim.MemoryMB = in.MemoryMB
	}
	if in.TimeoutMS != 0 {
		if in.TimeoutMS > m.MaxTimeoutMS {
			return nil, fmt.Errorf("timeout_ms %d exceeds workload maximum %d", in.TimeoutMS, m.MaxTimeoutMS)
		}
		lim.TimeoutMS = in.TimeoutMS
	}
	stdin, err := stdinBytes(in.Input, in.InputB64)
	if err != nil {
		return nil, err
	}
	return &prepared{wl: wl, lim: lim, stdin: stdin, args: append([]string{}, in.Args...)}, nil
}

// runPrepared executes and signs a receipt. runErr is the execution outcome
// (still accompanied by a signed receipt); err is an internal failure. A
// cancelled run returns context.Canceled in runErr with no receipt.
func (s *Server) runPrepared(ctx context.Context, p *prepared) (out ExecuteOutput, runErr, err error) {
	m := p.wl.Manifest
	res, runErr := runtime.Run(ctx, p.wl.Wasm, p.stdin, p.args, p.lim)
	if errors.Is(runErr, context.Canceled) {
		return ExecuteOutput{}, runErr, nil
	}

	var stdout, stderr []byte
	rec := receipts.Receipt{
		Tenant:          s.cfg.Tenant,
		Workload:        m.Name + "@" + m.Version,
		CodeSHA256:      m.SHA256,
		Args:            p.args,
		Inputs:          []receipts.InputRef{{Name: "stdin", SHA256: canon.SHA256(p.stdin)}},
		Runtime:         receipts.Runtime{Engine: runtime.Engine, Profile: m.Profile},
		Limits:          receipts.Limits{MemoryMB: p.lim.MemoryMB, TimeoutMS: p.lim.TimeoutMS},
		AttestationMode: s.cfg.Provider.Mode(),
	}
	if res != nil {
		stdout, stderr = res.Stdout, res.Stderr
		rec.Execution.ExitCode = res.ExitCode
		rec.Execution.DurationMS = res.Duration.Milliseconds()
	}
	rec.OutputSHA256 = canon.SHA256(stdout)
	rec.Execution.Status = "success"
	if runErr != nil {
		rec.Execution.Status = "error"
		rec.Execution.Error = runErr.Error()
	}

	bundle, err := s.cfg.Signer.Sign(rec, s.attestation)
	if err != nil {
		return ExecuteOutput{}, nil, err
	}
	asMap, err := toMap(bundle)
	if err != nil {
		return ExecuteOutput{}, nil, err
	}
	return ExecuteOutput{Status: rec.Execution.Status, Output: string(stdout), Stderr: string(stderr), Receipt: asMap}, runErr, nil
}

func (s *Server) execute(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, ExecuteOutput, error) {
	p, err := s.prepare(in)
	if err != nil {
		return nil, ExecuteOutput{}, err
	}
	out, runErr, err := s.runPrepared(ctx, p)
	if err != nil {
		return nil, ExecuteOutput{}, err
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) {
			return nil, ExecuteOutput{}, runErr
		}
		// Fail closed, but still hand back the signed receipt of the failure.
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "execution failed: " + runErr.Error()}}}, out, nil
	}
	return nil, out, nil
}

type ReplayInput struct {
	Bundle   map[string]any `json:"receipt_bundle" jsonschema:"the receipt_bundle returned by execute"`
	Input    string         `json:"input,omitempty" jsonschema:"the original UTF-8 text input (set only one of input and input_b64)"`
	InputB64 string         `json:"input_b64,omitempty" jsonschema:"the original input as base64 bytes"`
}

type ReplayOutput struct {
	Matches bool           `json:"replay_matches" jsonschema:"true only if the receipt verified and the re-execution reproduced the recorded output hash"`
	Checks  []verify.Check `json:"checks"`
	Note    string         `json:"note"`
}

func (s *Server) replay(ctx context.Context, _ *mcp.CallToolRequest, in ReplayInput) (*mcp.CallToolResult, ReplayOutput, error) {
	raw, err := json.Marshal(in.Bundle)
	if err != nil {
		return nil, ReplayOutput{}, err
	}
	var b receipts.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, ReplayOutput{}, fmt.Errorf("bad bundle: %w", err)
	}
	wl, ok := s.cfg.Registry.Get(b.Receipt.CodeSHA256)
	if !ok {
		return nil, ReplayOutput{}, fmt.Errorf("workload %s is not in this server's registry; replay it yourself with the trustgate CLI and the .wasm", b.Receipt.CodeSHA256)
	}
	stdin, err := stdinBytes(in.Input, in.InputB64)
	if err != nil {
		return nil, ReplayOutput{}, err
	}
	checks := verify.Bundle(&b, verify.Options{AllowDev: s.cfg.Provider.Mode() == attest.ModeDev, DevTrust: s.cfg.DevTrust})
	checks = append(checks, verify.Replay(ctx, &b, wl.Wasm, stdin)...)
	return nil, ReplayOutput{
		Matches: verify.OK(checks),
		Checks:  checks,
		Note:    "Replayed by this same server. For independent evidence, replay on your own machine: trustgate replay <bundle> -wasm <file> -stdin <file>.",
	}, nil
}

type ListInput struct{}
type ListOutput struct {
	Workloads []registry.Manifest `json:"workloads"`
}

func (s *Server) list(context.Context, *mcp.CallToolRequest, ListInput) (*mcp.CallToolResult, ListOutput, error) {
	return nil, ListOutput{Workloads: s.cfg.Registry.List()}, nil
}

type AttestationInput struct{}
type AttestationOutput struct {
	Mode           string `json:"mode"`
	Measurement    string `json:"measurement"`
	SignerPub      string `json:"signer_pub"`
	Epoch          string `json:"epoch"`
	AttestationB64 string `json:"attestation_b64"`
	Warning        string `json:"warning,omitempty"`
}

func (s *Server) attestationInfo() AttestationOutput {
	out := AttestationOutput{
		Mode:           s.cfg.Provider.Mode(),
		Measurement:    s.cfg.Provider.Measurement(),
		SignerPub:      hex.EncodeToString(s.cfg.Signer.PublicKey()),
		Epoch:          s.cfg.Signer.Epoch(),
		AttestationB64: base64.StdEncoding.EncodeToString(s.attestation),
	}
	if out.Mode == attest.ModeDev {
		out.Warning = "DEV MODE: software-only attestation, no hardware isolation. Not for real data."
	}
	return out
}

func (s *Server) getAttestation(context.Context, *mcp.CallToolRequest, AttestationInput) (*mcp.CallToolResult, AttestationOutput, error) {
	return nil, s.attestationInfo(), nil
}

type VerifyInput struct {
	Bundle              map[string]any `json:"receipt_bundle" jsonschema:"the receipt_bundle returned by execute"`
	ExpectedMeasurement string         `json:"expected_measurement,omitempty" jsonschema:"pin the enclave measurement (hex)"`
}
type VerifyOutput struct {
	Verified bool           `json:"verified"`
	Checks   []verify.Check `json:"checks"`
}

func (s *Server) verifyReceipt(_ context.Context, _ *mcp.CallToolRequest, in VerifyInput) (*mcp.CallToolResult, VerifyOutput, error) {
	raw, err := json.Marshal(in.Bundle)
	if err != nil {
		return nil, VerifyOutput{}, err
	}
	var b receipts.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, VerifyOutput{}, fmt.Errorf("bad bundle: %w", err)
	}
	cs := verify.Bundle(&b, verify.Options{
		AllowDev:            s.cfg.Provider.Mode() == attest.ModeDev,
		DevTrust:            s.cfg.DevTrust,
		ExpectedMeasurement: in.ExpectedMeasurement,
	})
	return nil, VerifyOutput{Verified: verify.OK(cs), Checks: cs}, nil
}

// MCP builds the MCP server with all tools registered.
func (s *Server) MCP() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "trustgate", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "TrustGate runs approved WebAssembly workloads in an isolated environment and returns a signed execution receipt. " +
			"The receipt proves what code ran on what input in which environment, not that the result is semantically correct.",
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "execute", Description: "Run an approved WASM workload with deny-by-default capabilities and resource limits; returns output plus a signed receipt."}, s.execute)
	mcp.AddTool(srv, &mcp.Tool{Name: "execute_async", Description: "Start a long-running workload and return a job_id immediately. Poll job_status, then fetch the output and signed receipt with job_result."}, s.jobs.submit)
	mcp.AddTool(srv, &mcp.Tool{Name: "job_status", Description: "Status of an async job: queued, running, succeeded, failed or cancelled."}, s.jobs.status)
	mcp.AddTool(srv, &mcp.Tool{Name: "job_result", Description: "Output and signed receipt bundle of a finished async job (status and no result while still running)."}, s.jobs.result)
	mcp.AddTool(srv, &mcp.Tool{Name: "cancel_job", Description: "Cancel a queued or running async job. A cancelled job produces no receipt."}, s.jobs.cancel)
	mcp.AddTool(srv, &mcp.Tool{Name: "replay", Description: "Re-run the workload recorded in a receipt against the original input and check that the output hash is reproduced. Only meaningful for deterministic-v1 receipts."}, s.replay)
	mcp.AddTool(srv, &mcp.Tool{Name: "list_workloads", Description: "List approved, publisher-signed workloads."}, s.list)
	mcp.AddTool(srv, &mcp.Tool{Name: "get_attestation", Description: "Return this server's attestation evidence and receipt-signing key."}, s.getAttestation)
	mcp.AddTool(srv, &mcp.Tool{Name: "verify_receipt", Description: "Verify a receipt bundle (signature, attestation, key binding, optional measurement pin)."}, s.verifyReceipt)
	return srv
}

// Handler returns the HTTP handler: /mcp (Streamable HTTP), /healthz and
// /.well-known/trustgate.
func (s *Server) Handler() http.Handler {
	srv := s.MCP()
	mcpH := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

	mux := http.NewServeMux()
	mux.Handle("/mcp", s.auth(mcpH))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/.well-known/trustgate", func(w http.ResponseWriter, _ *http.Request) {
		info := struct {
			AttestationOutput
			DevTrust string `json:"dev_trust,omitempty"`
		}{AttestationOutput: s.attestationInfo()}
		if info.Mode == attest.ModeDev {
			info.DevTrust = hex.EncodeToString(s.cfg.DevTrust)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})
	return mux
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.cfg.Token == "" {
		log.Println("WARNING: no bearer token configured; /mcp is unauthenticated")
		return next
	}
	want := []byte(s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func toMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("empty bundle")
	}
	return m, nil
}
