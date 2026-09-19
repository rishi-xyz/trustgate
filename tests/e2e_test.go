package tests

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trustgate/internal/attest"
	"trustgate/internal/canon"
	"trustgate/internal/receipts"
	"trustgate/internal/registry"
	"trustgate/internal/runtime"
	"trustgate/internal/seal"
	"trustgate/internal/server"
	"trustgate/internal/verify"
)

const csvData = "supplier,month,amount\nacme,jan,100\nacme,feb,110\nbeta,jan,90\nbeta,feb,95\nacme,mar,105\nbeta,mar,100\nacme,apr,98\nbeta,apr,102\nacme,may,101\nbeta,may,99\nacme,jun,103\nbeta,jun,97\nacme,jul,100000\n"

func buildWasm(t *testing.T, pkg, out string) []byte {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "./workloads/"+pkg)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	data, err := os.ReadFile(filepath.Join("..", out))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var hashBytesWasm []byte

type env struct {
	srv       *server.Server
	kms       *seal.DevKMS
	dir       string
	pubKey    ed25519.PublicKey
	privKey   ed25519.PrivateKey
	wasm      map[string][]byte
	session   *mcp.ClientSession
	devTrust  ed25519.PublicKey
	measure   string
	statsWasm []byte
}

func publishTo(t *testing.T, dir string, priv ed25519.PrivateKey, name string, wasm []byte, mem, timeout uint32) {
	t.Helper()
	m := registry.Manifest{Name: name, Version: "1", SHA256: canon.SHA256(wasm), Profile: runtime.ProfileDeterministicV1,
		MaxMemoryMB: mem, MaxTimeoutMS: timeout, Capabilities: []string{}}
	if err := registry.Sign(&m, priv); err != nil {
		t.Fatal(err)
	}
	mj, _ := json.Marshal(m)
	must(t, os.WriteFile(filepath.Join(dir, name+".manifest.json"), mj, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, name+".wasm"), wasm, 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) *env { return setupWith(t, true) }

func setupWith(t *testing.T, withKeys bool) *env {
	t.Helper()
	tmp := t.TempDir()
	buildDir := "build/test"
	must(t, os.MkdirAll(filepath.Join("..", buildDir), 0o755))
	stats := buildWasm(t, "csv-stats", buildDir+"/csv-stats.wasm")
	spin := buildWasm(t, "spin", buildDir+"/spin.wasm")
	hog := buildWasm(t, "hog", buildDir+"/hog.wasm")
	hashBytes := buildWasm(t, "hash-bytes", buildDir+"/hash-bytes.wasm")
	cat := buildWasm(t, "cat", buildDir+"/cat.wasm")
	primes := buildWasm(t, "primes", buildDir+"/primes.wasm")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	regDir := filepath.Join(tmp, "reg")
	must(t, os.MkdirAll(regDir, 0o755))
	publishTo(t, regDir, priv, "csv-stats", stats, 256, 20000)
	publishTo(t, regDir, priv, "spin", spin, 64, 500)
	publishTo(t, regDir, priv, "hog", hog, 64, 20000)
	publishTo(t, regDir, priv, "hash-bytes", hashBytes, 64, 20000)
	publishTo(t, regDir, priv, "cat", cat, 64, 20000)
	publishTo(t, regDir, priv, "primes", primes, 512, 60000)
	// Same module as spin but with a long limit, to test cancelling a running job.
	publishTo(t, regDir, priv, "spin-long", spin, 64, 30000)
	hashBytesWasm = hashBytes

	reg, errs := registry.Load(regDir, []ed25519.PublicKey{pub})
	if len(errs) != 0 {
		t.Fatalf("registry load: %v", errs)
	}
	dev, err := attest.NewDev(filepath.Join(tmp, "dev", "root.key"), "test-measurement")
	must(t, err)
	signer, err := receipts.NewSigner()
	must(t, err)
	cfg := server.Config{Tenant: "test", Registry: reg, Signer: signer, Provider: dev, DevTrust: dev.TrustKey()}
	var devKMS *seal.DevKMS
	if withKeys {
		devKMS, err = seal.LoadDevKMS(filepath.Join(tmp, "kms.key"))
		must(t, err)
		cfg.Keys = devKMS
	}
	srv, err := server.New(cfg)
	must(t, err)

	ctx := context.Background()
	t1, t2 := mcp.NewInMemoryTransports()
	_, err = srv.MCP().Connect(ctx, t1, nil)
	must(t, err)
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, t2, nil)
	must(t, err)
	t.Cleanup(func() { sess.Close() })
	return &env{srv: srv, kms: devKMS, dir: regDir, pubKey: pub, privKey: priv, session: sess, devTrust: dev.TrustKey(), measure: "test-measurement", statsWasm: stats}
}

func (e *env) execute(t *testing.T, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: "execute", Arguments: args})
	must(t, err)
	m, _ := res.StructuredContent.(map[string]any)
	return res, m
}

func bundleOf(t *testing.T, out map[string]any) *receipts.Bundle {
	t.Helper()
	raw, _ := json.Marshal(out["receipt_bundle"])
	var b receipts.Bundle
	must(t, json.Unmarshal(raw, &b))
	return &b
}

func (e *env) opts() verify.Options {
	return verify.Options{AllowDev: true, DevTrust: e.devTrust, ExpectedMeasurement: e.measure}
}

func TestExecuteVerifyReplay(t *testing.T) {
	e := setup(t)
	res, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount", "supplier"}})
	if res.IsError {
		t.Fatalf("execute failed: %+v", res.Content)
	}
	if !strings.Contains(out["output"].(string), `"anomalies":[{"row":14`) {
		t.Fatalf("expected anomaly at row 14, got %v", out["output"])
	}
	b := bundleOf(t, out)

	if cs := verify.Bundle(b, e.opts()); !verify.OK(cs) {
		t.Fatalf("verify failed: %+v", cs)
	}
	if cs := verify.Replay(context.Background(), b, e.statsWasm, []byte(csvData)); !verify.OK(cs) {
		t.Fatalf("replay failed: %+v", cs)
	}

	// Attack: dev attestation must be rejected unless explicitly allowed.
	noDev := e.opts()
	noDev.AllowDev = false
	if verify.OK(verify.Bundle(b, noDev)) {
		t.Fatal("dev attestation accepted without AllowDev")
	}
	// Attack: wrong pinned measurement.
	bad := e.opts()
	bad.ExpectedMeasurement = "something-else"
	if verify.OK(verify.Bundle(b, bad)) {
		t.Fatal("wrong measurement accepted")
	}
}

func TestAttackTamperedReceipt(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	b := bundleOf(t, out)
	b.Receipt.OutputSHA256 = canon.SHA256([]byte("forged"))
	if verify.OK(verify.Bundle(b, e.opts())) {
		t.Fatal("tampered receipt verified")
	}
}

func TestAttackForgedSignerKey(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	b := bundleOf(t, out)
	// Attacker re-signs with their own key; attestation no longer binds it.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b.Receipt.SignerPub = strings.ToLower(hexOf(pub))
	msg, _ := receipts.SignBytes(b.Receipt)
	b.Sig = "ed25519:" + hexOf(ed25519.Sign(priv, msg))
	cs := verify.Bundle(b, e.opts())
	if verify.OK(cs) {
		t.Fatalf("forged signer verified: %+v", cs)
	}
}

func TestAttackChangedInputReplay(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	b := bundleOf(t, out)
	changed := []byte(strings.Replace(csvData, "100000", "100001", 1))
	if verify.OK(verify.Replay(context.Background(), b, e.statsWasm, changed)) {
		t.Fatal("replay with changed input byte succeeded")
	}
}

func TestAttackTamperedWasmReplay(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	b := bundleOf(t, out)
	tampered := append([]byte{}, e.statsWasm...)
	tampered[len(tampered)-1] ^= 0xff
	if verify.OK(verify.Replay(context.Background(), b, tampered, []byte(csvData))) {
		t.Fatal("replay with tampered wasm succeeded")
	}
}

func TestRegistryRejects(t *testing.T) {
	e := setup(t)
	wasm := e.statsWasm

	// Untrusted publisher.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	publishTo(t, e.dir, otherPriv, "evil", wasm, 64, 1000)
	// Tampered wasm behind a valid manifest.
	publishTo(t, e.dir, e.privKey, "swapped", wasm, 64, 1000)
	must(t, os.WriteFile(filepath.Join(e.dir, "swapped.wasm"), append(append([]byte{}, wasm...), 0), 0o644))
	// Manifest edited after signing (limits raised).
	publishTo(t, e.dir, e.privKey, "edited", wasm, 64, 1000)
	mp := filepath.Join(e.dir, "edited.manifest.json")
	raw, _ := os.ReadFile(mp)
	raw = []byte(strings.Replace(string(raw), `"max_timeout_ms":1000`, `"max_timeout_ms":999999`, 1))
	must(t, os.WriteFile(mp, raw, 0o644))

	reg, errs := registry.Load(e.dir, []ed25519.PublicKey{e.pubKey})
	if len(errs) != 3 {
		t.Fatalf("expected 3 rejections, got %d: %v", len(errs), errs)
	}
	for _, n := range []string{"evil", "swapped", "edited"} {
		if _, ok := reg.Get(n); ok {
			t.Fatalf("%s should have been rejected", n)
		}
	}
}

func TestLimits(t *testing.T) {
	e := setup(t)

	start := time.Now()
	res, out := e.execute(t, map[string]any{"workload": "spin"})
	if !res.IsError || out["status"] != "error" {
		t.Fatalf("spin should fail closed: %+v", out)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout not enforced promptly: %v", time.Since(start))
	}
	if b := bundleOf(t, out); !strings.Contains(b.Receipt.Execution.Error, "timeout") || !verify.OK(verify.Bundle(b, e.opts())) {
		t.Fatalf("failure receipt should record the timeout and verify: %+v", b.Receipt.Execution)
	}

	res, out = e.execute(t, map[string]any{"workload": "hog"})
	if !res.IsError || out["status"] != "error" {
		t.Fatalf("hog should fail closed: %+v", out)
	}

	// Requesting more than the manifest allows is rejected, not clamped.
	res, _ = e.execute(t, map[string]any{"workload": "spin", "timeout_ms": 60000})
	if !res.IsError {
		t.Fatal("over-limit request should be rejected")
	}
}

func TestChainAndDeterminism(t *testing.T) {
	e := setup(t)
	_, o1 := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	_, o2 := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	b1, b2 := bundleOf(t, o1), bundleOf(t, o2)
	if b1.Receipt.OutputSHA256 != b2.Receipt.OutputSHA256 {
		t.Fatal("same code+input gave different output hashes")
	}
	if b2.Receipt.Seq != b1.Receipt.Seq+1 {
		t.Fatalf("seq not incrementing: %d then %d", b1.Receipt.Seq, b2.Receipt.Seq)
	}
	msg, _ := receipts.SignBytes(b1.Receipt)
	if b2.Receipt.Prev != canon.SHA256(msg) {
		t.Fatal("receipt 2 does not chain to receipt 1")
	}
}

func TestVerifyReceiptTool(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: "verify_receipt", Arguments: map[string]any{"receipt_bundle": out["receipt_bundle"], "expected_measurement": e.measure}})
	must(t, err)
	m := res.StructuredContent.(map[string]any)
	if m["verified"] != true {
		t.Fatalf("verify_receipt tool: %+v", m)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func (e *env) call(t *testing.T, tool string, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	must(t, err)
	m, _ := res.StructuredContent.(map[string]any)
	return res, m
}

func TestBinaryInput(t *testing.T) {
	e := setup(t)
	// Bytes that are not valid UTF-8 and contain NULs.
	data := make([]byte, 0, 4096)
	for i := 0; i < 4096; i++ {
		data = append(data, byte(i*7))
	}
	res, out := e.call(t, "execute", map[string]any{"workload": "hash-bytes", "input_b64": base64.StdEncoding.EncodeToString(data)})
	if res.IsError {
		t.Fatalf("execute failed: %+v", res.Content)
	}
	sum := sha256.Sum256(data)
	if !strings.Contains(out["output"].(string), hex.EncodeToString(sum[:])) || !strings.Contains(out["output"].(string), `"bytes":4096`) {
		t.Fatalf("workload did not see the exact bytes: %v", out["output"])
	}
	b := bundleOf(t, out)
	if b.Receipt.Inputs[0].SHA256 != canon.SHA256(data) {
		t.Fatal("receipt input hash is not the hash of the raw bytes")
	}
	if !verify.OK(verify.Replay(context.Background(), b, hashBytesWasm, data)) {
		t.Fatal("replay with the original bytes failed")
	}

	// Both input forms at once, and invalid base64, are rejected.
	if res, _ := e.call(t, "execute", map[string]any{"workload": "hash-bytes", "input": "x", "input_b64": "eA=="}); !res.IsError {
		t.Fatal("input and input_b64 together should be rejected")
	}
	if res, _ := e.call(t, "execute", map[string]any{"workload": "hash-bytes", "input_b64": "!!!"}); !res.IsError {
		t.Fatal("invalid base64 should be rejected")
	}
}

func waitJob(t *testing.T, e *env, id string, want ...string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, st := e.call(t, "job_status", map[string]any{"job_id": id})
		for _, w := range want {
			if st["status"] == w {
				return st
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %v", id, want)
	return nil
}

func TestAsyncJob(t *testing.T) {
	e := setup(t)
	res, job := e.call(t, "execute_async", map[string]any{"workload": "primes", "args": []string{"20000000"}})
	if res.IsError {
		t.Fatalf("submit failed: %+v", res.Content)
	}
	id := job["job_id"].(string)
	if s := job["status"]; s != "queued" && s != "running" {
		t.Fatalf("new job should be queued or running, got %v", s)
	}
	waitJob(t, e, id, "succeeded")

	_, r := e.call(t, "job_result", map[string]any{"job_id": id})
	result, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("finished job has no result: %+v", r)
	}
	if !strings.Contains(result["output"].(string), `"count":1270607`) {
		t.Fatalf("wrong prime count: %v", result["output"])
	}
	b := bundleOf(t, result)
	if !verify.OK(verify.Bundle(b, e.opts())) {
		t.Fatal("async job receipt does not verify")
	}

	// Validation happens at submit time, not inside the job.
	if res, _ := e.call(t, "execute_async", map[string]any{"workload": "primes", "timeout_ms": 999999999}); !res.IsError {
		t.Fatal("over-limit async request should be rejected at submit")
	}
	if res, _ := e.call(t, "job_status", map[string]any{"job_id": "nope"}); !res.IsError {
		t.Fatal("unknown job id should be an error")
	}
}

func TestAsyncFailureKeepsReceipt(t *testing.T) {
	e := setup(t)
	_, job := e.call(t, "execute_async", map[string]any{"workload": "spin", "timeout_ms": 300})
	id := job["job_id"].(string)
	waitJob(t, e, id, "failed")
	_, r := e.call(t, "job_result", map[string]any{"job_id": id})
	result, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("failed job should still return its signed receipt: %+v", r)
	}
	b := bundleOf(t, result)
	if b.Receipt.Execution.Status != "error" || !strings.Contains(b.Receipt.Execution.Error, "timeout") || !verify.OK(verify.Bundle(b, e.opts())) {
		t.Fatalf("bad failure receipt: %+v", b.Receipt.Execution)
	}
}

func TestCancelJob(t *testing.T) {
	e := setup(t)
	_, job := e.call(t, "execute_async", map[string]any{"workload": "spin-long"})
	id := job["job_id"].(string)
	waitJob(t, e, id, "running")

	start := time.Now()
	_, c := e.call(t, "cancel_job", map[string]any{"job_id": id})
	if c["status"] != "cancelled" {
		t.Fatalf("cancel_job: %+v", c)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("cancel was not prompt: %v", time.Since(start))
	}
	// The cancelled run must stay cancelled and must not produce a receipt.
	time.Sleep(500 * time.Millisecond)
	_, r := e.call(t, "job_result", map[string]any{"job_id": id})
	if r["status"] != "cancelled" || r["result"] != nil {
		t.Fatalf("cancelled job should have no result: %+v", r)
	}
	// The worker slot is freed: another job can run right after.
	_, job2 := e.call(t, "execute_async", map[string]any{"workload": "hash-bytes", "input": "ok"})
	waitJob(t, e, job2["job_id"].(string), "succeeded")
}

func TestReplayTool(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})

	_, ok := e.call(t, "replay", map[string]any{"receipt_bundle": out["receipt_bundle"], "input": csvData})
	if ok["replay_matches"] != true {
		t.Fatalf("replay with the original input should match: %+v", ok)
	}
	_, bad := e.call(t, "replay", map[string]any{"receipt_bundle": out["receipt_bundle"], "input": strings.Replace(csvData, "100000", "100001", 1)})
	if bad["replay_matches"] != false {
		t.Fatalf("replay with a changed byte must not match: %+v", bad)
	}

	// A tampered receipt must not replay as valid either.
	b := bundleOf(t, out)
	b.Receipt.OutputSHA256 = canon.SHA256([]byte("forged"))
	raw, _ := json.Marshal(b)
	var forged map[string]any
	must(t, json.Unmarshal(raw, &forged))
	_, f := e.call(t, "replay", map[string]any{"receipt_bundle": forged, "input": csvData})
	if f["replay_matches"] != false {
		t.Fatalf("forged receipt must not replay as valid: %+v", f)
	}

	// A workload the server does not have cannot be replayed server-side.
	b2 := bundleOf(t, out)
	b2.Receipt.CodeSHA256 = canon.SHA256([]byte("other"))
	raw, _ = json.Marshal(b2)
	var other map[string]any
	must(t, json.Unmarshal(raw, &other))
	if res, _ := e.call(t, "replay", map[string]any{"receipt_bundle": other, "input": csvData}); !res.IsError {
		t.Fatal("replaying an unknown workload should be an error")
	}
}

// ---- confidential data path ----

type owner struct {
	priv *ecdh.PrivateKey
}

func newOwner(t *testing.T) owner {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	return owner{k}
}

// seal encrypts plaintext for one exact job, as `trustgate seal` does.
func (o owner) seal(t *testing.T, e *env, workload string, args []string, plaintext []byte) (*seal.SealedInput, []byte) {
	t.Helper()
	dk, wrapped, err := e.kms.GenerateDataKey()
	must(t, err)
	sha := workloadSHA(t, e, workload)
	env, salt, err := seal.SealInput(dk, wrapped, sha, args, o.priv.PublicKey().Bytes(), plaintext)
	must(t, err)
	return env, salt
}

func workloadSHA(t *testing.T, e *env, name string) string {
	t.Helper()
	_, out := e.call(t, "list_workloads", map[string]any{})
	for _, w := range out["workloads"].([]any) {
		m := w.(map[string]any)
		if m["name"] == name {
			return m["sha256"].(string)
		}
	}
	t.Fatalf("workload %s not found", name)
	return ""
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	var m map[string]any
	must(t, json.Unmarshal(raw, &m))
	return m
}

func (o owner) open(t *testing.T, out map[string]any) *seal.OutputPayload {
	t.Helper()
	var so seal.SealedOutput
	must(t, json.Unmarshal(mustJSON(t, out["sealed_output"]), &so))
	b := bundleOf(t, out)
	p, err := seal.OpenOutput(o.priv.Bytes(), &so, b.Receipt.Confidential.InputCiphertextSHA256)
	must(t, err)
	return p
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return raw
}

func TestConfidentialJob(t *testing.T) {
	e := setup(t)
	o := newOwner(t)
	plaintext := []byte(csvData)
	args := []string{"amount", "supplier"}
	env, salt := o.seal(t, e, "csv-stats", args, plaintext)

	res, out := e.call(t, "execute", map[string]any{"workload": "csv-stats", "args": args, "sealed_input": asMap(t, env)})
	if res.IsError {
		t.Fatalf("sealed execute failed: %+v", res.Content)
	}
	if out["output"] != "" || out["stderr"] != nil && out["stderr"] != "" || out["sealed_output"] == nil {
		t.Fatalf("a confidential job must not return plaintext output: %+v", out)
	}
	p := o.open(t, out)
	if !strings.Contains(string(p.Stdout), `"anomalies":[{"row":14`) {
		t.Fatalf("decrypted result is wrong: %s", p.Stdout)
	}

	// Same job in the clear gives the same bytes, so sealing changes nothing.
	_, clear := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": args})
	if clear["output"].(string) != string(p.Stdout) {
		t.Fatal("sealed and plain execution disagree")
	}

	b := bundleOf(t, out)
	if !verify.OK(verify.Bundle(b, e.opts())) {
		t.Fatal("confidential receipt does not verify")
	}
	// Commitments are salted: not the plain hash of the data.
	if b.Receipt.OutputSHA256 == canon.SHA256(p.Stdout) || b.Receipt.Inputs[0].SHA256 == canon.SHA256(plaintext) {
		t.Fatal("confidential receipt exposes plain, brute-forceable hashes")
	}
	// The data owner can replay with the salts; nobody else can.
	if cs := verify.ReplaySalted(context.Background(), b, e.statsWasm, plaintext, salt, p.Salt); !verify.OK(cs) {
		t.Fatalf("owner replay failed: %+v", cs)
	}
	if verify.OK(verify.Replay(context.Background(), b, e.statsWasm, plaintext)) {
		t.Fatal("replay without salts should not succeed")
	}
	if verify.OK(verify.ReplaySalted(context.Background(), b, e.statsWasm, plaintext, salt, make([]byte, 32))) {
		t.Fatal("replay with a wrong salt should not succeed")
	}
	// The server refuses to replay confidential receipts itself.
	if res, _ := e.call(t, "replay", map[string]any{"receipt_bundle": out["receipt_bundle"], "input": csvData}); !res.IsError {
		t.Fatal("server-side replay of a confidential receipt should be refused")
	}
}

// recorder captures every byte that crosses the (untrusted) network path.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) write(b []byte) { r.mu.Lock(); r.buf.Write(b); r.mu.Unlock() }

type recordingTransport struct{ r *recorder }

func (rt recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		rt.r.write(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, writerFunc(rt.r.write)))
	return resp, nil
}

type writerFunc func([]byte)

func (f writerFunc) Write(b []byte) (int, error) { f(b); return len(b), nil }

func TestConfidentialNothingInTheClearOnTheWire(t *testing.T) {
	e := setup(t)
	o := newOwner(t)
	args := []string{"amount", "supplier"}
	env, _ := o.seal(t, e, "csv-stats", args, []byte(csvData))

	ts := httptest.NewServer(e.srv.Handler())
	defer ts.Close()
	rec := &recorder{}
	ctx := context.Background()
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "wire"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: recordingTransport{rec}},
	}, nil)
	must(t, err)
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "execute", Arguments: map[string]any{"workload": "csv-stats", "args": args, "sealed_input": asMap(t, env)}})
	must(t, err)
	if res.IsError {
		t.Fatalf("execute failed: %+v", res.Content)
	}
	out, _ := res.StructuredContent.(map[string]any)
	if got := o.open(t, out); len(got.Stdout) == 0 {
		t.Fatal("owner could not read the result")
	}

	// Positive control: the same job sent unsealed MUST show plaintext on the
	// recorded wire, otherwise this test would pass while observing nothing.
	ctl := &recorder{}
	sess2, err := mcp.NewClient(&mcp.Implementation{Name: "wire-control"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: recordingTransport{ctl}},
	}, nil)
	must(t, err)
	defer sess2.Close()
	if _, err := sess2.CallTool(ctx, &mcp.CallToolParams{Name: "execute", Arguments: map[string]any{"workload": "csv-stats", "args": args, "input": csvData}}); err != nil {
		t.Fatal(err)
	}
	// Fragments are long enough that they cannot appear by chance in random
	// base64 ciphertext, and contain no quotes (the workload's JSON is escaped
	// inside the MCP message).
	fragments := []string{"acme", "beta", "100000", "anomalies", "stddev", "groups"}
	for _, visible := range fragments {
		if !strings.Contains(ctl.buf.String(), visible) {
			t.Fatalf("positive control failed: %q not seen on the wire of an unsealed job, so the recorder is not capturing traffic", visible)
		}
	}

	wire := rec.buf.String()
	if len(wire) < 500 {
		t.Fatalf("recorded suspiciously little traffic (%d bytes); the test is not observing the wire", len(wire))
	}
	// Input values and result values must not appear anywhere on the wire.
	// (The column names in args are visible on purpose: arguments are public,
	// authenticated job parameters. Sensitive parameters belong in the sealed input.)
	for _, secret := range fragments {
		if strings.Contains(wire, secret) {
			t.Errorf("plaintext fragment %q crossed the wire", secret)
		}
	}
}

func TestConfidentialParentAttacks(t *testing.T) {
	e := setup(t)
	o := newOwner(t)
	args := []string{"amount", "supplier"}
	env, _ := o.seal(t, e, "csv-stats", args, []byte(csvData))
	good := func() map[string]any {
		return map[string]any{"workload": "csv-stats", "args": args, "sealed_input": asMap(t, env)}
	}
	expectFail := func(name string, in map[string]any) {
		t.Helper()
		res, out := e.call(t, "execute", in)
		if !res.IsError {
			t.Errorf("%s: the attack succeeded", name)
			return
		}
		if out != nil && out["sealed_output"] != nil {
			t.Errorf("%s: a sealed output was produced", name)
		}
	}

	// The hostile parent has the ciphertext and can call execute itself.
	in := good()
	in["workload"] = "cat" // an approved workload that just echoes stdin
	expectFail("point ciphertext at an echo workload", in)

	in = good()
	in["args"] = []string{"amount"}
	expectFail("change the arguments", in)

	attacker := newOwner(t)
	swapped := *env
	swapped.RecipientPub = hex.EncodeToString(attacker.priv.PublicKey().Bytes())
	in = good()
	in["sealed_input"] = asMap(t, &swapped)
	expectFail("swap in the attacker's result key", in)

	tampered := *env
	raw, _ := base64.StdEncoding.DecodeString(tampered.Ciphertext)
	raw[len(raw)-1] ^= 1
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	in = good()
	in["sealed_input"] = asMap(t, &tampered)
	expectFail("flip a ciphertext bit", in)

	// Data wrapped by a different KMS (a key the enclave cannot unwrap).
	other, err := seal.LoadDevKMS(filepath.Join(t.TempDir(), "other.key"))
	must(t, err)
	dk, wrapped, _ := other.GenerateDataKey()
	foreign, _, err := seal.SealInput(dk, wrapped, workloadSHA(t, e, "csv-stats"), args, o.priv.PublicKey().Bytes(), []byte(csvData))
	must(t, err)
	in = good()
	in["sealed_input"] = asMap(t, foreign)
	expectFail("data key from a KMS the enclave cannot use", in)

	in = good()
	in["input"] = "x"
	expectFail("plaintext input together with sealed input", in)

	// Even the legitimate attacker view: the parent can run the job again, but
	// only the owner's key can read what comes back.
	res, out := e.call(t, "execute", good())
	if res.IsError {
		t.Fatalf("a replayed legitimate request should still work: %+v", res.Content)
	}
	var so seal.SealedOutput
	must(t, json.Unmarshal(mustJSON(t, out["sealed_output"]), &so))
	b := bundleOf(t, out)
	if _, err := seal.OpenOutput(attacker.priv.Bytes(), &so, b.Receipt.Confidential.InputCiphertextSHA256); err == nil {
		t.Fatal("the attacker read a result sealed to someone else")
	}
}

func TestConfidentialDisabledWithoutKeys(t *testing.T) {
	e := setupWith(t, false)
	o := newOwner(t)
	// Seal with a throwaway KMS; the server has none configured at all.
	tmp, err := seal.LoadDevKMS(filepath.Join(t.TempDir(), "k.key"))
	must(t, err)
	dk, wrapped, _ := tmp.GenerateDataKey()
	env, _, err := seal.SealInput(dk, wrapped, workloadSHA(t, e, "csv-stats"), []string{"amount"}, o.priv.PublicKey().Bytes(), []byte(csvData))
	must(t, err)
	res, _ := e.call(t, "execute", map[string]any{"workload": "csv-stats", "args": []string{"amount"}, "sealed_input": asMap(t, env)})
	if !res.IsError {
		t.Fatal("sealed jobs must be refused when the server has no key provider")
	}
}

func TestConfidentialAsyncJob(t *testing.T) {
	e := setup(t)
	o := newOwner(t)
	env, _ := o.seal(t, e, "hash-bytes", nil, []byte("async secret"))
	_, job := e.call(t, "execute_async", map[string]any{"workload": "hash-bytes", "sealed_input": asMap(t, env)})
	id := job["job_id"].(string)
	waitJob(t, e, id, "succeeded")
	_, r := e.call(t, "job_result", map[string]any{"job_id": id})
	result := r["result"].(map[string]any)
	if result["output"] != "" || result["sealed_output"] == nil {
		t.Fatalf("async confidential job leaked plaintext: %+v", result)
	}
	sum := sha256.Sum256([]byte("async secret"))
	if p := o.open(t, result); !strings.Contains(string(p.Stdout), hex.EncodeToString(sum[:])) {
		t.Fatalf("wrong decrypted result: %s", p.Stdout)
	}
}

func TestReceiptByID(t *testing.T) {
	e := setup(t)
	_, out := e.execute(t, map[string]any{"workload": "csv-stats", "input": csvData, "args": []string{"amount"}})
	id, _ := out["receipt_id"].(string)
	if id == "" {
		t.Fatalf("execute must return a receipt_id: %+v", out)
	}

	// Verify and replay by reference, without passing the bundle.
	_, v := e.call(t, "verify_receipt", map[string]any{"receipt_id": id, "expected_measurement": e.measure})
	if v["verified"] != true {
		t.Fatalf("verify by id failed: %+v", v)
	}
	_, r := e.call(t, "replay", map[string]any{"receipt_id": id, "input": csvData})
	if r["replay_matches"] != true {
		t.Fatalf("replay by id failed: %+v", r)
	}

	// A wrong pin is still caught when verifying by id.
	_, bad := e.call(t, "verify_receipt", map[string]any{"receipt_id": id, "expected_measurement": "not-the-measurement"})
	if bad["verified"] != false {
		t.Fatalf("wrong measurement must fail by id too: %+v", bad)
	}

	// Ambiguous or missing references are rejected.
	if res, _ := e.call(t, "verify_receipt", map[string]any{"receipt_id": id, "receipt_bundle": out["receipt_bundle"]}); !res.IsError {
		t.Fatal("both receipt_id and receipt_bundle should be rejected")
	}
	if res, _ := e.call(t, "verify_receipt", map[string]any{}); !res.IsError {
		t.Fatal("no reference at all should be rejected")
	}
	if res, _ := e.call(t, "verify_receipt", map[string]any{"receipt_id": "boot-nope-1"}); !res.IsError {
		t.Fatal("unknown receipt_id should be an error")
	}

	// Async jobs and confidential jobs get ids too.
	_, job := e.call(t, "execute_async", map[string]any{"workload": "hash-bytes", "input": "x"})
	waitJob(t, e, job["job_id"].(string), "succeeded")
	_, jr := e.call(t, "job_result", map[string]any{"job_id": job["job_id"]})
	aid, _ := jr["result"].(map[string]any)["receipt_id"].(string)
	if _, av := e.call(t, "verify_receipt", map[string]any{"receipt_id": aid}); av["verified"] != true {
		t.Fatalf("async receipt by id failed: %+v", av)
	}
}
