// Package verify checks TrustGate receipt bundles and replays deterministic
// workloads. It is shared by the CLI and the server's verify_receipt tool.
package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"trustgate/internal/attest"
	"trustgate/internal/canon"
	"trustgate/internal/receipts"
	"trustgate/internal/runtime"
	"trustgate/internal/seal"
)

const (
	Pass = "pass"
	Fail = "fail"
	Skip = "skip"
)

// Check is one verification step and its outcome.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Options configure verification.
type Options struct {
	// AllowDev accepts software-only dev attestations. Without it, a dev-mode
	// bundle fails: it carries no hardware evidence.
	AllowDev bool
	// DevTrust is the public key that signs dev attestation documents.
	DevTrust ed25519.PublicKey
	// ExpectedMeasurement pins the enclave image (hex PCR0 / dev binary hash).
	// If empty the measurement check is skipped and reported as such.
	ExpectedMeasurement string
}

// OK reports whether no check failed. Skipped checks do not fail a bundle, but
// callers should surface them.
func OK(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

func add(cs *[]Check, name string, err error, detail string) bool {
	if err != nil {
		*cs = append(*cs, Check{Name: name, Status: Fail, Detail: err.Error()})
		return false
	}
	*cs = append(*cs, Check{Name: name, Status: Pass, Detail: detail})
	return true
}

// Bundle verifies signature, attestation and their binding for b.
func Bundle(b *receipts.Bundle, opt Options) []Check {
	var cs []Check

	add(&cs, "receipt signature", receipts.VerifySig(b), "Ed25519 signature matches receipt contents")

	if got := canon.SHA256(b.Attestation); got != b.Receipt.AttestationRef {
		add(&cs, "attestation reference", fmt.Errorf("receipt commits to %s but bundle attestation hashes to %s", b.Receipt.AttestationRef, got), "")
	} else {
		add(&cs, "attestation reference", nil, "attestation document matches the hash committed in the receipt")
	}

	mode := b.Receipt.AttestationMode
	if mode == attest.ModeDev && !opt.AllowDev {
		add(&cs, "attestation document", fmt.Errorf("dev-mode attestation is software-only and not hardware-backed (re-run with --allow-dev to inspect anyway)"), "")
		return cs
	}
	info, err := attest.Verify(mode, b.Attestation, attest.VerifyOptions{DevTrust: opt.DevTrust})
	if !add(&cs, "attestation document", err, fmt.Sprintf("%s attestation verified", mode)) {
		return cs
	}
	if mode == attest.ModeDev {
		cs[len(cs)-1].Detail += " (INSECURE dev mode: no hardware isolation)"
	}

	if pub, _ := hex.DecodeString(b.Receipt.SignerPub); !bytes.Equal(pub, info.PublicKey) {
		add(&cs, "signing key binding", fmt.Errorf("attested public key does not match receipt signer"), "")
	} else {
		add(&cs, "signing key binding", nil, "signing key is the one bound by the attestation document")
	}

	switch {
	case opt.ExpectedMeasurement == "":
		cs = append(cs, Check{Name: "enclave measurement", Status: Skip, Detail: "no expected measurement pinned; got " + info.Measurement})
	case strings.EqualFold(opt.ExpectedMeasurement, info.Measurement):
		add(&cs, "enclave measurement", nil, "matches pinned "+info.Measurement)
	default:
		add(&cs, "enclave measurement", fmt.Errorf("attested %s, expected %s", info.Measurement, opt.ExpectedMeasurement), "")
	}
	return cs
}

// Replay re-runs the workload with the supplied wasm and stdin and compares
// against the receipt. It is only meaningful for deterministic-v1 receipts.
func Replay(ctx context.Context, b *receipts.Bundle, wasm, stdin []byte) []Check {
	return ReplaySalted(ctx, b, wasm, stdin, nil, nil)
}

// ReplaySalted is Replay for confidential receipts, whose input and output
// commitments are sha256(salt||data). saltIn and saltOut are the secrets held
// by the data owner; they are ignored for ordinary receipts.
func ReplaySalted(ctx context.Context, b *receipts.Bundle, wasm, stdin, saltIn, saltOut []byte) []Check {
	var cs []Check
	r := b.Receipt
	hashIn, hashOut := canon.SHA256, canon.SHA256
	if r.Confidential != nil {
		if len(saltIn) == 0 || len(saltOut) == 0 {
			return append(cs, Check{Name: "confidential receipt", Status: Fail, Detail: "receipt commitments are salted; supply the input and output salts (kept by the data owner)"})
		}
		hashIn = func(d []byte) string { return seal.SaltedSHA256(saltIn, d) }
		hashOut = func(d []byte) string { return seal.SaltedSHA256(saltOut, d) }
	}

	if r.Runtime.Profile != runtime.ProfileDeterministicV1 {
		return append(cs, Check{Name: "replay profile", Status: Fail, Detail: "receipt profile " + r.Runtime.Profile + " is not replayable"})
	}
	if got := canon.SHA256(wasm); got != r.CodeSHA256 {
		add(&cs, "workload hash", fmt.Errorf("supplied wasm hashes to %s, receipt says %s", got, r.CodeSHA256), "")
		return cs
	}
	add(&cs, "workload hash", nil, "supplied wasm matches receipt code_sha256")

	var want string
	for _, in := range r.Inputs {
		if in.Name == "stdin" {
			want = in.SHA256
		}
	}
	if got := hashIn(stdin); got != want {
		add(&cs, "input hash", fmt.Errorf("supplied input hashes to %s, receipt says %s", got, want), "")
		return cs
	}
	add(&cs, "input hash", nil, "supplied input matches receipt")

	res, err := runtime.Run(ctx, wasm, stdin, r.Args, runtime.Limits{MemoryMB: r.Limits.MemoryMB, TimeoutMS: r.Limits.TimeoutMS})
	if err != nil && r.Execution.Status == "success" {
		add(&cs, "replay execution", fmt.Errorf("replay failed but original succeeded: %w", err), "")
		return cs
	}
	var out []byte
	if res != nil {
		out = res.Stdout
	}
	if got := hashOut(out); got != r.OutputSHA256 {
		add(&cs, "replay output hash", fmt.Errorf("replay produced %s, receipt says %s", got, r.OutputSHA256), "")
		return cs
	}
	add(&cs, "replay output hash", nil, "replayed output hash matches receipt")
	return cs
}
