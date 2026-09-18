package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trustgate/internal/attest"
	"trustgate/internal/canon"
	"trustgate/internal/receipts"
	"trustgate/internal/registry"
	"trustgate/internal/runtime"
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

func setup(t *testing.T) *env {
	t.Helper()
	tmp := t.TempDir()
	buildDir := "build/test"
	must(t, os.MkdirAll(filepath.Join("..", buildDir), 0o755))
	stats := buildWasm(t, "csv-stats", buildDir+"/csv-stats.wasm")
	spin := buildWasm(t, "spin", buildDir+"/spin.wasm")
	hog := buildWasm(t, "hog", buildDir+"/hog.wasm")
	hashBytes := buildWasm(t, "hash-bytes", buildDir+"/hash-bytes.wasm")
	primes := buildWasm(t, "primes", buildDir+"/primes.wasm")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	regDir := filepath.Join(tmp, "reg")
	must(t, os.MkdirAll(regDir, 0o755))
	publishTo(t, regDir, priv, "csv-stats", stats, 256, 20000)
	publishTo(t, regDir, priv, "spin", spin, 64, 500)
	publishTo(t, regDir, priv, "hog", hog, 64, 20000)
	publishTo(t, regDir, priv, "hash-bytes", hashBytes, 64, 20000)
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
	srv, err := server.New(server.Config{Tenant: "test", Registry: reg, Signer: signer, Provider: dev, DevTrust: dev.TrustKey()})
	must(t, err)

	ctx := context.Background()
	t1, t2 := mcp.NewInMemoryTransports()
	_, err = srv.MCP().Connect(ctx, t1, nil)
	must(t, err)
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, t2, nil)
	must(t, err)
	t.Cleanup(func() { sess.Close() })
	return &env{dir: regDir, pubKey: pub, privKey: priv, session: sess, devTrust: dev.TrustKey(), measure: "test-measurement", statsWasm: stats}
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
