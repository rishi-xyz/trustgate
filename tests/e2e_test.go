package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	regDir := filepath.Join(tmp, "reg")
	must(t, os.MkdirAll(regDir, 0o755))
	publishTo(t, regDir, priv, "csv-stats", stats, 256, 20000)
	publishTo(t, regDir, priv, "spin", spin, 64, 500)
	publishTo(t, regDir, priv, "hog", hog, 64, 20000)

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
