package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"trustgate/internal/attest"
	"trustgate/internal/receipts"
	"trustgate/internal/verify"
)

// pcr is the measurement of the enclave build that produced the real fixture.
const pcr = "1c680df50a18ba46d3bce7af9d63d653335593a788d25c624aa378c9c9e782072408baf0a836f01d4a6481dc243a030e"

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/nitro-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func call(t *testing.T, method, path, body string, query map[string]string, b64 bool) (int, response, errorResponse) {
	t.Helper()
	req := events.APIGatewayV2HTTPRequest{Body: body, IsBase64Encoded: b64, QueryStringParameters: query}
	req.RequestContext.HTTP.Method, req.RequestContext.HTTP.Path = method, path
	res, err := handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var ok response
	var bad errorResponse
	_ = json.Unmarshal([]byte(res.Body), &ok)
	_ = json.Unmarshal([]byte(res.Body), &bad)
	return res.StatusCode, ok, bad
}

func wrap(t *testing.T, bundle []byte, pin string) string {
	t.Helper()
	out, err := json.Marshal(map[string]any{"receipt_bundle": json.RawMessage(bundle), "expected_measurement": pin})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func status(r response, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "missing"
}

func TestRealNitroReceiptVerifies(t *testing.T) {
	code, r, _ := call(t, "POST", "/verify", wrap(t, fixture(t), pcr), nil, false)
	if code != 200 || !r.Verified {
		t.Fatalf("real receipt should verify: %d %+v", code, r)
	}
	for _, c := range r.Checks {
		if c.Status != verify.Pass {
			t.Errorf("check %q: %s %s", c.Name, c.Status, c.Detail)
		}
	}
	if len(r.Checks) != 5 || !strings.Contains(r.Note, "does not prove the result is correct") {
		t.Fatalf("unexpected checks or missing honesty note: %+v", r)
	}
}

func TestInputForms(t *testing.T) {
	bare := string(fixture(t))
	// Bare bundle, measurement in the query string.
	if code, r, _ := call(t, "POST", "/verify", bare, map[string]string{"measurement": pcr}, false); code != 200 || !r.Verified {
		t.Fatalf("bare bundle with query pin: %d %+v", code, r)
	}
	// Base64-encoded body, as API Gateway may deliver it.
	enc := base64.StdEncoding.EncodeToString([]byte(wrap(t, fixture(t), pcr)))
	if code, r, _ := call(t, "POST", "/verify", enc, nil, true); code != 200 || !r.Verified {
		t.Fatalf("base64 body: %d %+v", code, r)
	}
	// No pin: still verifies, but the measurement check is reported as skipped, not passed.
	code, r, _ := call(t, "POST", "/verify", bare, nil, false)
	if code != 200 || !r.Verified || status(r, "enclave measurement") != verify.Skip {
		t.Fatalf("unpinned should verify with the measurement check skipped: %d %+v", code, r)
	}
}

func TestAttacksAreRejected(t *testing.T) {
	// Wrong pinned measurement.
	_, r, _ := call(t, "POST", "/verify", wrap(t, fixture(t), strings.Repeat("00", 48)), nil, false)
	if r.Verified || status(r, "enclave measurement") != verify.Fail {
		t.Fatalf("wrong measurement accepted: %+v", r)
	}

	// Edited receipt (output hash overwritten): signature must fail.
	var b map[string]any
	if err := json.Unmarshal(fixture(t), &b); err != nil {
		t.Fatal(err)
	}
	b["receipt"].(map[string]any)["output_sha256"] = "sha256:" + strings.Repeat("0", 64)
	forged, _ := json.Marshal(b)
	_, r, _ = call(t, "POST", "/verify", wrap(t, forged, pcr), nil, false)
	if r.Verified || status(r, "receipt signature") != verify.Fail {
		t.Fatalf("forged receipt accepted: %+v", r)
	}

	// Corrupted attestation document: must not verify.
	b2 := map[string]any{}
	_ = json.Unmarshal(fixture(t), &b2)
	att, _ := base64.StdEncoding.DecodeString(b2["attestation"].(string))
	att[len(att)/2] ^= 0xff
	b2["attestation"] = base64.StdEncoding.EncodeToString(att)
	bad, _ := json.Marshal(b2)
	if _, r, _ = call(t, "POST", "/verify", wrap(t, bad, pcr), nil, false); r.Verified {
		t.Fatalf("corrupted attestation accepted: %+v", r)
	}
}

func TestDevModeReceiptIsRefused(t *testing.T) {
	dev, err := attest.NewDev(filepath.Join(t.TempDir(), "root.key"), "dev-measurement")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipts.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := dev.Attest(signer.PublicKey(), []byte("n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := signer.Sign(receipts.Receipt{Workload: "x@1", AttestationMode: attest.ModeDev}, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bundle)
	_, r, _ := call(t, "POST", "/verify", wrap(t, raw, "dev-measurement"), nil, false)
	if r.Verified || status(r, "attestation document") != verify.Fail {
		t.Fatalf("a software-only dev receipt must be refused: %+v", r)
	}
}

func TestBadRequestsAndRouting(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"not json", "POST", "/verify", "{nope", 400},
		{"no bundle", "POST", "/verify", `{"hello":1}`, 400},
		{"wrong pin type", "POST", "/verify", `{"receipt_bundle":{},"expected_measurement":5}`, 400},
		{"too large", "POST", "/verify", strings.Repeat("a", maxBody+1), 413},
		{"wrong method", "GET", "/verify", "", 405},
		{"unknown route", "POST", "/other", "{}", 404},
		{"health", "GET", "/healthz", "", 200},
		{"root", "GET", "/", "", 200},
		{"cors preflight", "OPTIONS", "/verify", "", 204},
	}
	for _, c := range cases {
		if code, _, _ := call(t, c.method, c.path, c.body, nil, false); code != c.want {
			t.Errorf("%s: got %d want %d", c.name, code, c.want)
		}
	}
}
