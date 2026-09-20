// Command verifier is an AWS Lambda that independently verifies a TrustGate
// receipt bundle: signature, the Nitro attestation document (against the AWS
// root CA), the binding of the signing key to that document, and, if given, a
// pinned enclave measurement.
//
// It runs somewhere other than the enclave and the parent instance, so it does
// not rely on the server that produced the receipt. It refuses dev-mode
// (software-only) attestation. It proves what ran and where, not correctness.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"trustgate/internal/receipts"
	"trustgate/internal/verify"
)

// maxBody bounds the request. A real bundle is about 8 KB.
const maxBody = 256 << 10

const note = "This verifies what code ran on which input in which attested environment. It does not prove the result is correct."

type response struct {
	Verified bool           `json:"verified"`
	Checks   []verify.Check `json:"checks"`
	Note     string         `json:"note"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() { lambda.Start(handle) }

func reply(status int, v any) (events.APIGatewayV2HTTPResponse, error) {
	body, _ := json.Marshal(v)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type",
			"Cache-Control":                "no-store",
		},
		Body: string(body),
	}, nil
}

func handle(_ context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	method, path := req.RequestContext.HTTP.Method, strings.TrimRight(req.RequestContext.HTTP.Path, "/")
	switch {
	case method == http.MethodOptions:
		return reply(http.StatusNoContent, struct{}{})
	case method == http.MethodGet && (path == "" || path == "/healthz"):
		return reply(http.StatusOK, map[string]string{"status": "ok", "service": "trustgate-receipt-verifier"})
	case path != "/verify":
		return reply(http.StatusNotFound, errorResponse{"not found; POST /verify"})
	case method != http.MethodPost:
		return reply(http.StatusMethodNotAllowed, errorResponse{"use POST /verify"})
	}

	body := req.Body
	if req.IsBase64Encoded {
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return reply(http.StatusBadRequest, errorResponse{"body is not valid base64"})
		}
		body = string(raw)
	}
	if len(body) > maxBody {
		return reply(http.StatusRequestEntityTooLarge, errorResponse{"request too large"})
	}

	bundle, pin, err := parse([]byte(body), req.QueryStringParameters["measurement"])
	if err != nil {
		return reply(http.StatusBadRequest, errorResponse{err.Error()})
	}

	// AllowDev stays false: a dev-mode receipt carries no hardware evidence.
	checks := verify.Bundle(bundle, verify.Options{ExpectedMeasurement: pin})
	return reply(http.StatusOK, response{Verified: verify.OK(checks), Checks: checks, Note: note})
}

// parse accepts either {"receipt_bundle": {...}, "expected_measurement": "..."}
// (also the raw `execute` result) or a bare bundle {"receipt", "sig",
// "attestation"}. A measurement in the query string is used if the body has none.
func parse(body []byte, queryPin string) (*receipts.Bundle, string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, "", errString("body must be JSON")
	}
	pin := queryPin
	if raw, ok := top["expected_measurement"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, "", errString("expected_measurement must be a string")
		}
		if s != "" {
			pin = s
		}
	}
	bundleRaw := body
	if raw, ok := top["receipt_bundle"]; ok {
		bundleRaw = raw
	} else if _, ok := top["receipt"]; !ok {
		return nil, "", errString(`send {"receipt_bundle": {...}, "expected_measurement": "<hex>"} or a bare receipt bundle`)
	}
	var b receipts.Bundle
	if err := json.Unmarshal(bundleRaw, &b); err != nil {
		return nil, "", errString("could not read the receipt bundle: " + err.Error())
	}
	return &b, strings.TrimSpace(pin), nil
}

type errString string

func (e errString) Error() string { return string(e) }
