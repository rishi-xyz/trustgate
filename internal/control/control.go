// Package control is the enclave's private control channel. It listens on a
// vsock port that is NOT exposed via the public forwarder, so only the parent
// host process can use it. It carries what the enclave cannot obtain itself:
// AWS credentials, the current time, and ciphertext to decrypt.
package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"time"

	"trustgate/internal/kms"
)

// Ops understood by the control channel.
const (
	OpKMSTest  = "kms-test"  // decrypt a ciphertext with the request's own credentials
	OpSetCreds = "set-creds" // store credentials used for confidential jobs
)

// Request is sent by the parent tool (one JSON object per connection).
type Request struct {
	Op            string    `json:"op,omitempty"`
	Region        string    `json:"region"`
	Creds         kms.Creds `json:"creds"`
	CiphertextB64 string    `json:"ciphertext_b64"`
	UnixTime      int64     `json:"unix_time"`
}

// Response never contains plaintext; it commits to it by hash.
type Response struct {
	OK              bool   `json:"ok"`
	PlaintextSHA256 string `json:"plaintext_sha256,omitempty"`
	PlaintextLen    int    `json:"plaintext_len,omitempty"`
	Measurement     string `json:"measurement,omitempty"`
	Error           string `json:"error,omitempty"`
}

type Handler struct {
	// Keys receives credentials from set-creds; the server uses it to unwrap
	// data keys for confidential jobs. May be nil.
	Keys        *kms.Provider
	Attester    kms.Attester
	Measurement string
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Serve handles connections until l is closed.
func (h *Handler) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go h.handle(c)
	}
}

func (h *Handler) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	var req Request
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Error: "bad request: " + err.Error()})
		return
	}
	var resp Response
	switch req.Op {
	case "", OpKMSTest:
		resp = h.decrypt(&req)
	case OpSetCreds:
		resp = h.setCreds(&req)
	default:
		resp = Response{Error: "unknown op " + req.Op}
	}
	if !resp.OK {
		log.Printf("control: %s", resp.Error)
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func (h *Handler) decrypt(req *Request) Response {
	ct, err := base64.StdEncoding.DecodeString(req.CiphertextB64)
	if err != nil {
		return Response{Error: "bad ciphertext: " + err.Error()}
	}
	syncClock(req.UnixTime)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &kms.Client{Region: req.Region, Creds: req.Creds, Attester: h.Attester, Dial: h.Dial}
	pt, err := client.Decrypt(ctx, ct)
	if err != nil {
		return Response{Measurement: h.Measurement, Error: err.Error()}
	}
	sum := sha256.Sum256(pt)
	return Response{OK: true, PlaintextSHA256: hex.EncodeToString(sum[:]), PlaintextLen: len(pt), Measurement: h.Measurement}
}

func (h *Handler) setCreds(req *Request) Response {
	if h.Keys == nil {
		return Response{Error: "confidential jobs are not enabled on this server"}
	}
	if req.Region == "" || req.Creds.AccessKeyID == "" {
		return Response{Error: "set-creds needs region and credentials"}
	}
	syncClock(req.UnixTime)
	h.Keys.SetCreds(req.Region, req.Creds)
	return Response{OK: true, Measurement: h.Measurement}
}
