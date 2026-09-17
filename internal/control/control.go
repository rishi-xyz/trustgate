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

// Request is sent by the parent tool (one JSON object per connection).
type Request struct {
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
	resp := h.decrypt(&req)
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
