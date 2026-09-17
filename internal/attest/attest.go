// Package attest provides attestation providers and verification.
//
// Two modes exist:
//   - "nitro": a real AWS Nitro Enclaves attestation document (COSE_Sign1)
//     obtained from the NSM device and verified against the AWS Nitro root CA.
//   - "dev": a SOFTWARE-ONLY stand-in for local development. It offers no
//     hardware isolation and MUST NOT be presented as attested execution.
package attest

import (
	"crypto/ed25519"
	"time"
)

const (
	ModeNitro = "nitro"
	ModeDev   = "dev"
)

// Provider produces an attestation document binding pub to the environment.
type Provider interface {
	Mode() string
	// Measurement is the hex identity of the running image (Nitro PCR0, or the
	// binary hash in dev mode).
	Measurement() string
	Attest(pub ed25519.PublicKey, nonce []byte) ([]byte, error)
}

// Info is what a verified attestation document asserts.
type Info struct {
	Mode        string          `json:"mode"`
	Measurement string          `json:"measurement"`
	PCRs        map[uint]string `json:"pcrs,omitempty"`
	PublicKey   []byte          `json:"public_key"`
	Nonce       []byte          `json:"nonce,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// VerifyOptions configures document verification.
type VerifyOptions struct {
	// DevTrust is the public key trusted to sign dev-mode documents.
	DevTrust ed25519.PublicKey
}
