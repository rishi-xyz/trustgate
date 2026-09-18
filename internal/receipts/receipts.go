// Package receipts defines the signed execution receipt and the hash-chained
// signer that issues them.
package receipts

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"trustgate/internal/canon"
)

const sigPrefix = "ed25519:"

type InputRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type Runtime struct {
	Engine  string `json:"engine"`
	Profile string `json:"profile"`
}

type Limits struct {
	MemoryMB  uint32 `json:"memory_mb"`
	TimeoutMS uint32 `json:"timeout_ms"`
}

type Execution struct {
	Status     string `json:"status"` // "success" | "error"
	ExitCode   uint32 `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// Confidential marks a receipt for a job whose input and output were sealed.
// Input and output hashes in such a receipt are salted with secrets known only
// to the data owner, so the parent cannot brute-force small or guessable data
// from the receipt.
type Confidential struct {
	// InputCiphertextSHA256 identifies the exact sealed input that was processed.
	InputCiphertextSHA256 string `json:"input_ciphertext_sha256"`
	// RecipientPub is the X25519 key (hex) the result was sealed to.
	RecipientPub string `json:"recipient_pub"`
}

// Receipt commits to what ran, on what, under which limits and environment.
type Receipt struct {
	V            int        `json:"v"`
	Type         string     `json:"type"`
	Tenant       string     `json:"tenant"`
	Epoch        string     `json:"epoch"`
	Seq          uint64     `json:"seq"`
	Prev         string     `json:"prev"`
	Workload     string     `json:"workload"`
	CodeSHA256   string     `json:"code_sha256"`
	Args         []string   `json:"args"`
	Inputs       []InputRef `json:"inputs"`
	OutputSHA256 string     `json:"output_sha256"`
	Runtime      Runtime    `json:"runtime"`
	Limits       Limits     `json:"limits"`
	Execution    Execution  `json:"execution"`
	// Confidential is set for sealed jobs; input_sha256/output_sha256 are then
	// sha256(salt||data) rather than plain hashes.
	Confidential *Confidential `json:"confidential,omitempty"`
	// AttestationMode is "nitro" (hardware-backed) or "dev" (software, insecure).
	AttestationMode string `json:"attestation_mode"`
	AttestationRef  string `json:"attestation_ref"`
	// SignerPub is the hex Ed25519 public key that signed this receipt; the
	// attestation document binds it to the enclave measurement.
	SignerPub string `json:"signer_pub"`
}

// Bundle is a receipt with its signature and the attestation document that
// vouches for the signing key. It is the unit passed to the verifier.
type Bundle struct {
	Receipt     Receipt `json:"receipt"`
	Sig         string  `json:"sig"`
	Attestation []byte  `json:"attestation"`
}

// SignBytes returns the canonical bytes that are signed for r.
func SignBytes(r Receipt) ([]byte, error) { return canon.Marshal(r) }

// VerifySig checks the bundle signature against the signer key in the receipt.
func VerifySig(b *Bundle) error {
	pub, err := hex.DecodeString(b.Receipt.SignerPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signer_pub")
	}
	if len(b.Sig) <= len(sigPrefix) || b.Sig[:len(sigPrefix)] != sigPrefix {
		return fmt.Errorf("invalid signature encoding")
	}
	sig, err := hex.DecodeString(b.Sig[len(sigPrefix):])
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	msg, err := SignBytes(b.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature does not match receipt contents")
	}
	return nil
}

// Signer issues hash-chained receipts under a key generated at boot.
type Signer struct {
	mu    sync.Mutex
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	epoch string
	seq   uint64
	prev  string
}

// NewSigner generates a fresh in-memory signing key and boot epoch.
func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub, epoch: "boot-" + hex.EncodeToString(nonce), prev: "sha256:" + fmt.Sprintf("%064d", 0)}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }
func (s *Signer) Epoch() string                { return s.epoch }

// Sign fills chain fields on r, signs it and returns the bundle. The caller
// supplies the attestation document that binds s.PublicKey to the enclave.
func (s *Signer) Sign(r Receipt, attestation []byte) (*Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	r.V = 1
	r.Type = "exec.run"
	r.Epoch = s.epoch
	r.Seq = s.seq
	r.Prev = s.prev
	r.SignerPub = hex.EncodeToString(s.pub)
	r.AttestationRef = canon.SHA256(attestation)
	msg, err := SignBytes(r)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.priv, msg)
	s.prev = canon.SHA256(msg)
	return &Bundle{Receipt: r, Sig: sigPrefix + hex.EncodeToString(sig), Attestation: attestation}, nil
}
