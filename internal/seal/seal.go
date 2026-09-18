// Package seal implements TrustGate's confidential job format.
//
// The data owner encrypts input with a fresh data key (wrapped by KMS) and
// binds the ciphertext to one exact job: workload hash, arguments and the
// public key that may receive the result. The enclave unwraps the data key via
// an attested KMS call, runs the job, and seals the output to that public key.
// The untrusted parent only ever handles ciphertext, and cannot reuse it for a
// different workload, different arguments or a different result recipient.
package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"trustgate/internal/canon"
)

const (
	Version  = 1
	SaltSize = 32
	keySize  = 32
)

// SealedInput is what the data owner sends in place of plaintext input.
type SealedInput struct {
	V                int    `json:"v"`
	EncryptedDataKey string `json:"encrypted_data_key" jsonschema:"base64 KMS-wrapped AES-256 data key"`
	Nonce            string `json:"nonce" jsonschema:"base64 AES-GCM nonce"`
	Ciphertext       string `json:"ciphertext" jsonschema:"base64 AES-256-GCM ciphertext of salt||input"`
	RecipientPub     string `json:"recipient_pub" jsonschema:"hex X25519 public key that the result is sealed to"`
}

// SealedOutput is the job result encrypted to the recipient's public key.
type SealedOutput struct {
	V            int    `json:"v"`
	EphemeralPub string `json:"ephemeral_pub" jsonschema:"hex X25519 ephemeral public key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// OutputPayload is the plaintext inside a SealedOutput.
type OutputPayload struct {
	Stdout []byte `json:"stdout"`
	// Salt is the secret salt behind the receipt's output commitment.
	Salt []byte `json:"salt"`
}

// KeyProvider unwraps data keys. In production this is an attested KMS call
// from inside the enclave.
type KeyProvider interface {
	DecryptDataKey(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Binding returns the additional authenticated data that ties a ciphertext to
// one job. It must be computed identically by the owner and by the enclave.
func Binding(workloadSHA256 string, args []string, recipientPubHex string) ([]byte, error) {
	if args == nil {
		args = []string{}
	}
	return canon.Marshal(map[string]any{
		"v":               Version,
		"workload_sha256": workloadSHA256,
		"args":            args,
		"recipient_pub":   recipientPubHex,
	})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s, what string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid base64", what)
	}
	return b, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("data key must be %d bytes", keySize)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// SealInput encrypts stdin for one job. dataKey is a fresh plaintext data key
// and wrappedKey its KMS-encrypted form. It returns the envelope and the secret
// salt the owner must keep to check the receipt's input commitment.
func SealInput(dataKey, wrappedKey []byte, workloadSHA256 string, args []string, recipientPub []byte, stdin []byte) (*SealedInput, []byte, error) {
	if len(recipientPub) != 32 {
		return nil, nil, errors.New("recipient public key must be 32 bytes (X25519)")
	}
	aead, err := gcm(dataKey)
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, SaltSize)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	pubHex := hex.EncodeToString(recipientPub)
	aad, err := Binding(workloadSHA256, args, pubHex)
	if err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce, append(append([]byte{}, salt...), stdin...), aad)
	return &SealedInput{V: Version, EncryptedDataKey: b64(wrappedKey), Nonce: b64(nonce), Ciphertext: b64(ct), RecipientPub: pubHex}, salt, nil
}

// WrappedKey returns the decoded KMS-wrapped data key.
func (s *SealedInput) WrappedKey() ([]byte, error) {
	return unb64(s.EncryptedDataKey, "encrypted_data_key")
}

// CiphertextBytes returns the decoded ciphertext.
func (s *SealedInput) CiphertextBytes() ([]byte, error) { return unb64(s.Ciphertext, "ciphertext") }

// Validate checks structure without decrypting.
func (s *SealedInput) Validate() error {
	if s.V != Version {
		return fmt.Errorf("unsupported sealed input version %d", s.V)
	}
	if _, err := s.WrappedKey(); err != nil {
		return err
	}
	if n, err := unb64(s.Nonce, "nonce"); err != nil || len(n) != 12 {
		return errors.New("nonce must be 12 bytes of base64")
	}
	if _, err := s.CiphertextBytes(); err != nil {
		return err
	}
	if p, err := hex.DecodeString(s.RecipientPub); err != nil || len(p) != 32 {
		return errors.New("recipient_pub must be 32 bytes of hex")
	}
	return nil
}

// OpenInput decrypts and authenticates the input for exactly this workload and
// arguments. It fails if the parent changed the workload, args, recipient key,
// or any ciphertext bit. It returns the secret salt and the plaintext input.
func OpenInput(dataKey []byte, s *SealedInput, workloadSHA256 string, args []string) (salt, stdin []byte, err error) {
	if err := s.Validate(); err != nil {
		return nil, nil, err
	}
	aead, err := gcm(dataKey)
	if err != nil {
		return nil, nil, err
	}
	nonce, _ := unb64(s.Nonce, "nonce")
	ct, _ := s.CiphertextBytes()
	aad, err := Binding(workloadSHA256, args, s.RecipientPub)
	if err != nil {
		return nil, nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, nil, errors.New("sealed input does not authenticate for this workload, arguments and recipient")
	}
	if len(pt) < SaltSize {
		return nil, nil, errors.New("sealed input is too short")
	}
	return pt[:SaltSize], pt[SaltSize:], nil
}

func outputKey(shared, ephPub, recipPub []byte) ([]byte, error) {
	info := append(append([]byte("trustgate-output-v1"), ephPub...), recipPub...)
	return hkdf.Key(sha256.New, shared, nil, string(info), keySize)
}

// SealOutput encrypts the job result to recipientPub (X25519). inputCiphertextSHA256
// is authenticated so a result cannot be spliced onto a different job.
func SealOutput(recipientPub []byte, p OutputPayload, inputCiphertextSHA256 string) (*SealedOutput, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("recipient key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := outputKey(shared, eph.PublicKey().Bytes(), recipientPub)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, raw, []byte(inputCiphertextSHA256))
	return &SealedOutput{V: Version, EphemeralPub: hex.EncodeToString(eph.PublicKey().Bytes()), Nonce: b64(nonce), Ciphertext: b64(ct)}, nil
}

// OpenOutput decrypts a SealedOutput with the recipient's private key.
func OpenOutput(recipientPriv []byte, s *SealedOutput, inputCiphertextSHA256 string) (*OutputPayload, error) {
	priv, err := ecdh.X25519().NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("recipient private key: %w", err)
	}
	ephBytes, err := hex.DecodeString(s.EphemeralPub)
	if err != nil {
		return nil, errors.New("bad ephemeral_pub")
	}
	eph, err := ecdh.X25519().NewPublicKey(ephBytes)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := outputKey(shared, ephBytes, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce, err := unb64(s.Nonce, "nonce")
	if err != nil {
		return nil, err
	}
	ct, err := unb64(s.Ciphertext, "ciphertext")
	if err != nil {
		return nil, err
	}
	raw, err := aead.Open(nil, nonce, ct, []byte(inputCiphertextSHA256))
	if err != nil {
		return nil, errors.New("sealed output does not decrypt with this key")
	}
	var p OutputPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SaltedSHA256 is the receipt commitment for confidential data: sha256(salt || data).
func SaltedSHA256(salt, data []byte) string {
	return canon.SHA256(append(append([]byte{}, salt...), data...))
}
