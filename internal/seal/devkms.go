package seal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// DevKMS is a local stand-in for KMS used by -mode dev so the whole
// confidential flow can be exercised without AWS. A single local master key
// wraps data keys. It offers NO protection against the machine's operator.
type DevKMS struct{ master []byte }

// LoadDevKMS reads the master key at path, creating it if missing.
func LoadDevKMS(path string) (*DevKMS, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		m := make([]byte, keySize)
		if _, err := rand.Read(m); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(m)), 0o600); err != nil {
			return nil, err
		}
		return &DevKMS{master: m}, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(m) != keySize {
		return nil, errors.New("corrupt dev KMS master key")
	}
	return &DevKMS{master: m}, nil
}

// GenerateDataKey returns a fresh data key and its wrapped form.
func (d *DevKMS) GenerateDataKey() (plain, wrapped []byte, err error) {
	plain = make([]byte, keySize)
	if _, err := rand.Read(plain); err != nil {
		return nil, nil, err
	}
	aead, err := gcm(d.master)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return plain, append(nonce, aead.Seal(nil, nonce, plain, []byte("trustgate-dev-kms"))...), nil
}

func (d *DevKMS) DecryptDataKey(_ context.Context, wrapped []byte) ([]byte, error) {
	aead, err := gcm(d.master)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, errors.New("wrapped key too short")
	}
	pt, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], []byte("trustgate-dev-kms"))
	if err != nil {
		return nil, errors.New("dev KMS: cannot unwrap data key")
	}
	return pt, nil
}
