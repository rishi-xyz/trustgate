package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trustgate/internal/canon"
)

type devDoc struct {
	Mode        string `json:"mode"`
	Measurement string `json:"measurement"`
	PublicKey   string `json:"public_key"`
	Nonce       string `json:"nonce"`
	Timestamp   int64  `json:"timestamp"`
}

type devEnvelope struct {
	Payload devDoc `json:"payload"`
	Sig     string `json:"sig"`
}

// Dev is the insecure local provider. Its "measurement" is the SHA-384 of the
// running executable, so rebuilding the binary changes it, mimicking PCR0.
type Dev struct {
	priv        ed25519.PrivateKey
	measurement string
}

// NewDev loads (or creates) the dev root key at keyPath. measurement may be
// empty, in which case the running executable is hashed.
func NewDev(keyPath, measurement string) (*Dev, error) {
	var priv ed25519.PrivateKey
	if raw, err := os.ReadFile(keyPath); err == nil {
		b, err := hex.DecodeString(string(trimNL(raw)))
		if err != nil || len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("corrupt dev key at %s", keyPath)
		}
		priv = b
	} else if errors.Is(err, os.ErrNotExist) {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = p
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	if measurement == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(exe)
		if err != nil {
			return nil, err
		}
		sum := sha512.Sum384(data)
		measurement = hex.EncodeToString(sum[:])
	}
	return &Dev{priv: priv, measurement: measurement}, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func (d *Dev) Mode() string        { return ModeDev }
func (d *Dev) Measurement() string { return d.measurement }

// TrustKey is the public key a verifier must trust for dev documents.
func (d *Dev) TrustKey() ed25519.PublicKey { return d.priv.Public().(ed25519.PublicKey) }

func (d *Dev) Attest(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	doc := devDoc{
		Mode:        ModeDev,
		Measurement: d.measurement,
		PublicKey:   hex.EncodeToString(pub),
		Nonce:       hex.EncodeToString(nonce),
		Timestamp:   time.Now().UnixMilli(),
	}
	msg, err := canon.Marshal(doc)
	if err != nil {
		return nil, err
	}
	env := devEnvelope{Payload: doc, Sig: hex.EncodeToString(ed25519.Sign(d.priv, msg))}
	return json.Marshal(env)
}

func verifyDev(data []byte, opt VerifyOptions) (*Info, error) {
	if len(opt.DevTrust) != ed25519.PublicKeySize {
		return nil, errors.New("dev attestation: no trusted dev key supplied")
	}
	var env devEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("dev attestation: %w", err)
	}
	msg, err := canon.Marshal(env.Payload)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(env.Sig)
	if err != nil || !ed25519.Verify(opt.DevTrust, msg, sig) {
		return nil, errors.New("dev attestation: signature invalid")
	}
	pub, err := hex.DecodeString(env.Payload.PublicKey)
	if err != nil {
		return nil, errors.New("dev attestation: bad public key")
	}
	nonce, _ := hex.DecodeString(env.Payload.Nonce)
	return &Info{
		Mode:        ModeDev,
		Measurement: env.Payload.Measurement,
		PublicKey:   pub,
		Nonce:       nonce,
		Timestamp:   time.UnixMilli(env.Payload.Timestamp),
	}, nil
}
