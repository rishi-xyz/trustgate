package attest

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Nitro obtains real attestation documents from the NSM device. It only works
// inside a Nitro Enclave.
type Nitro struct {
	measurement string
}

// NewNitro opens the NSM once to learn PCR0 (the image measurement).
func NewNitro() (*Nitro, error) {
	n := &Nitro{}
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM (not inside a Nitro Enclave?): %w", err)
	}
	defer sess.Close()
	res, err := sess.Send(&request.DescribePCR{Index: 0})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, fmt.Errorf("NSM error: %s", res.Error)
	}
	if res.DescribePCR == nil {
		return nil, errors.New("NSM returned no PCR data")
	}
	n.measurement = hex.EncodeToString(res.DescribePCR.Data)
	return n, nil
}

func (n *Nitro) Mode() string        { return ModeNitro }
func (n *Nitro) Measurement() string { return n.measurement }

func (n *Nitro) Attest(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	return n.AttestRaw(pub, nonce, nil)
}

// AttestRaw requests a document embedding arbitrary public key bytes (KMS
// requires a PKIX DER RSA key) plus optional user data.
func (n *Nitro) AttestRaw(pub, nonce, userData []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	res, err := sess.Send(&request.Attestation{PublicKey: pub, Nonce: nonce, UserData: userData})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, fmt.Errorf("NSM error: %s", res.Error)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM returned no attestation document")
	}
	return res.Attestation.Document, nil
}
