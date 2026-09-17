package attest

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

// Verify checks an attestation document of the given mode and returns what it
// asserts. Nitro documents are verified against the AWS Nitro root CA.
func Verify(mode string, doc []byte, opt VerifyOptions) (*Info, error) {
	switch mode {
	case ModeDev:
		return verifyDev(doc, opt)
	case ModeNitro:
		return verifyNitro(doc)
	default:
		return nil, fmt.Errorf("unknown attestation mode %q", mode)
	}
}

type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

func verifyNitro(doc []byte) (*Info, error) {
	// Nitro leaf certificates are short-lived, so a receipt verified later must
	// be checked as of the time the document was issued. The timestamp is read
	// first, then the full chain and signature are verified at that time.
	var c coseSign1
	if err := cbor.Unmarshal(doc, &c); err != nil {
		return nil, fmt.Errorf("nitro attestation: malformed COSE_Sign1: %w", err)
	}
	var pre nitrite.Document
	if err := cbor.Unmarshal(c.Payload, &pre); err != nil {
		return nil, fmt.Errorf("nitro attestation: malformed payload: %w", err)
	}
	at := time.UnixMilli(int64(pre.Timestamp))
	res, err := nitrite.Verify(doc, nitrite.VerifyOptions{CurrentTime: at})
	if err != nil {
		return nil, fmt.Errorf("nitro attestation: %w", err)
	}
	d := res.Document
	pcrs := make(map[uint]string, len(d.PCRs))
	for k, v := range d.PCRs {
		pcrs[k] = hex.EncodeToString(v)
	}
	return &Info{
		Mode:        ModeNitro,
		Measurement: pcrs[0],
		PCRs:        pcrs,
		PublicKey:   d.PublicKey,
		Nonce:       d.Nonce,
		Timestamp:   at,
	}, nil
}
