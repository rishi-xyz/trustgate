// Package kms performs attested AWS KMS decryption from inside an enclave.
//
// KMS Decrypt with a Recipient attestation document returns the plaintext
// wrapped in a CMS EnvelopedData encrypted to a public key that was bound into
// the attestation document. Only the enclave holding the matching private key
// can open it, so neither the parent nor the network ever sees plaintext.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type envelopedData struct {
	Version    int
	Originator asn1.RawValue   `asn1:"optional,tag:0"`
	Recipients []asn1.RawValue `asn1:"set"`
	EncContent encryptedContentInfo
}

type encryptedContentInfo struct {
	Type asn1.ObjectIdentifier
	Alg  pkix.AlgorithmIdentifier
	Data []byte `asn1:"optional,tag:0"`
}

type keyTransRecipient struct {
	Version int
	Rid     asn1.RawValue
	Alg     pkix.AlgorithmIdentifier
	EncKey  []byte
}

// DecryptCMS opens a CMS EnvelopedData (RSAES-OAEP-SHA256 key transport,
// AES-256-CBC content) with priv, as produced by KMS for a Recipient.
func DecryptCMS(priv *rsa.PrivateKey, ber []byte) ([]byte, error) {
	// KMS returns BER (indefinite lengths); normalise to DER first.
	der, err := berToDER(ber)
	if err != nil {
		return nil, fmt.Errorf("cms: %w", err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: content info: %w", err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("cms: enveloped data: %w", err)
	}
	if len(ed.Recipients) == 0 {
		return nil, errors.New("cms: no recipients")
	}
	var ktri keyTransRecipient
	if _, err := asn1.Unmarshal(ed.Recipients[0].FullBytes, &ktri); err != nil {
		return nil, fmt.Errorf("cms: recipient: %w", err)
	}
	if !ed.EncContent.Alg.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("cms: unsupported content cipher %v", ed.EncContent.Alg.Algorithm)
	}
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ktri.EncKey, nil)
	if err != nil {
		return nil, fmt.Errorf("cms: unwrap content key: %w", err)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(ed.EncContent.Alg.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("cms: bad IV")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := ed.EncContent.Data
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("cms: bad ciphertext length")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(pt) {
		return nil, errors.New("cms: bad padding")
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return nil, errors.New("cms: bad padding")
		}
	}
	return pt[:len(pt)-pad], nil
}
