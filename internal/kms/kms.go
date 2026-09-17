package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Creds are temporary AWS credentials handed to the enclave by the parent.
// They are the parent role's credentials, so on their own they cannot decrypt:
// the key policy additionally requires the enclave's attestation measurements.
type Creds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

// Attester returns an attestation document embedding publicKey (PKIX DER).
type Attester interface {
	AttestRaw(publicKey, nonce, userData []byte) ([]byte, error)
}

// Client decrypts under KMS with recipient attestation. Dial reaches the KMS
// endpoint (inside an enclave: vsock to the parent's vsock-proxy).
type Client struct {
	Region   string
	Creds    Creds
	Attester Attester
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Decrypt asks KMS to decrypt ciphertext for this enclave only. The plaintext
// comes back encrypted to an ephemeral key that exists only in this process.
func (c *Client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	doc, err := c.Attester.AttestRaw(pubDER, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}

	httpClient := awshttp.NewBuildableClient()
	if c.Dial != nil {
		httpClient = httpClient.WithTransportOptions(func(t *http.Transport) { t.DialContext = c.Dial })
	}
	svc := awskms.New(awskms.Options{
		Region:      c.Region,
		Credentials: credentials.NewStaticCredentialsProvider(c.Creds.AccessKeyID, c.Creds.SecretAccessKey, c.Creds.SessionToken),
		HTTPClient:  httpClient,
		Retryer:     aws.NopRetryer{},
	})
	out, err := svc.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob: ciphertext,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    doc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, errors.New("kms returned no CiphertextForRecipient")
	}
	return DecryptCMS(priv, out.CiphertextForRecipient)
}
