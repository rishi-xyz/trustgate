package kms

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Provider unwraps data keys for confidential jobs. It holds the AWS
// credentials the parent pushes over the control channel; without them (or
// without a matching attested measurement) KMS refuses to decrypt.
type Provider struct {
	Attester Attester
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)

	mu      sync.RWMutex
	region  string
	creds   Creds
	updated time.Time
}

// SetCreds stores fresh credentials pushed by the parent.
func (p *Provider) SetCreds(region string, c Creds) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.region, p.creds, p.updated = region, c, time.Now()
}

// CredsAge reports how long ago credentials were last set (false if never).
func (p *Provider) CredsAge() (time.Duration, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.updated.IsZero() {
		return 0, false
	}
	return time.Since(p.updated), true
}

// DecryptDataKey unwraps a KMS-wrapped data key using attested Decrypt.
func (p *Provider) DecryptDataKey(ctx context.Context, wrapped []byte) ([]byte, error) {
	p.mu.RLock()
	region, creds := p.region, p.creds
	p.mu.RUnlock()
	if region == "" || creds.AccessKeyID == "" {
		return nil, errors.New("enclave has no AWS credentials yet: run `trustgate-parent creds` on the parent")
	}
	c := &Client{Region: region, Creds: creds, Attester: p.Attester, Dial: p.Dial}
	return c.Decrypt(ctx, wrapped)
}
