//go:build !linux

package attest

import "errors"

func NewNitro() (Provider, error) {
	return nil, errors.New("nitro attestation requires linux")
}
