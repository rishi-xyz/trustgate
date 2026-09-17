package kms

import (
	"errors"
	"fmt"
)

// berToDER rewrites BER (as produced by AWS KMS: indefinite lengths and
// chunked, constructed octet strings) into DER so encoding/asn1 can parse it.
// Constructed OCTET STRINGs, and the context-specific [0] encryptedContent
// made only of OCTET STRING chunks, are merged into one primitive string.
func berToDER(in []byte) ([]byte, error) {
	n, rest, err := parseTLV(in)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("ber: trailing data")
	}
	return n.der(), nil
}

type node struct {
	id       byte // identifier octet (single-octet tags only)
	content  []byte
	children []*node
}

func (n *node) constructed() bool { return n.id&0x20 != 0 }

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func (n *node) der() []byte {
	if !n.constructed() {
		return append(append([]byte{n.id}, derLen(len(n.content))...), n.content...)
	}
	var body []byte
	for _, c := range n.children {
		body = append(body, c.der()...)
	}
	return append(append([]byte{n.id}, derLen(len(body))...), body...)
}

func parseTLV(b []byte) (*node, []byte, error) {
	if len(b) < 2 {
		return nil, nil, errors.New("ber: truncated")
	}
	id := b[0]
	if id&0x1f == 0x1f {
		return nil, nil, errors.New("ber: multi-octet tags unsupported")
	}
	l := int(b[1])
	b = b[2:]
	indefinite := false
	switch {
	case l == 0x80:
		if id&0x20 == 0 {
			return nil, nil, errors.New("ber: indefinite length on primitive")
		}
		indefinite = true
	case l > 0x80:
		cnt := l & 0x7f
		if cnt > 4 || len(b) < cnt {
			return nil, nil, errors.New("ber: bad length")
		}
		l = 0
		for _, x := range b[:cnt] {
			l = l<<8 | int(x)
		}
		b = b[cnt:]
	}
	n := &node{id: id}
	if id&0x20 == 0 {
		if l > len(b) {
			return nil, nil, errors.New("ber: truncated value")
		}
		n.content = b[:l]
		return n, b[l:], nil
	}

	var body []byte
	rest := b
	if !indefinite {
		if l > len(b) {
			return nil, nil, errors.New("ber: truncated value")
		}
		body, rest = b[:l], b[l:]
	}
	for {
		if indefinite {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]
				break
			}
			if len(rest) == 0 {
				return nil, nil, errors.New("ber: missing end-of-contents")
			}
			c, r, err := parseTLV(rest)
			if err != nil {
				return nil, nil, err
			}
			n.children, rest = append(n.children, c), r
			continue
		}
		if len(body) == 0 {
			break
		}
		c, r, err := parseTLV(body)
		if err != nil {
			return nil, nil, err
		}
		n.children, body = append(n.children, c), r
	}

	// Merge chunked octet strings into a single primitive value.
	if id == 0x24 || (id == 0xA0 && len(n.children) > 0 && allOctetStrings(n.children)) {
		var merged []byte
		for _, c := range n.children {
			if c.id != 0x04 {
				return nil, nil, fmt.Errorf("ber: unexpected chunk tag %#x", c.id)
			}
			merged = append(merged, c.content...)
		}
		newID := byte(0x04)
		if id == 0xA0 {
			newID = 0x80
		}
		return &node{id: newID, content: merged}, rest, nil
	}
	return n, rest, nil
}

func allOctetStrings(cs []*node) bool {
	for _, c := range cs {
		if c.id != 0x04 && c.id != 0x24 {
			return false
		}
	}
	return true
}
