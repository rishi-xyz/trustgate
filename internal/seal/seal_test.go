package seal

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
)

const wl = "sha256:aaaa"

func recipient(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, k.PublicKey().Bytes()
}

func TestInputRoundTripAndBinding(t *testing.T) {
	kms, err := LoadDevKMS(filepath.Join(t.TempDir(), "m.key"))
	if err != nil {
		t.Fatal(err)
	}
	dk, wrapped, err := kms.GenerateDataKey()
	if err != nil {
		t.Fatal(err)
	}
	_, rpub := recipient(t)
	args := []string{"amount", "supplier"}
	secret := []byte("very secret transactions\x00\xff")

	env, salt, err := SealInput(dk, wrapped, wl, args, rpub, secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(env.Ciphertext, "secret") {
		t.Fatal("ciphertext leaks plaintext")
	}

	// The enclave side: unwrap the key, then open for the same job.
	got, err := kms.DecryptDataKey(context.Background(), mustB64(t, env.EncryptedDataKey))
	if err != nil {
		t.Fatal(err)
	}
	s2, pt, err := OpenInput(got, env, wl, args)
	if err != nil || !bytes.Equal(pt, secret) || !bytes.Equal(s2, salt) {
		t.Fatalf("round trip failed: %v", err)
	}

	// Confused-deputy attacks by the untrusted parent: each must fail.
	_, otherPub := recipient(t)
	swapped := *env
	swapped.RecipientPub = strings.Repeat("ab", 32)
	tampered := *env
	tampered.Ciphertext = flipFirstChar(env.Ciphertext)
	_ = otherPub
	for name, run := range map[string]func() error{
		"different workload":  func() error { _, _, e := OpenInput(got, env, "sha256:bbbb", args); return e },
		"different args":      func() error { _, _, e := OpenInput(got, env, wl, []string{"amount"}); return e },
		"different recipient": func() error { _, _, e := OpenInput(got, &swapped, wl, args); return e },
		"tampered ciphertext": func() error { _, _, e := OpenInput(got, &tampered, wl, args); return e },
		"wrong data key":      func() error { _, _, e := OpenInput(make([]byte, 32), env, wl, args); return e },
	} {
		if run() == nil {
			t.Errorf("%s: opened when it must not", name)
		}
	}
}

func TestOutputRoundTrip(t *testing.T) {
	priv, pub := recipient(t)
	p := OutputPayload{Stdout: []byte(`{"sum":1}`), Salt: bytes.Repeat([]byte{7}, SaltSize)}
	so, err := SealOutput(pub, p, "sha256:ctx")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenOutput(priv.Bytes(), so, "sha256:ctx")
	if err != nil || !bytes.Equal(got.Stdout, p.Stdout) || !bytes.Equal(got.Salt, p.Salt) {
		t.Fatalf("output round trip failed: %v", err)
	}
	other, _ := recipient(t)
	if _, err := OpenOutput(other.Bytes(), so, "sha256:ctx"); err == nil {
		t.Fatal("a different key opened the output")
	}
	if _, err := OpenOutput(priv.Bytes(), so, "sha256:other-job"); err == nil {
		t.Fatal("output opened for a different job")
	}
	if strings.Contains(so.Ciphertext, "sum") {
		t.Fatal("sealed output leaks plaintext")
	}
}

func TestDevKMSWrongMaster(t *testing.T) {
	a, _ := LoadDevKMS(filepath.Join(t.TempDir(), "a.key"))
	b, _ := LoadDevKMS(filepath.Join(t.TempDir(), "b.key"))
	_, wrapped, _ := a.GenerateDataKey()
	if _, err := b.DecryptDataKey(context.Background(), wrapped); err == nil {
		t.Fatal("different master key unwrapped the data key")
	}
}

func TestSaltedCommitmentHidesLowEntropyData(t *testing.T) {
	s1 := bytes.Repeat([]byte{1}, SaltSize)
	s2 := bytes.Repeat([]byte{2}, SaltSize)
	if SaltedSHA256(s1, []byte("42")) == SaltedSHA256(s2, []byte("42")) {
		t.Fatal("salt has no effect")
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := unb64(s, "x")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func flipFirstChar(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}
