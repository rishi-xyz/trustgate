package kms

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Interop check against OpenSSL's CMS implementation using the same
// parameters KMS uses (RSAES-OAEP with SHA-256, AES-256-CBC).
func TestDecryptCMSOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("openssl", "req", "-new", "-x509", "-key", keyPath, "-subj", "/CN=test", "-days", "1", "-out", certPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	// "-stream" makes OpenSSL emit BER with indefinite lengths and chunked
	// content, which is what AWS KMS returns.
	for _, stream := range []bool{false, true} {
		for _, msg := range [][]byte{[]byte("hello secret"), bytes.Repeat([]byte("A"), 32), []byte("x"), bytes.Repeat([]byte("Z"), 5000)} {
			in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out.der")
			if err := os.WriteFile(in, msg, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"cms", "-encrypt", "-binary", "-aes-256-cbc", "-recip", certPath,
				"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256",
				"-outform", "DER", "-in", in, "-out", out}
			if stream {
				args = append(args, "-stream")
			}
			if b, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
				t.Fatalf("openssl cms: %v\n%s", err, b)
			}
			der, _ := os.ReadFile(out)
			got, err := DecryptCMS(key, der)
			if err != nil {
				t.Fatalf("DecryptCMS(%q): %v", msg, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("got %q want %q", got, msg)
			}
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "out.der")); len(raw) < 2 || raw[1] != 0x80 {
		t.Fatal("test bug: -stream output was expected to use indefinite length")
	}
	// A different key must not open it.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := os.ReadFile(filepath.Join(dir, "out.der"))
	if _, err := DecryptCMS(other, der); err == nil {
		t.Fatal("wrong key decrypted the message")
	}
}
