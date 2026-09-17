// Package registry loads publisher-signed workload manifests and the WASM
// modules they describe. Anything unsigned, untrusted, or whose hash does not
// match is rejected (fail closed).
package registry

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"trustgate/internal/canon"
	"trustgate/internal/runtime"
)

// Manifest is the signed description of a workload.
type Manifest struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	SHA256       string   `json:"sha256"`
	Profile      string   `json:"profile"`
	MaxMemoryMB  uint32   `json:"max_memory_mb"`
	MaxTimeoutMS uint32   `json:"max_timeout_ms"`
	Capabilities []string `json:"capabilities"`
	Publisher    string   `json:"publisher"`
	Sig          string   `json:"sig,omitempty"`
}

func (m Manifest) signBytes() ([]byte, error) {
	m.Sig = ""
	return canon.Marshal(m)
}

// Sign signs m in place with the publisher key.
func Sign(m *Manifest, priv ed25519.PrivateKey) error {
	m.Publisher = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	msg, err := m.signBytes()
	if err != nil {
		return err
	}
	m.Sig = hex.EncodeToString(ed25519.Sign(priv, msg))
	return nil
}

// Workload is a verified, loadable workload.
type Workload struct {
	Manifest Manifest
	Wasm     []byte
}

type Registry struct {
	byName map[string]*Workload
	byHash map[string]*Workload
}

// Load reads every *.manifest.json in dir. wasm files are looked up as
// <name>.wasm next to the manifest. Only manifests signed by a trusted
// publisher are accepted; the rest are returned as errors and skipped.
func Load(dir string, trusted []ed25519.PublicKey) (*Registry, []error) {
	r := &Registry{byName: map[string]*Workload{}, byHash: map[string]*Workload{}}
	var errs []error
	files, _ := filepath.Glob(filepath.Join(dir, "*.manifest.json"))
	for _, f := range files {
		w, err := loadOne(f, trusted)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), err))
			continue
		}
		r.byName[w.Manifest.Name] = w
		r.byHash[w.Manifest.SHA256] = w
	}
	return r, errs
}

func loadOne(path string, trusted []ed25519.PublicKey) (*Workload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(m.Publisher)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid publisher key")
	}
	ok := false
	for _, t := range trusted {
		if t.Equal(ed25519.PublicKey(pub)) {
			ok = true
		}
	}
	if !ok {
		return nil, errors.New("publisher is not trusted")
	}
	msg, err := m.signBytes()
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil || !ed25519.Verify(pub, msg, sig) {
		return nil, errors.New("manifest signature invalid")
	}
	if m.Profile != runtime.ProfileDeterministicV1 {
		return nil, fmt.Errorf("unsupported profile %q", m.Profile)
	}
	if len(m.Capabilities) != 0 {
		return nil, fmt.Errorf("unsupported capabilities %v (only deny-all is implemented)", m.Capabilities)
	}
	if m.MaxMemoryMB == 0 || m.MaxTimeoutMS == 0 {
		return nil, errors.New("manifest limits must be non-zero")
	}
	wasmPath := strings.TrimSuffix(path, ".manifest.json") + ".wasm"
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	if got := canon.SHA256(wasm); got != m.SHA256 {
		return nil, fmt.Errorf("wasm hash mismatch: manifest %s, file %s", m.SHA256, got)
	}
	return &Workload{Manifest: m, Wasm: wasm}, nil
}

// Get finds a workload by name or by sha256:<hex>.
func (r *Registry) Get(ref string) (*Workload, bool) {
	if w, ok := r.byName[ref]; ok {
		return w, true
	}
	w, ok := r.byHash[ref]
	return w, ok
}

// List returns manifests sorted by name.
func (r *Registry) List() []Manifest {
	out := make([]Manifest, 0, len(r.byName))
	for _, w := range r.byName {
		out = append(out, w.Manifest)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
