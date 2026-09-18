// trustgate-server is the MCP execution server. In production it runs inside
// a Nitro Enclave (-mode nitro); locally it runs in insecure -mode dev.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdlayher/vsock"

	"trustgate/internal/attest"
	"trustgate/internal/control"
	"trustgate/internal/kms"
	"trustgate/internal/receipts"
	"trustgate/internal/registry"
	"trustgate/internal/seal"
	"trustgate/internal/server"
)

func main() {
	var (
		addr       = flag.String("addr", ":8080", "listen address")
		mode       = flag.String("mode", "dev", "attestation mode: dev (INSECURE, local only) or nitro")
		regDir     = flag.String("registry", "registry/manifests", "directory of signed workload manifests and wasm")
		publishers = flag.String("publisher-pub", "", "comma-separated hex Ed25519 publisher public keys to trust")
		pubFile    = flag.String("publisher-pub-file", "", "file with a hex publisher public key (one per line)")
		devDir     = flag.String("dev-dir", ".trustgate-dev", "dev mode: directory for the dev attestation root key")
		tenant     = flag.String("tenant", "demo", "tenant label recorded in receipts")
		vsockPort  = flag.Uint("vsock-port", 0, "listen on this vsock port instead of TCP (required inside a Nitro Enclave)")
		ctlPort    = flag.Uint("control-vsock-port", 0, "nitro: private vsock port for the parent's control channel (KMS decrypt self-test)")
		kmsProxy   = flag.Uint("kms-proxy-port", 8000, "nitro: parent vsock-proxy port that forwards to the KMS endpoint")
	)
	flag.Parse()

	trusted := parsePublishers(*publishers, *pubFile)
	if len(trusted) == 0 {
		log.Fatal("no trusted publisher keys: pass -publisher-pub or -publisher-pub-file")
	}
	reg, errs := registry.Load(*regDir, trusted)
	for _, e := range errs {
		log.Printf("REJECTED workload: %v", e)
	}
	log.Printf("loaded %d workload(s)", len(reg.List()))

	var (
		provider attest.Provider
		devTrust []byte
		keys     seal.KeyProvider
		kmsProv  *kms.Provider
	)
	switch *mode {
	case attest.ModeDev:
		d, err := attest.NewDev(filepath.Join(*devDir, "root.key"), "")
		if err != nil {
			log.Fatal(err)
		}
		provider, devTrust = d, d.TrustKey()
		dk, err := seal.LoadDevKMS(filepath.Join(*devDir, "kms-master.key"))
		if err != nil {
			log.Fatal(err)
		}
		keys = dk
		log.Println("confidential jobs: DEV KMS (local master key, no protection from this machine's operator)")
		log.Println("*** DEV MODE: software-only attestation, NO hardware isolation. Do not use with real data. ***")
	case attest.ModeNitro:
		n, err := attest.NewNitro()
		if err != nil {
			log.Fatal(err)
		}
		provider = n
		// Data keys are unwrapped by attested KMS calls through the parent's
		// vsock-proxy, using credentials the parent pushes over the control channel.
		kmsProv = &kms.Provider{
			Attester: n,
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return vsock.Dial(3, uint32(*kmsProxy), nil)
			},
		}
		keys = kmsProv
	default:
		log.Fatalf("unknown -mode %q", *mode)
	}

	signer, err := receipts.NewSigner()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Tenant:   *tenant,
		Registry: reg,
		Signer:   signer,
		Provider: provider,
		DevTrust: devTrust,
		Token:    os.Getenv("TRUSTGATE_TOKEN"),
		Keys:     keys,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mode=%s measurement=%s signer=%s epoch=%s", provider.Mode(), provider.Measurement(), hex.EncodeToString(signer.PublicKey()), signer.Epoch())
	if len(devTrust) > 0 {
		log.Printf("dev trust key (for `trustgate verify --dev-trust`): %s", hex.EncodeToString(devTrust))
	}

	if *ctlPort != 0 {
		att, ok := provider.(kms.Attester)
		if !ok {
			log.Fatal("control channel needs -mode nitro")
		}
		ctl := &control.Handler{
			Keys:        kmsProv,
			Attester:    att,
			Measurement: provider.Measurement(),
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				// Every AWS endpoint is reached through the parent's vsock-proxy (CID 3).
				return vsock.Dial(3, uint32(*kmsProxy), nil)
			},
		}
		cl, err := vsock.Listen(uint32(*ctlPort), nil)
		if err != nil {
			log.Fatalf("control listen: %v", err)
		}
		log.Printf("control channel on vsock port %d", *ctlPort)
		go func() { log.Fatal(ctl.Serve(cl)) }()
	}

	hs := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if *vsockPort != 0 {
		l, err := vsock.Listen(uint32(*vsockPort), nil)
		if err != nil {
			log.Fatalf("vsock listen: %v", err)
		}
		log.Printf("listening on vsock port %d (MCP at /mcp)", *vsockPort)
		log.Fatal(hs.Serve(l))
	}
	log.Printf("listening on %s (MCP at /mcp)", *addr)
	log.Fatal(hs.ListenAndServe())
}

func parsePublishers(csv, file string) []ed25519.PublicKey {
	var items []string
	items = append(items, strings.Split(csv, ",")...)
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("read publisher file: %v", err)
		}
		items = append(items, strings.Fields(string(raw))...)
	}
	var out []ed25519.PublicKey
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		b, err := hex.DecodeString(it)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("invalid publisher public key %q", it)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out
}
