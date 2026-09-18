// trustgate is the publisher and verifier CLI.
//
//	trustgate keygen  -out publisher
//	trustgate publish -key publisher.key -wasm x.wasm -name x -version 1 -out registry/manifests
//	trustgate exec    -workload x -input file -args a,b -out receipt.json
//	trustgate verify  bundle.json [-allow-dev -dev-trust HEX] [-measurement HEX]
//	trustgate replay  bundle.json -wasm x.wasm -stdin input.txt [...]
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"trustgate/internal/canon"
	"trustgate/internal/receipts"
	"trustgate/internal/registry"
	"trustgate/internal/runtime"
	"trustgate/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "publish":
		publish(os.Args[2:])
	case "seal":
		sealCmd(os.Args[2:])
	case "exec":
		execCmd(os.Args[2:])
	case "verify":
		os.Exit(verifyCmd(os.Args[2:], false))
	case "replay":
		os.Exit(verifyCmd(os.Args[2:], true))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: trustgate keygen|publish|seal|exec|verify|replay [flags]")
	os.Exit(2)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "publisher", "output basename (<out>.key, <out>.pub)")
	_ = fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(*out+".key", []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		die("%v", err)
	}
	fmt.Printf("wrote %s.key (secret) and %s.pub\npublisher public key: %s\n", *out, *out, hex.EncodeToString(pub))
}

func publish(args []string) {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	key := fs.String("key", "publisher.key", "publisher private key file")
	wasmPath := fs.String("wasm", "", "workload .wasm file")
	name := fs.String("name", "", "workload name")
	version := fs.String("version", "1", "workload version")
	desc := fs.String("desc", "", "description")
	mem := fs.Uint("max-memory-mb", 256, "maximum memory (MB)")
	timeout := fs.Uint("max-timeout-ms", 10000, "maximum runtime (ms)")
	out := fs.String("out", "registry/manifests", "output directory")
	_ = fs.Parse(args)
	if *wasmPath == "" || *name == "" {
		die("-wasm and -name are required")
	}
	rawKey, err := os.ReadFile(*key)
	if err != nil {
		die("%v", err)
	}
	priv, err := hex.DecodeString(string(rawKey))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		die("invalid private key")
	}
	wasm, err := os.ReadFile(*wasmPath)
	if err != nil {
		die("%v", err)
	}
	m := registry.Manifest{
		Name: *name, Version: *version, Description: *desc,
		SHA256: canon.SHA256(wasm), Profile: runtime.ProfileDeterministicV1,
		MaxMemoryMB: uint32(*mem), MaxTimeoutMS: uint32(*timeout), Capabilities: []string{},
	}
	if err := registry.Sign(&m, ed25519.PrivateKey(priv)); err != nil {
		die("%v", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("%v", err)
	}
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, *name+".manifest.json"), mj, 0o644); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(filepath.Join(*out, *name+".wasm"), wasm, 0o644); err != nil {
		die("%v", err)
	}
	fmt.Printf("published %s@%s  %s\n", m.Name, m.Version, m.SHA256)
}

func loadBundle(path string) *receipts.Bundle {
	raw, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	// Accept either a bare bundle or the full execute output.
	var wrapper struct {
		Receipt json.RawMessage `json:"receipt_bundle"`
	}
	if json.Unmarshal(raw, &wrapper) == nil && len(wrapper.Receipt) > 0 {
		raw = wrapper.Receipt
	}
	var b receipts.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		die("bad bundle: %v", err)
	}
	return &b
}

// verifyCmd returns the process exit code.
func verifyCmd(args []string, replay bool) int {
	name := "verify"
	if replay {
		name = "replay"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	allowDev := fs.Bool("allow-dev", false, "accept INSECURE software-only dev attestations")
	devTrust := fs.String("dev-trust", "", "hex public key trusted for dev attestations")
	measurement := fs.String("measurement", "", "expected enclave measurement (hex PCR0 / dev binary hash)")
	wasmPath := fs.String("wasm", "", "replay: workload .wasm to re-run")
	stdinPath := fs.String("stdin", "", "replay: input file used originally")
	saltsPath := fs.String("salts", "", "replay of a confidential receipt: JSON file with salt_in and salt_out (written by `exec -sealed`)")
	// Allow the bundle path before or after flags.
	var bundlePath string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		bundlePath, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if bundlePath == "" && fs.NArg() > 0 {
		bundlePath = fs.Arg(0)
	}
	if bundlePath == "" {
		die("bundle file required")
	}
	b := loadBundle(bundlePath)

	opt := verify.Options{AllowDev: *allowDev, ExpectedMeasurement: *measurement}
	if *devTrust != "" {
		k, err := hex.DecodeString(*devTrust)
		if err != nil || len(k) != ed25519.PublicKeySize {
			die("invalid -dev-trust")
		}
		opt.DevTrust = k
	}
	checks := verify.Bundle(b, opt)

	if replay {
		if *wasmPath == "" || *stdinPath == "" {
			die("replay needs -wasm and -stdin")
		}
		wasm, err := os.ReadFile(*wasmPath)
		if err != nil {
			die("%v", err)
		}
		stdin, err := os.ReadFile(*stdinPath)
		if err != nil {
			die("%v", err)
		}
		var saltIn, saltOut []byte
		if *saltsPath != "" {
			raw, err := os.ReadFile(*saltsPath)
			if err != nil {
				die("%v", err)
			}
			var sj struct{ In, Out string }
			var tmp map[string]string
			if err := json.Unmarshal(raw, &tmp); err != nil {
				die("bad salts file: %v", err)
			}
			sj.In, sj.Out = tmp["salt_in"], tmp["salt_out"]
			if saltIn, err = hex.DecodeString(sj.In); err != nil {
				die("bad salt_in")
			}
			if saltOut, err = hex.DecodeString(sj.Out); err != nil {
				die("bad salt_out")
			}
		}
		checks = append(checks, verify.ReplaySalted(context.Background(), b, wasm, stdin, saltIn, saltOut)...)
	}

	for _, c := range checks {
		mark := map[string]string{verify.Pass: "✓", verify.Fail: "✗", verify.Skip: "-"}[c.Status]
		fmt.Printf("%s %s", mark, c.Name)
		if c.Detail != "" {
			fmt.Printf(": %s", c.Detail)
		}
		fmt.Println()
	}
	fmt.Println()
	if !verify.OK(checks) {
		fmt.Println("VERIFICATION FAILED")
		return 1
	}
	if b.Receipt.AttestationMode == "dev" {
		fmt.Println("EXECUTION CHECKS PASSED (dev mode: software-only, not hardware-attested)")
	} else {
		fmt.Println("EXECUTION VERIFIED (proves what ran and where, not that the result is correct)")
	}
	return 0
}
