package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trustgate/internal/seal"
)

// sealMeta is the data owner's private sidecar for a sealed input. It holds
// the secret salt needed to check the receipt's input commitment.
type sealMeta struct {
	SaltIn       string   `json:"salt_in"`
	WorkloadSHA  string   `json:"workload_sha256"`
	Args         []string `json:"args"`
	RecipientKey string   `json:"recipient_key"`
}

func loadOrCreateRecipient(path string) *ecdh.PrivateKey {
	if raw, err := os.ReadFile(path); err == nil {
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			die("recipient key %s is not hex", path)
		}
		k, err := ecdh.X25519().NewPrivateKey(b)
		if err != nil {
			die("recipient key %s: %v", path, err)
		}
		return k
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k.Bytes())+"\n"), 0o600); err != nil {
		die("%v", err)
	}
	fmt.Printf("created recipient key %s (keep it private; only its holder can read results)\n", path)
	return k
}

// resolveWorkloadSHA asks the server for a workload's hash so the ciphertext
// can be bound to that exact module.
func resolveWorkloadSHA(url, token, name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "trustgate-cli", Version: "0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: bearerTransport{token}}}, nil)
	if err != nil {
		die("connect: %v", err)
	}
	defer sess.Close()
	m, _ := call(ctx, sess, "list_workloads", map[string]any{})
	list, _ := m["workloads"].([]any)
	for _, w := range list {
		wm, _ := w.(map[string]any)
		if wm["name"] == name || wm["sha256"] == name {
			return wm["sha256"].(string)
		}
	}
	die("workload %q not found on %s", name, url)
	return ""
}

func generateDataKey(mode, region, devDir string) (plain, wrapped []byte) {
	switch {
	case mode == "dev":
		d, err := seal.LoadDevKMS(filepath.Join(devDir, "kms-master.key"))
		if err != nil {
			die("%v", err)
		}
		plain, wrapped, err = d.GenerateDataKey()
		if err != nil {
			die("%v", err)
		}
	case strings.HasPrefix(mode, "aws:"):
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			die("aws config: %v", err)
		}
		out, err := awskms.NewFromConfig(cfg).GenerateDataKey(ctx, &awskms.GenerateDataKeyInput{KeyId: strPtr(strings.TrimPrefix(mode, "aws:")), KeySpec: kmstypes.DataKeySpecAes256})
		if err != nil {
			die("kms GenerateDataKey: %v", err)
		}
		plain, wrapped = out.Plaintext, out.CiphertextBlob
	default:
		die("-kms must be dev or aws:<key-id-or-alias>")
	}
	return
}

func strPtr(s string) *string { return &s }

// sealCmd encrypts an input file for one specific job.
func sealCmd(args []string) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/mcp", "MCP endpoint, used to look up the workload hash")
	token := fs.String("token", os.Getenv("TRUSTGATE_TOKEN"), "bearer token")
	workload := fs.String("workload", "", "workload name or sha256")
	argList := fs.String("args", "", "comma-separated workload arguments (bound into the ciphertext)")
	input := fs.String("input", "", "file to encrypt")
	out := fs.String("out", "sealed.json", "sealed input output file (a .meta sidecar is written next to it)")
	recip := fs.String("recipient", "recipient.key", "X25519 private key file for receiving results (created if missing)")
	kmsMode := fs.String("kms", "dev", "dev (local, insecure) or aws:<key-id-or-alias>")
	region := fs.String("region", "ap-south-1", "AWS region for -kms aws:...")
	devDir := fs.String("dev-dir", ".trustgate-dev", "dev mode key directory")
	_ = fs.Parse(args)
	if *workload == "" || *input == "" {
		die("-workload and -input are required")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		die("%v", err)
	}
	var wargs []string
	if *argList != "" {
		wargs = strings.Split(*argList, ",")
	}
	sha := *workload
	if !strings.HasPrefix(sha, "sha256:") {
		sha = resolveWorkloadSHA(*url, *token, *workload)
	}
	rk := loadOrCreateRecipient(*recip)
	dk, wrapped := generateDataKey(*kmsMode, *region, *devDir)
	env, salt, err := seal.SealInput(dk, wrapped, sha, wargs, rk.PublicKey().Bytes(), data)
	clear(dk)
	if err != nil {
		die("%v", err)
	}
	raw, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		die("%v", err)
	}
	meta, _ := json.MarshalIndent(sealMeta{SaltIn: hex.EncodeToString(salt), WorkloadSHA: sha, Args: wargs, RecipientKey: *recip}, "", "  ")
	if err := os.WriteFile(*out+".meta", meta, 0o600); err != nil {
		die("%v", err)
	}
	fmt.Printf("sealed %d bytes for %s (args %v)\n  -> %s (safe to hand to an untrusted parent)\n  -> %s.meta (private: contains the input salt)\n", len(data), sha, wargs, *out, *out)
}

// openSealedOutput decrypts a sealed output with the recipient key and returns
// the plaintext and the output salt.
func openSealedOutput(raw any, recipientKeyPath, ciphertextSHA string) (*seal.OutputPayload, error) {
	b, _ := json.Marshal(raw)
	var so seal.SealedOutput
	if err := json.Unmarshal(b, &so); err != nil {
		return nil, err
	}
	kraw, err := os.ReadFile(recipientKeyPath)
	if err != nil {
		return nil, err
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(kraw)))
	if err != nil {
		return nil, fmt.Errorf("recipient key is not hex")
	}
	return seal.OpenOutput(priv, &so, ciphertextSHA)
}
