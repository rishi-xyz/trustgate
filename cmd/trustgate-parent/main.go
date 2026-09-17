// trustgate-parent runs on the parent instance and talks to the enclave's
// private control channel. `kms-test` sends the instance role's temporary AWS
// credentials plus a KMS ciphertext; the enclave attempts an attested decrypt
// and answers with a hash of the plaintext (never the plaintext itself).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/mdlayher/vsock"

	"trustgate/internal/control"
	"trustgate/internal/kms"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "kms-test" {
		die("usage: trustgate-parent kms-test -ciphertext-file ct.b64 [-region ap-south-1] [-cid 16] [-port 8081]")
	}
	fs := flag.NewFlagSet("kms-test", flag.ExitOnError)
	region := fs.String("region", "ap-south-1", "AWS region of the KMS key")
	cid := fs.Uint("cid", 16, "enclave CID")
	port := fs.Uint("port", 8081, "enclave control vsock port")
	ctFile := fs.String("ciphertext-file", "", "file with the base64 KMS ciphertext (aws kms encrypt --query CiphertextBlob --output text)")
	_ = fs.Parse(os.Args[2:])
	if *ctFile == "" {
		die("-ciphertext-file is required")
	}
	raw, err := os.ReadFile(*ctFile)
	if err != nil {
		die("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region))
	if err != nil {
		die("aws config: %v", err)
	}
	cr, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		die("load instance credentials: %v", err)
	}

	conn, err := vsock.Dial(uint32(*cid), uint32(*port), nil)
	if err != nil {
		die("dial enclave control port: %v", err)
	}
	defer conn.Close()
	req := control.Request{
		Region:        *region,
		Creds:         kms.Creds{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken},
		CiphertextB64: strings.TrimSpace(string(raw)),
		UnixTime:      time.Now().Unix(),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		die("send: %v", err)
	}
	var resp control.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		die("read response: %v", err)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
	if !resp.OK {
		os.Exit(1)
	}
}
