// trustgate-parent runs on the parent instance and talks to the enclave's
// private control channel.
//
//	kms-test  send the instance role's credentials plus a KMS ciphertext; the
//	          enclave attempts an attested decrypt and answers with a hash of the
//	          plaintext (never the plaintext itself).
//	creds     keep the enclave supplied with fresh role credentials so it can
//	          unwrap data keys for confidential jobs.
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

func usage() {
	die("usage: trustgate-parent kms-test|creds [flags]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "kms-test":
		kmsTest(os.Args[2:])
	case "creds":
		credsCmd(os.Args[2:])
	default:
		usage()
	}
}

func loadCreds(ctx context.Context, region string) kms.Creds {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		die("aws config: %v", err)
	}
	cr, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		die("load instance credentials: %v", err)
	}
	return kms.Creds{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken}
}

func send(cid, port uint, req control.Request) (control.Response, error) {
	conn, err := vsock.Dial(uint32(cid), uint32(port), nil)
	if err != nil {
		return control.Response{}, fmt.Errorf("dial enclave control port: %w", err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return control.Response{}, fmt.Errorf("send: %w", err)
	}
	var resp control.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return control.Response{}, fmt.Errorf("read response: %w", err)
	}
	return resp, nil
}

func kmsTest(args []string) {
	fs := flag.NewFlagSet("kms-test", flag.ExitOnError)
	region := fs.String("region", "ap-south-1", "AWS region of the KMS key")
	cid := fs.Uint("cid", 16, "enclave CID")
	port := fs.Uint("port", 8081, "enclave control vsock port")
	ctFile := fs.String("ciphertext-file", "", "file with the base64 KMS ciphertext (aws kms encrypt --query CiphertextBlob --output text)")
	_ = fs.Parse(args)
	if *ctFile == "" {
		die("-ciphertext-file is required")
	}
	raw, err := os.ReadFile(*ctFile)
	if err != nil {
		die("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := send(*cid, *port, control.Request{
		Op:            control.OpKMSTest,
		Region:        *region,
		Creds:         loadCreds(ctx, *region),
		CiphertextB64: strings.TrimSpace(string(raw)),
		UnixTime:      time.Now().Unix(),
	})
	if err != nil {
		die("%v", err)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
	if !resp.OK {
		os.Exit(1)
	}
}

func credsCmd(args []string) {
	fs := flag.NewFlagSet("creds", flag.ExitOnError)
	region := fs.String("region", "ap-south-1", "AWS region of the KMS key")
	cid := fs.Uint("cid", 16, "enclave CID")
	port := fs.Uint("port", 8081, "enclave control vsock port")
	interval := fs.Duration("interval", 30*time.Minute, "how often to refresh the enclave's credentials")
	once := fs.Bool("once", false, "push credentials once and exit")
	_ = fs.Parse(args)

	push := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := send(*cid, *port, control.Request{Op: control.OpSetCreds, Region: *region, Creds: loadCreds(ctx, *region), UnixTime: time.Now().Unix()})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s push failed: %v\n", time.Now().Format(time.TimeOnly), err)
			return false
		}
		if !resp.OK {
			fmt.Fprintf(os.Stderr, "%s enclave refused: %s\n", time.Now().Format(time.TimeOnly), resp.Error)
			return false
		}
		fmt.Printf("%s credentials pushed to enclave (measurement %.16s…)\n", time.Now().Format(time.TimeOnly), resp.Measurement)
		return true
	}
	if *once {
		if !push() {
			os.Exit(1)
		}
		return
	}
	for {
		// Retry quickly until the enclave is up; then refresh on the normal interval.
		wait := *interval
		if !push() {
			wait = 5 * time.Second
		}
		time.Sleep(wait)
	}
}
