package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// call invokes a tool and returns its structured result.
func call(ctx context.Context, sess *mcp.ClientSession, name string, args map[string]any) (map[string]any, *mcp.CallToolResult) {
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		die("%s: %v", name, err)
	}
	m, _ := res.StructuredContent.(map[string]any)
	if m == nil {
		var msgs []string
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				msgs = append(msgs, t.Text)
			}
		}
		die("%s: %s", name, strings.Join(msgs, "; "))
	}
	return m, res
}

// execCmd calls the execute tool (or execute_async with -async) over MCP
// Streamable HTTP, prints the workload output and saves the receipt bundle.
// It is a scriptable stand-in for an agent. The input file is sent as raw
// bytes, so binary files work.
func execCmd(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/mcp", "MCP endpoint")
	token := fs.String("token", os.Getenv("TRUSTGATE_TOKEN"), "bearer token")
	workload := fs.String("workload", "", "workload name or sha256")
	inputFile := fs.String("input", "", "file whose bytes are sent as stdin (binary is fine)")
	argList := fs.String("args", "", "comma-separated workload arguments")
	out := fs.String("out", "receipt.json", "where to save the receipt bundle")
	sealed := fs.String("sealed", "", "sealed input file from `trustgate seal` (confidential job)")
	recipient := fs.String("recipient", "", "recipient private key to decrypt a sealed result (default: from the .meta sidecar)")
	async := fs.Bool("async", false, "run as an async job and poll until it finishes")
	poll := fs.Duration("poll", 500*time.Millisecond, "async: polling interval")
	_ = fs.Parse(args)
	if *workload == "" {
		die("-workload is required")
	}
	callArgs := map[string]any{"workload": *workload}
	var meta sealMeta
	if *sealed != "" {
		if *inputFile != "" {
			die("-sealed and -input are mutually exclusive")
		}
		raw, err := os.ReadFile(*sealed)
		if err != nil {
			die("%v", err)
		}
		var env map[string]any
		if err := json.Unmarshal(raw, &env); err != nil {
			die("bad sealed file: %v", err)
		}
		callArgs["sealed_input"] = env
		if mraw, err := os.ReadFile(*sealed + ".meta"); err == nil {
			_ = json.Unmarshal(mraw, &meta)
			if *argList == "" && len(meta.Args) > 0 {
				*argList = strings.Join(meta.Args, ",")
			}
			if *recipient == "" {
				*recipient = meta.RecipientKey
			}
		}
	}
	if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			die("%v", err)
		}
		callArgs["input_b64"] = base64.StdEncoding.EncodeToString(b)
	}
	if *argList != "" {
		callArgs["args"] = strings.Split(*argList, ",")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "trustgate-cli", Version: "0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   *url,
		HTTPClient: &http.Client{Transport: bearerTransport{*token}},
	}, nil)
	if err != nil {
		die("connect: %v", err)
	}
	defer sess.Close()

	var m map[string]any
	failed := false
	if *async {
		job, _ := call(ctx, sess, "execute_async", callArgs)
		id, _ := job["job_id"].(string)
		fmt.Printf("job %s submitted\n", id)
		last := ""
		for {
			st, _ := call(ctx, sess, "job_status", map[string]any{"job_id": id})
			status, _ := st["status"].(string)
			if status != last {
				fmt.Printf("  status: %s\n", status)
				last = status
			}
			if status != "queued" && status != "running" {
				break
			}
			time.Sleep(*poll)
		}
		res, _ := call(ctx, sess, "job_result", map[string]any{"job_id": id})
		if r, ok := res["result"].(map[string]any); ok {
			m = r
		} else {
			die("job ended with status %v: %v", res["status"], res["error"])
		}
		failed = res["status"] != "succeeded"
	} else {
		var res *mcp.CallToolResult
		m, res = call(ctx, sess, "execute", callArgs)
		failed = res.IsError
	}

	if so, ok := m["sealed_output"]; ok {
		showSealed(m, so, *recipient, meta, *out)
	} else {
		fmt.Printf("status: %v\n%v\n", m["status"], m["output"])
		if s, _ := m["stderr"].(string); s != "" {
			fmt.Printf("stderr: %s\n", s)
		}
	}
	raw, _ := json.MarshalIndent(m["receipt_bundle"], "", "  ")
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		die("%v", err)
	}
	fmt.Printf("receipt saved to %s\n", *out)
	if failed {
		os.Exit(1)
	}
}

// showSealed decrypts a confidential result and writes the salts needed to
// check the receipt's commitments later (kept private by the data owner).
func showSealed(m map[string]any, so any, recipientKey string, meta sealMeta, out string) {
	fmt.Printf("status: %v\n(result is sealed: the server and any relay only saw ciphertext)\n", m["status"])
	if recipientKey == "" {
		fmt.Println("no -recipient key given: cannot decrypt")
		return
	}
	bundle, _ := m["receipt_bundle"].(map[string]any)
	rec, _ := bundle["receipt"].(map[string]any)
	conf, _ := rec["confidential"].(map[string]any)
	ctSHA, _ := conf["input_ciphertext_sha256"].(string)
	p, err := openSealedOutput(so, recipientKey, ctSHA)
	if err != nil {
		die("decrypt result: %v", err)
	}
	fmt.Printf("decrypted result:\n%s", p.Stdout)
	salts, _ := json.MarshalIndent(map[string]string{"salt_in": meta.SaltIn, "salt_out": hex.EncodeToString(p.Salt)}, "", "  ")
	if err := os.WriteFile(out+".salts.json", salts, 0o600); err == nil {
		fmt.Printf("salts saved to %s.salts.json (private)\n", out)
	}
}
