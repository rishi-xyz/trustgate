package main

import (
	"context"
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

// execCmd calls the execute tool over MCP Streamable HTTP, prints the workload
// output and saves the receipt bundle. It is a scriptable stand-in for an agent.
func execCmd(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/mcp", "MCP endpoint")
	token := fs.String("token", os.Getenv("TRUSTGATE_TOKEN"), "bearer token")
	workload := fs.String("workload", "", "workload name or sha256")
	inputFile := fs.String("input", "", "file whose contents are sent as stdin")
	argList := fs.String("args", "", "comma-separated workload arguments")
	out := fs.String("out", "receipt.json", "where to save the receipt bundle")
	_ = fs.Parse(args)
	if *workload == "" {
		die("-workload is required")
	}
	var input string
	if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			die("%v", err)
		}
		input = string(b)
	}
	callArgs := map[string]any{"workload": *workload, "input": input}
	if *argList != "" {
		callArgs["args"] = strings.Split(*argList, ",")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "execute", Arguments: callArgs})
	if err != nil {
		die("execute: %v", err)
	}
	m, _ := res.StructuredContent.(map[string]any)
	if m == nil {
		die("no structured result: %+v", res.Content)
	}
	fmt.Printf("status: %v\n%v\n", m["status"], m["output"])
	if s, _ := m["stderr"].(string); s != "" {
		fmt.Printf("stderr: %s\n", s)
	}
	raw, _ := json.MarshalIndent(m["receipt_bundle"], "", "  ")
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		die("%v", err)
	}
	fmt.Printf("receipt saved to %s\n", *out)
	if res.IsError {
		os.Exit(1)
	}
}
