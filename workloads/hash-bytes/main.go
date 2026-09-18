// hash-bytes reads arbitrary binary data from stdin and prints its length and
// SHA-256. It exists to exercise binary inputs end to end.
//
// Build: GOOS=wasip1 GOARCH=wasm go build -o hash-bytes.wasm ./workloads/hash-bytes
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sum := sha256.Sum256(data)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"bytes": len(data), "sha256": hex.EncodeToString(sum[:])})
}
