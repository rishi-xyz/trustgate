// primes counts primes below argv[1] with a sieve. It is deliberately
// CPU-heavy so it can demonstrate long-running asynchronous jobs.
//
// Build: GOOS=wasip1 GOARCH=wasm go build -o primes.wasm ./workloads/primes
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: primes <limit>")
		os.Exit(1)
	}
	n, err := strconv.Atoi(os.Args[1])
	if err != nil || n < 2 {
		fmt.Fprintln(os.Stderr, "limit must be an integer >= 2")
		os.Exit(1)
	}
	composite := make([]bool, n)
	count, last := 0, 0
	for i := 2; i < n; i++ {
		if composite[i] {
			continue
		}
		count++
		last = i
		for j := i * i; j < n; j += i {
			composite[j] = true
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"limit": n, "count": count, "largest": last})
}
