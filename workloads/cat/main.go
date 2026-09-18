// cat echoes stdin to stdout. It is used in tests as the "malicious but
// approved" workload that a hostile parent might try to point sealed data at.
package main

import (
	"io"
	"os"
)

func main() { _, _ = io.Copy(os.Stdout, os.Stdin) }
