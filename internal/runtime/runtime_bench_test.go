package runtime

import (
	"context"
	"os"
	"testing"
)

const benchCSV = "supplier,amount\nacme,100\nbeta,90\nacme,110\nbeta,95\n"

// BenchmarkRunCSVStats measures one full execution of a real workload,
// including module compilation. It needs the published sample workloads
// (`make publish`) and is skipped otherwise.
func BenchmarkRunCSVStats(b *testing.B) {
	wasm, err := os.ReadFile("../../registry/manifests/csv-stats.wasm")
	if err != nil {
		b.Skip("run `make publish` first")
	}
	lim := Limits{MemoryMB: 256, TimeoutMS: 20000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(context.Background(), wasm, []byte(benchCSV), []string{"amount", "supplier"}, lim); err != nil {
			b.Fatal(err)
		}
	}
}

// TestRunIsRepeatable guards determinism: repeated runs (which may reuse a
// compilation cache) must produce byte-identical output.
func TestRunIsRepeatable(t *testing.T) {
	wasm, err := os.ReadFile("../../registry/manifests/csv-stats.wasm")
	if err != nil {
		t.Skip("run `make publish` first")
	}
	lim := Limits{MemoryMB: 256, TimeoutMS: 20000}
	var first []byte
	for i := 0; i < 5; i++ {
		res, err := Run(context.Background(), wasm, []byte(benchCSV), []string{"amount", "supplier"}, lim)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = res.Stdout
		} else if string(first) != string(res.Stdout) {
			t.Fatalf("run %d differs from run 0", i)
		}
	}
}
