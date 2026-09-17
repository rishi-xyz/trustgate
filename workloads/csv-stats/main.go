// csv-stats is a deterministic TrustGate workload.
//
// stdin:  CSV with a header row.
// argv:   <value-column> [group-column]
// stdout: JSON summary (count/sum/mean/min/max/stddev, per-group sums, z>3 anomalies).
//
// Build: GOOS=wasip1 GOARCH=wasm go build -o csv-stats.wasm ./workloads/csv-stats
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
)

type anomaly struct {
	Row   int     `json:"row"`
	Value float64 `json:"value"`
	Z     float64 `json:"z"`
}

type output struct {
	Column    string             `json:"column"`
	Count     int                `json:"count"`
	Sum       float64            `json:"sum"`
	Mean      float64            `json:"mean"`
	Min       float64            `json:"min"`
	Max       float64            `json:"max"`
	StdDev    float64            `json:"stddev"`
	Groups    map[string]float64 `json:"groups,omitempty"`
	Anomalies []anomaly          `json:"anomalies"`
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: csv-stats <value-column> [group-column]")
	}
	valueCol := os.Args[1]
	groupCol := ""
	if len(os.Args) > 2 {
		groupCol = os.Args[2]
	}

	r := csv.NewReader(os.Stdin)
	header, err := r.Read()
	if err != nil {
		fail("read header: %v", err)
	}
	vi, gi := -1, -1
	for i, h := range header {
		if h == valueCol {
			vi = i
		}
		if groupCol != "" && h == groupCol {
			gi = i
		}
	}
	if vi < 0 {
		fail("column %q not found", valueCol)
	}
	if groupCol != "" && gi < 0 {
		fail("group column %q not found", groupCol)
	}

	var values []float64
	rows := []int{}
	groups := map[string]float64{}
	line := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			fail("line %d: %v", line, err)
		}
		v, err := strconv.ParseFloat(rec[vi], 64)
		if err != nil {
			fail("line %d: bad number %q", line, rec[vi])
		}
		values = append(values, v)
		rows = append(rows, line)
		if gi >= 0 {
			groups[rec[gi]] += v
		}
	}

	out := output{Column: valueCol, Count: len(values), Anomalies: []anomaly{}}
	if len(values) > 0 {
		out.Min, out.Max = values[0], values[0]
		for _, v := range values {
			out.Sum += v
			out.Min = math.Min(out.Min, v)
			out.Max = math.Max(out.Max, v)
		}
		out.Mean = out.Sum / float64(len(values))
		var sq float64
		for _, v := range values {
			sq += (v - out.Mean) * (v - out.Mean)
		}
		out.StdDev = math.Sqrt(sq / float64(len(values)))
		if out.StdDev > 0 {
			for i, v := range values {
				z := (v - out.Mean) / out.StdDev
				if math.Abs(z) > 3 {
					out.Anomalies = append(out.Anomalies, anomaly{Row: rows[i], Value: v, Z: z})
				}
			}
		}
	}
	if gi >= 0 {
		out.Groups = groups
	}
	sort.Slice(out.Anomalies, func(i, j int) bool { return out.Anomalies[i].Row < out.Anomalies[j].Row })
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fail("encode: %v", err)
	}
}
