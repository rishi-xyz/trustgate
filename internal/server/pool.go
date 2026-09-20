package server

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// ErrBusy is returned when every worker is occupied for longer than the caller
// is willing to wait. It is a clear, retryable answer instead of letting a
// burst of requests exhaust the enclave's memory.
var ErrBusy = errors.New("server busy: all workers are in use, retry in a few seconds")

// pool bounds concurrent workload executions. Every path that runs a workload
// (execute, execute_async, replay) takes a slot, so total memory stays within
// workers x the per-workload memory limit.
type pool struct {
	sem     chan struct{}
	started time.Time

	inflight atomic.Int64
	queued   atomic.Int64
	executed atomic.Int64
	rejected atomic.Int64
}

func newPool(workers int) *pool {
	return &pool{sem: make(chan struct{}, workers), started: time.Now()}
}

// acquire waits for a worker. wait < 0 waits until ctx ends (used by async
// jobs, which are allowed to sit in the queue); otherwise it gives up after
// wait with ErrBusy. The returned func releases the slot.
func (p *pool) acquire(ctx context.Context, wait time.Duration) (func(), error) {
	select {
	case p.sem <- struct{}{}:
		p.inflight.Add(1)
		return p.release, nil
	default:
	}

	p.queued.Add(1)
	defer p.queued.Add(-1)
	var timeout <-chan time.Time
	if wait >= 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case p.sem <- struct{}{}:
		p.inflight.Add(1)
		return p.release, nil
	case <-timeout:
		p.rejected.Add(1)
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pool) release() {
	p.inflight.Add(-1)
	p.executed.Add(1)
	<-p.sem
}

// Stats is a point-in-time view of the server, safe to expose: counters only,
// never any request or result data.
type Stats struct {
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Workers       int    `json:"workers"`
	InFlight      int64  `json:"in_flight"`
	Queued        int64  `json:"queued"`
	Executed      int64  `json:"executed"`
	Rejected      int64  `json:"rejected_busy"`
}

func (p *pool) stats() Stats {
	return Stats{
		Status:        "ok",
		UptimeSeconds: int64(time.Since(p.started).Seconds()),
		Workers:       cap(p.sem),
		InFlight:      p.inflight.Load(),
		Queued:        p.queued.Load(),
		Executed:      p.executed.Load(),
		Rejected:      p.rejected.Load(),
	}
}
