package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Async jobs are exposed as ordinary MCP tools rather than the MCP Tasks
// extension: the Go SDK has no Tasks support yet and agent clients handle
// plain tools everywhere. The tool shapes are deliberately close to tasks
// (a handle, a status, a result, cancel) so they can be mapped later.

const (
	maxLiveJobs = 64
	jobTTL      = time.Hour
)

const (
	jobQueued    = "queued"
	jobRunning   = "running"
	jobSucceeded = "succeeded"
	jobFailed    = "failed"
	jobCancelled = "cancelled"
)

type job struct {
	id       string
	status   string
	created  time.Time
	started  time.Time
	finished time.Time
	out      *ExecuteOutput
	errMsg   string
	cancel   context.CancelFunc
}

type jobStore struct {
	s  *Server
	mu sync.Mutex
	m  map[string]*job
}

func newJobStore(s *Server) *jobStore {
	return &jobStore{s: s, m: map[string]*job{}}
}

type JobOutput struct {
	JobID      string         `json:"job_id"`
	Status     string         `json:"status" jsonschema:"queued, running, succeeded, failed or cancelled"`
	CreatedAt  string         `json:"created_at"`
	StartedAt  string         `json:"started_at,omitempty"`
	FinishedAt string         `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Result     *ExecuteOutput `json:"result,omitempty" jsonschema:"present from job_result once the job has finished (succeeded or failed, both with a signed receipt)"`
}

type JobRef struct {
	JobID string `json:"job_id" jsonschema:"job id returned by execute_async"`
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// view must be called with mu held.
func (j *job) view(withResult bool) JobOutput {
	o := JobOutput{JobID: j.id, Status: j.status, CreatedAt: ts(j.created), StartedAt: ts(j.started), FinishedAt: ts(j.finished), Error: j.errMsg}
	if withResult {
		o.Result = j.out
	}
	return o
}

func (js *jobStore) submit(_ context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, JobOutput, error) {
	p, err := js.s.prepare(in)
	if err != nil {
		return nil, JobOutput{}, err
	}
	idb := make([]byte, 8)
	if _, err := rand.Read(idb); err != nil {
		return nil, JobOutput{}, err
	}

	js.mu.Lock()
	js.gcLocked()
	if len(js.m) >= maxLiveJobs {
		js.mu.Unlock()
		return nil, JobOutput{}, fmt.Errorf("too many jobs in memory (%d); wait for some to expire or cancel them", maxLiveJobs)
	}
	// Jobs outlive the request that started them, so they get their own context.
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{id: hex.EncodeToString(idb), status: jobQueued, created: time.Now(), cancel: cancel}
	js.m[j.id] = j
	view := j.view(false)
	js.mu.Unlock()

	go js.run(ctx, j, p)
	return nil, view, nil
}

func (js *jobStore) run(ctx context.Context, j *job, p *prepared) {
	// Async jobs share the worker pool with synchronous calls and may wait in
	// the queue indefinitely (until cancelled), unlike synchronous requests.
	release, err := js.s.pool.acquire(ctx, -1)
	if err != nil {
		js.finish(j, nil, context.Canceled, nil)
		return
	}
	defer release()
	js.mu.Lock()
	if j.status == jobCancelled {
		js.mu.Unlock()
		return
	}
	j.status, j.started = jobRunning, time.Now()
	js.mu.Unlock()

	out, runErr, err := js.s.runPrepared(ctx, p)
	if err != nil {
		js.finish(j, nil, nil, err)
		return
	}
	js.finish(j, &out, runErr, nil)
}

func (js *jobStore) finish(j *job, out *ExecuteOutput, runErr, internal error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	j.finished = time.Now()
	j.cancel()
	switch {
	case j.status == jobCancelled || errors.Is(runErr, context.Canceled):
		j.status = jobCancelled
	case internal != nil:
		j.status, j.errMsg = jobFailed, internal.Error()
	case runErr != nil:
		j.status, j.errMsg, j.out = jobFailed, runErr.Error(), out
	default:
		j.status, j.out = jobSucceeded, out
	}
}

func (js *jobStore) get(id string) (*job, error) {
	j, ok := js.m[id]
	if !ok {
		return nil, fmt.Errorf("unknown or expired job %q", id)
	}
	return j, nil
}

func (js *jobStore) status(_ context.Context, _ *mcp.CallToolRequest, in JobRef) (*mcp.CallToolResult, JobOutput, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	j, err := js.get(in.JobID)
	if err != nil {
		return nil, JobOutput{}, err
	}
	return nil, j.view(false), nil
}

func (js *jobStore) result(_ context.Context, _ *mcp.CallToolRequest, in JobRef) (*mcp.CallToolResult, JobOutput, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	j, err := js.get(in.JobID)
	if err != nil {
		return nil, JobOutput{}, err
	}
	return nil, j.view(true), nil
}

func (js *jobStore) cancel(_ context.Context, _ *mcp.CallToolRequest, in JobRef) (*mcp.CallToolResult, JobOutput, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	j, err := js.get(in.JobID)
	if err != nil {
		return nil, JobOutput{}, err
	}
	if j.status == jobQueued || j.status == jobRunning {
		j.status, j.finished = jobCancelled, time.Now()
		j.cancel()
	}
	return nil, j.view(false), nil
}

// gcLocked drops finished jobs older than jobTTL.
func (js *jobStore) gcLocked() {
	for id, j := range js.m {
		if !j.finished.IsZero() && time.Since(j.finished) > jobTTL {
			delete(js.m, id)
		}
	}
}
