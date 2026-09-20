// Package runtime runs WASI command-style WASM modules under the
// deterministic-v1 profile: no filesystem, no network, fixed clock,
// zeroed randomness, single-threaded, capped memory/time/output.
package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const (
	// Engine identifies the pinned runtime in receipts.
	Engine = "wazero-1.12.0"
	// ProfileDeterministicV1 is the only supported execution profile.
	ProfileDeterministicV1 = "deterministic-v1"

	wasmPageBytes  = 65536
	maxOutputBytes = 8 << 20
)

// Limits bound a single execution. Zero values are rejected by the caller.
type Limits struct {
	MemoryMB  uint32
	TimeoutMS uint32
}

// Result is the outcome of an execution attempt.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode uint32
	Duration time.Duration
}

// compilationCache is shared by every execution, so a module is compiled once
// per process rather than on every call. It only stores compiled machine code;
// each Run still gets its own runtime, memory and clock, so isolation and
// determinism are unaffected.
var compilationCache = wazero.NewCompilationCache()

// ErrLimit is returned (wrapped) when a resource limit was hit.
var ErrLimit = errors.New("resource limit exceeded")

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		return 0, fmt.Errorf("%w: output exceeds %d bytes", ErrLimit, c.max)
	}
	return c.buf.Write(p)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// Run executes wasm with the given stdin and argv (excluding argv[0]).
// It fails closed: any trap, limit violation or non-zero exit is an error
// alongside a populated Result where available.
func Run(ctx context.Context, wasm, stdin []byte, args []string, lim Limits) (*Result, error) {
	if lim.MemoryMB == 0 || lim.TimeoutMS == 0 {
		return nil, errors.New("limits must be non-zero")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(lim.TimeoutMS)*time.Millisecond)
	defer cancel()

	pages := lim.MemoryMB * (1 << 20) / wasmPageBytes
	if pages > 65536 {
		pages = 65536
	}
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCompilationCache(compilationCache).
		WithMemoryLimitPages(pages).
		WithCloseOnContextDone(true))
	defer rt.Close(context.Background())
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	stdout := &cappedBuffer{max: maxOutputBytes}
	stderr := &cappedBuffer{max: 64 << 10}
	// No WithFS, no WithSysWalltime/Nanotime/Nanosleep: the clock is fixed and
	// there is no filesystem or socket capability. Randomness is zeroed.
	cfg := wazero.NewModuleConfig().
		WithName("workload").
		WithArgs(append([]string{"workload"}, args...)...).
		WithStdin(bytes.NewReader(stdin)).
		WithStdout(stdout).
		WithStderr(stderr).
		WithRandSource(zeroReader{}).
		WithStartFunctions("_start")

	start := time.Now()
	mod, err := rt.InstantiateModule(ctx, compiled, cfg)
	res := &Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Duration: time.Since(start)}
	if mod != nil {
		_ = mod.Close(ctx)
	}
	if err == nil {
		return res, nil
	}
	var exit *sys.ExitError
	if errors.As(err, &exit) {
		res.ExitCode = exit.ExitCode()
		if exit.ExitCode() == 0 {
			return res, nil
		}
		// wazero reports context cancellation as a sys exit code.
		if ctx.Err() != nil {
			return res, ctxError(ctx, lim)
		}
		return res, fmt.Errorf("workload exited with code %d", exit.ExitCode())
	}
	if ctx.Err() != nil {
		return res, ctxError(ctx, lim)
	}
	if errors.Is(err, ErrLimit) {
		return res, err
	}
	return res, fmt.Errorf("execution failed: %w", err)
}

// ctxError maps a finished context to either a resource-limit error (deadline)
// or a plain cancellation requested by the caller.
func ctxError(ctx context.Context, lim Limits) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: timeout after %dms", ErrLimit, lim.TimeoutMS)
	}
	return fmt.Errorf("cancelled: %w", context.Canceled)
}
