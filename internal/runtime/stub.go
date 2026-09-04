package runtime

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// Stub simulates the Firecracker lifecycle without executing guest code.
// Running agent code on the Warden host would defeat the whole product, so
// the stub only records the request and returns a clearly marked placeholder.
type Stub struct {
	seq atomic.Uint64
}

// NewStub returns a process-wide stub runtime.
func NewStub() *Stub {
	return &Stub{}
}

// Name implements Runtime.
func (*Stub) Name() string { return "stub" }

// Boot allocates a fake VM id. Limits and network policy are accepted so the
// real pipeline path is exercised even without KVM.
func (s *Stub) Boot(_ context.Context, spec Spec) (Instance, error) {
	if !Supported(spec.Language) {
		return nil, fmt.Errorf("unsupported runtime %q", spec.Language)
	}
	if err := spec.Limits.Validate(); err != nil {
		return nil, fmt.Errorf("boot stub: %w", err)
	}
	id := fmt.Sprintf("stub-%d", s.seq.Add(1))
	return &stubInstance{id: id, spec: spec}, nil
}

type stubInstance struct {
	id   string
	spec Spec
	dead atomic.Bool
}

func (i *stubInstance) ID() string { return i.id }

func (i *stubInstance) Execute(ctx context.Context, req ExecRequest) (Result, error) {
	if i.dead.Load() {
		return Result{}, fmt.Errorf("vm %s already destroyed", i.id)
	}
	if req.Timeout <= 0 {
		req.Timeout = 30 * time.Second
	}

	select {
	case <-ctx.Done():
		return Result{
			VMID:     i.id,
			Stderr:   ctx.Err().Error(),
			ExitCode: -1,
			TimedOut: true,
		}, nil
	default:
	}

	// Intentionally does not interpret req.Code.
	stdout := fmt.Sprintf(
		"[warden-stub] vm=%s language=%s session=%s bytes=%d timeout=%s\n[warden-stub] guest code was NOT executed; Firecracker is not wired yet\n",
		i.id, i.spec.Language, i.spec.SessionID, len(req.Code), req.Timeout,
	)
	return Result{
		Stdout:   stdout,
		Stderr:   "",
		ExitCode: 0,
		VMID:     i.id,
		TimedOut: false,
	}, nil
}

func (i *stubInstance) Destroy(_ context.Context) error {
	if !i.dead.CompareAndSwap(false, true) {
		return fmt.Errorf("vm %s already destroyed", i.id)
	}
	return nil
}
