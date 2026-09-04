// Package runtime is the isolation boundary: boot a microVM, run guest code,
// tear the VM down. The HTTP API never talks to Firecracker directly — it
// talks to this interface so we can swap Stub → Firecracker without rewriting
// handlers.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
)

// ErrNotImplemented is kept for leftover fail-closed hooks.
var ErrNotImplemented = errors.New("firecracker feature is not implemented yet")

// Supported guest language runtimes for phase 1.
const (
	LangPython = "python"
	LangNode   = "node"
)

// Spec describes one disposable microVM.
type Spec struct {
	Language  string
	SessionID string
	Limits    resources.Profile
	Seccomp   resources.SeccompProfile
	Network   network.Policy
}

// ExecRequest is the guest payload.
type ExecRequest struct {
	Code    string
	Timeout time.Duration
}

// Result is what /execute returns to the agent.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	VMID     string
	TimedOut bool
}

// Instance is a booted (or stubbed) microVM.
type Instance interface {
	ID() string
	Execute(ctx context.Context, req ExecRequest) (Result, error)
	Destroy(ctx context.Context) error
}

// Runtime boots disposable instances. A session_id plus a snapshot.Store
// can restore a previous microVM; otherwise each request gets a new VM.
type Runtime interface {
	Boot(ctx context.Context, spec Spec) (Instance, error)
	Name() string
}

// Supported reports whether language is in the phase-1 allowlist.
func Supported(language string) bool {
	switch language {
	case LangPython, LangNode:
		return true
	default:
		return false
	}
}

// New selects an implementation. "stub" is the default until Firecracker
// wiring lands. "firecracker" returns a typed placeholder that fails closed.
func New(kind string) (Runtime, error) {
	switch kind {
	case "", "stub":
		return NewStub(), nil
	case "firecracker":
		cfgPath := os.Getenv("WARDEN_FC_CONFIG")
		if cfgPath == "" {
			cfgPath = "configs/firecracker.json"
		}
		cfg, err := LoadConfig(cfgPath)
		if err != nil {
			return nil, err
		}
		return NewFirecrackerWithConfig(cfg), nil
	default:
		return nil, fmt.Errorf("unknown runtime %q (want stub or firecracker)", kind)
	}
}
