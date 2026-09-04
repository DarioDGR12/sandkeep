// Package snapshot is the phase 2 hook for pausing and restoring a microVM
// session instead of booting from scratch on every /execute call.
//
// Phase 1 always boots a fresh VM and ignores session reuse. The interface
// exists so the execute pipeline can start threading session_id through
// without a rewrite later.
package snapshot

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotImplemented is returned by every phase-2 snapshot operation.
var ErrNotImplemented = errors.New("snapshot: phase 2 not implemented")

// Record is a saved VM image tied to an agent session.
type Record struct {
	SessionID string
	VMID      string
	Path      string
}

// Store persists and restores session snapshots.
type Store interface {
	Save(ctx context.Context, sessionID, vmID string) (*Record, error)
	Restore(ctx context.Context, sessionID string) (*Record, error)
	Delete(ctx context.Context, sessionID string) error
}

// Unsupported is a placeholder Store. It keeps session_id visible in logs
// but refuses to snapshot anything.
type Unsupported struct{}

// Save implements Store.
func (Unsupported) Save(_ context.Context, sessionID, _ string) (*Record, error) {
	return nil, fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}

// Restore implements Store.
func (Unsupported) Restore(_ context.Context, sessionID string) (*Record, error) {
	return nil, fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}

// Delete implements Store.
func (Unsupported) Delete(_ context.Context, sessionID string) error {
	return fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}
