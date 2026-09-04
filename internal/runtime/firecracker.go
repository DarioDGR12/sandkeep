package runtime

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotImplemented is returned until the jailer + Firecracker API client lands.
var ErrNotImplemented = errors.New("firecracker runtime is not implemented yet")

// Firecracker is the real isolation backend. Phase 1 only defines the type
// and the Boot/Execute/Destroy shape so the next session can fill this file
// in without changing the API layer.
//
// Planned host-side flow (do not implement here yet):
//  1. Allocate a jailer chroot, tap device, and vsock.
//  2. Apply cgroups + seccomp to the jailer process (internal/resources).
//  3. Attach egress iptables/nft rules from internal/network.
//  4. Start Firecracker, boot the rootfs, wait for the guest agent.
//  5. Send code over vsock, collect stdout/stderr/exit.
//  6. SIGTERM the VM, release tap/cgroup, always Destroy on the way out.
type Firecracker struct{}

// NewFirecracker returns the placeholder backend.
func NewFirecracker() *Firecracker {
	return &Firecracker{}
}

// Name implements Runtime.
func (*Firecracker) Name() string { return "firecracker" }

// Boot is the integration point for launching a microVM.
func (f *Firecracker) Boot(_ context.Context, spec Spec) (Instance, error) {
	if !Supported(spec.Language) {
		return nil, fmt.Errorf("unsupported runtime %q", spec.Language)
	}
	return nil, fmt.Errorf("%w: boot language=%s session=%s", ErrNotImplemented, spec.Language, spec.SessionID)
}

type firecrackerInstance struct {
	id string
}

func (i *firecrackerInstance) ID() string { return i.id }

func (i *firecrackerInstance) Execute(_ context.Context, _ ExecRequest) (Result, error) {
	return Result{}, fmt.Errorf("%w: execute vm=%s", ErrNotImplemented, i.id)
}

func (i *firecrackerInstance) Destroy(_ context.Context) error {
	return fmt.Errorf("%w: destroy vm=%s", ErrNotImplemented, i.id)
}
