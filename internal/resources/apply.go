package resources

import (
	"fmt"
	"log/slog"
)

// Limiter is the host-side hook that will attach cgroups and a seccomp filter
// to a Firecracker jailer process. Phase 1 only records the intent.
type Limiter interface {
	Apply(target string, profile Profile, seccomp SeccompProfile) error
}

// NoopLimiter logs the limits that will be applied once jailer integration lands.
type NoopLimiter struct {
	Log *slog.Logger
}

// Apply records the isolation intent without touching the kernel.
func (n NoopLimiter) Apply(target string, profile Profile, seccomp SeccompProfile) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("apply limits to %s: %w", target, err)
	}
	if n.Log != nil {
		n.Log.Info("resource limits staged (noop)",
			"target", target,
			"cpu_quota_us", profile.CPUQuotaUs,
			"memory_bytes", profile.MemoryBytes,
			"pids_max", profile.PIDsMax,
			"seccomp_default", seccomp.DefaultAction,
			"seccomp_rules", len(seccomp.Syscalls),
		)
	}
	return nil
}
