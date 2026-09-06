package resources

import (
	"fmt"
	"log/slog"
)

// Limiter validates host-side isolation profiles before Boot.
// Attaching a cgroup requires a live VMM PID and happens in Firecracker.Boot
// via CgroupAttacher — Apply must not pretend it already jailed a process.
type Limiter interface {
	Apply(target string, profile Profile, seccomp SeccompProfile) error
}

// ProfileLimiter fail-closes on an invalid cgroup or seccomp profile.
// It does not write to the kernel; that is CgroupV2.Attach after spawn.
type ProfileLimiter struct {
	Log *slog.Logger
}

// Apply validates the profiles that Boot will enforce.
func (p ProfileLimiter) Apply(target string, profile Profile, seccomp SeccompProfile) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("apply limits to %s: %w", target, err)
	}
	if err := seccomp.Validate(); err != nil {
		return fmt.Errorf("apply seccomp for %s: %w", target, err)
	}
	if p.Log != nil {
		p.Log.Info("resource profiles validated; cgroup attach waits for VMM pid",
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

// NoopLimiter validates the cgroup profile only. Prefer ProfileLimiter in
// production so an open seccomp file cannot pass Apply.
type NoopLimiter struct {
	Log *slog.Logger
}

// Apply records the isolation intent without attaching a cgroup.
func (n NoopLimiter) Apply(target string, profile Profile, seccomp SeccompProfile) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("apply limits to %s: %w", target, err)
	}
	if n.Log != nil {
		n.Log.Info("resource limits staged (profile only)",
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
