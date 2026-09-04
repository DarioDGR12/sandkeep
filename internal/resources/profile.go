// Package resources holds host-side isolation profiles: cgroups (CPU, RAM,
// PIDs, disk) and a seccomp syscall allowlist.
//
// These limits are meant to wrap the Firecracker/jailer process on the host.
// They do not replace the microVM boundary — they are a second layer so a
// runaway or compromised guest cannot starve the host.
package resources

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	DefaultCPUQuotaUs  = 100_000 // 100ms / 100ms period = 1 CPU
	DefaultCPUPeriodUs = 100_000
	DefaultMemoryBytes = 256 << 20 // 256 MiB
	DefaultPIDsMax     = 64
	DefaultDiskBytes   = 1 << 30 // 1 GiB
)

// Profile is the cgroup budget for one sandbox instance.
type Profile struct {
	CPUQuotaUs  int64 `json:"cpu_quota_us"`
	CPUPeriodUs int64 `json:"cpu_period_us"`
	MemoryBytes int64 `json:"memory_bytes"`
	PIDsMax     int64 `json:"pids_max"`
	DiskBytes   int64 `json:"disk_bytes"`
}

// SeccompProfile is a Docker/libseccomp-style filter. Phase 1 only loads and
// validates it; the Firecracker runtime will pass it to the jailer later.
type SeccompProfile struct {
	DefaultAction string           `json:"default_action"`
	Architectures []string         `json:"architectures"`
	Syscalls      []SeccompSyscall `json:"syscalls"`
}

// SeccompSyscall is one allow/deny rule inside a seccomp profile.
type SeccompSyscall struct {
	Action string   `json:"action"`
	Names  []string `json:"names"`
}

// DefaultProfile returns the built-in conservative limits used when no config
// file is present.
func DefaultProfile() Profile {
	return Profile{
		CPUQuotaUs:  DefaultCPUQuotaUs,
		CPUPeriodUs: DefaultCPUPeriodUs,
		MemoryBytes: DefaultMemoryBytes,
		PIDsMax:     DefaultPIDsMax,
		DiskBytes:   DefaultDiskBytes,
	}
}

// Validate checks that a profile can actually constrain a process.
func (p Profile) Validate() error {
	if p.CPUQuotaUs <= 0 || p.CPUPeriodUs <= 0 {
		return fmt.Errorf("cpu quota and period must be > 0")
	}
	if p.MemoryBytes < 16<<20 {
		return fmt.Errorf("memory_bytes must be at least 16MiB")
	}
	if p.PIDsMax < 1 {
		return fmt.Errorf("pids_max must be at least 1")
	}
	if p.DiskBytes < 1<<20 {
		return fmt.Errorf("disk_bytes must be at least 1MiB")
	}
	return nil
}

// LoadProfile reads a cgroups JSON file. Extra fields (like "comment") are ignored.
func LoadProfile(path string) (Profile, error) {
	p := DefaultProfile()
	if err := decodeJSONFile(path, &p); err != nil {
		return Profile{}, err
	}
	if err := p.Validate(); err != nil {
		return Profile{}, fmt.Errorf("invalid cgroups profile %s: %w", path, err)
	}
	return p, nil
}

// LoadSeccomp reads a seccomp JSON file and requires a fail-closed default action.
func LoadSeccomp(path string) (SeccompProfile, error) {
	var s SeccompProfile
	if err := decodeJSONFile(path, &s); err != nil {
		return SeccompProfile{}, err
	}
	if s.DefaultAction == "" {
		return SeccompProfile{}, fmt.Errorf("seccomp profile %s: default_action is required", path)
	}
	if s.DefaultAction != "SCMP_ACT_ERRNO" && s.DefaultAction != "SCMP_ACT_KILL" && s.DefaultAction != "SCMP_ACT_KILL_PROCESS" {
		return SeccompProfile{}, fmt.Errorf("seccomp profile %s: default_action %q is not fail-closed", path, s.DefaultAction)
	}
	if len(s.Syscalls) == 0 {
		return SeccompProfile{}, fmt.Errorf("seccomp profile %s: at least one syscall rule is required", path)
	}
	return s, nil
}

func decodeJSONFile(path string, dest any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
