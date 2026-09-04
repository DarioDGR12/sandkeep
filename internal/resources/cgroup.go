package resources

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupAttacher applies a Profile to a live process via cgroup v2.
type CgroupAttacher interface {
	Attach(id string, pid int, profile Profile) (cleanup func() error, err error)
}

// CgroupV2 writes cpu/memory/pids limits under the current process cgroup
// when the kernel lets us create a child. In many containers this is not
// delegated; Attach then returns a no-op cleanup and a warning error that
// the caller may ignore unless Require is set.
type CgroupV2 struct {
	Log     *slog.Logger
	Require bool
	Root    string // default /sys/fs/cgroup
}

// Attach creates warden-<id> under the current cgroup and moves pid into it.
func (c CgroupV2) Attach(id string, pid int, profile Profile) (func() error, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	root := c.Root
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	parent, err := currentCgroupDir(root)
	if err != nil {
		return c.missing("resolve current cgroup", err)
	}
	dir := filepath.Join(parent, "warden-"+sanitizeID(id))
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return c.missing("create "+dir, err)
	}
	cleanup := func() error {
		// Move leftover tasks out so the directory can be removed.
		_ = os.WriteFile(filepath.Join(parent, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
		return os.Remove(dir)
	}

	if err := writeCgroup(dir, "memory.max", strconv.FormatInt(profile.MemoryBytes, 10)); err != nil {
		_ = cleanup()
		return c.missing("memory.max", err)
	}
	cpuMax := fmt.Sprintf("%d %d", profile.CPUQuotaUs, profile.CPUPeriodUs)
	if err := writeCgroup(dir, "cpu.max", cpuMax); err != nil {
		_ = cleanup()
		return c.missing("cpu.max", err)
	}
	if err := writeCgroup(dir, "pids.max", strconv.FormatInt(profile.PIDsMax, 10)); err != nil {
		_ = cleanup()
		return c.missing("pids.max", err)
	}
	if err := writeCgroup(dir, "cgroup.procs", strconv.Itoa(pid)); err != nil {
		_ = cleanup()
		return c.missing("cgroup.procs", err)
	}
	if c.Log != nil {
		c.Log.Info("cgroup attached", "id", id, "pid", pid, "dir", dir, "memory_bytes", profile.MemoryBytes)
	}
	return cleanup, nil
}

func (c CgroupV2) missing(what string, err error) (func() error, error) {
	wrapped := fmt.Errorf("cgroup v2 %s: %w", what, err)
	if c.Require {
		return nil, wrapped
	}
	if c.Log != nil {
		c.Log.Warn("cgroup attach skipped", "err", wrapped)
	}
	return func() error { return nil }, nil
}

func writeCgroup(dir, file, value string) error {
	return os.WriteFile(filepath.Join(dir, file), []byte(value+"\n"), 0o644)
}

func currentCgroupDir(root string) (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		// v2: 0::/system.slice/foo
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "" || parts[0] == "0" {
			rel := parts[2]
			if rel == "/" {
				return root, nil
			}
			return filepath.Join(root, rel), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 line in /proc/self/cgroup")
}

func sanitizeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "vm"
	}
	return b.String()
}
