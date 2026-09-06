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
	Self    string // default /proc/self/cgroup; override in tests
}

// Attach creates warden-<id> under the current cgroup and moves pid (plus
// descendants, so sudo+jailer children are included) into it.
func (c CgroupV2) Attach(id string, pid int, profile Profile) (func() error, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	root := c.Root
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	parent, err := currentCgroupDir(root, c.Self)
	if err != nil {
		return c.missing("resolve current cgroup", err)
	}
	dir := filepath.Join(parent, "warden-"+sanitizeID(id))
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return c.missing("create "+dir, err)
	}
	cleanup := func() error {
		for _, p := range append([]int{pid}, descendantPIDs(pid)...) {
			_ = os.WriteFile(filepath.Join(parent, "cgroup.procs"), []byte(strconv.Itoa(p)), 0o644)
		}
		if err := os.Remove(dir); err == nil {
			return nil
		}
		// Real cgroupfs rmdirs once tasks are gone. A fake sysfs in tests
		// still has the controller files we wrote, so fall back to RemoveAll.
		return os.RemoveAll(dir)
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
	// Optional controllers: missing files must not undo memory/cpu/pids.
	_ = writeCgroup(dir, "memory.swap.max", "0")
	_ = writeCgroup(dir, "memory.oom.group", "1")

	pids := append([]int{pid}, descendantPIDs(pid)...)
	if err := moveProcs(dir, pids); err != nil {
		_ = cleanup()
		return c.missing("cgroup.procs", err)
	}
	if c.Log != nil {
		c.Log.Info("cgroup attached", "id", id, "pid", pid, "dir", dir, "memory_bytes", profile.MemoryBytes, "moved", len(pids))
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

func moveProcs(dir string, pids []int) error {
	if len(pids) == 0 {
		return fmt.Errorf("no processes to move")
	}
	// The root VMM/jailer pid must move. Descendants are best-effort.
	if err := writeCgroup(dir, "cgroup.procs", strconv.Itoa(pids[0])); err != nil {
		return err
	}
	for _, pid := range pids[1:] {
		_ = writeCgroup(dir, "cgroup.procs", strconv.Itoa(pid))
	}
	return nil
}

func currentCgroupDir(root, self string) (string, error) {
	if self == "" {
		self = "/proc/self/cgroup"
	}
	data, err := os.ReadFile(self)
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
	return "", fmt.Errorf("no cgroup v2 line in %s", self)
}

func descendantPIDs(rootPID int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	ppid := make(map[int]int, 64)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		parent, err := procPPid(pid)
		if err != nil {
			continue
		}
		ppid[pid] = parent
	}
	seen := map[int]bool{rootPID: true}
	var out []int
	changed := true
	for changed {
		changed = false
		for pid, parent := range ppid {
			if seen[pid] || !seen[parent] {
				continue
			}
			seen[pid] = true
			out = append(out, pid)
			changed = true
		}
	}
	return out
}

func procPPid(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// comm can contain spaces and parentheses: 123 (comm here) S ppid ...
	s := string(data)
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+1 >= len(s) {
		return 0, fmt.Errorf("parse /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[rparen+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("parse /proc/%d/stat fields", pid)
	}
	return strconv.Atoi(fields[1])
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
