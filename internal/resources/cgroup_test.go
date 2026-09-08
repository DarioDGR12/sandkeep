package resources_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/resources"
)

func TestCgroupAttachBestEffort(t *testing.T) {
	c := resources.CgroupV2{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Require: false}
	cleanup, err := c.Attach("test", os.Getpid(), resources.DefaultProfile())
	if err != nil {
		t.Fatalf("best-effort must not fail: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup is nil")
	}
	_ = cleanup()
}

func TestCgroupRequireFailsClosedWhenUndelegated(t *testing.T) {
	c := resources.CgroupV2{Require: true}
	_, err := c.Attach("test", os.Getpid(), resources.DefaultProfile())
	// On a delegated host this might succeed; skip in that case.
	if err == nil {
		t.Skip("cgroup v2 is writable here; cannot assert fail-closed")
	}
}

func TestCgroupV2WritesControllers(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(self, []byte("0::/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := resources.CgroupV2{Root: root, Self: self, Require: true}
	cleanup, err := c.Attach("abc", 4242, resources.DefaultProfile())
	if err != nil {
		t.Fatalf("attach on fake sysfs: %v", err)
	}
	dir := filepath.Join(root, "warden-abc")
	assertFile(t, filepath.Join(dir, "memory.max"), "268435456")
	assertFile(t, filepath.Join(dir, "cpu.max"), "100000 100000")
	assertFile(t, filepath.Join(dir, "pids.max"), "64")
	assertFile(t, filepath.Join(dir, "cgroup.procs"), "4242")
	assertFile(t, filepath.Join(dir, "memory.swap.max"), "0")
	assertFile(t, filepath.Join(dir, "memory.oom.group"), "1")

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the cgroup directory")
	}
}

func TestCgroupRequireFailsOnReadOnlyFakeRoot(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(self, []byte("0::/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	c := resources.CgroupV2{Root: root, Self: self, Require: true}
	if _, err := c.Attach("x", 1, resources.DefaultProfile()); err == nil {
		t.Fatal("Require must fail when the cgroup dir cannot be created")
	}
}

func TestCgroupV2RejectsTinyMemory(t *testing.T) {
	c := resources.CgroupV2{Require: true, Root: t.TempDir(), Self: filepath.Join(t.TempDir(), "missing")}
	p := resources.DefaultProfile()
	p.MemoryBytes = 1024
	if _, err := c.Attach("x", 1, p); err == nil {
		t.Fatal("invalid profile must fail before touching the kernel")
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got := strings.TrimSpace(string(data))
	if got != want {
		t.Fatalf("%s=%q want %q", path, got, want)
	}
}
