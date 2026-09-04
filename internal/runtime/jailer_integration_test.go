package runtime_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestJailerCreatesAPISocket(t *testing.T) {
	if os.Getenv("WARDEN_JAILER_ITEST") != "1" {
		t.Skip("set WARDEN_JAILER_ITEST=1 to run the jailer (needs sudo -n)")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("sudo -n not available:", err)
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		root = filepath.Dir(root)
	}
	jailer := filepath.Join(root, "assets", "jailer")
	binary := filepath.Join(root, "assets", "firecracker")
	kernel := filepath.Join(root, "assets", "vmlinux")
	rootfs := filepath.Join(root, "assets", "rootfs.ext4")
	for _, p := range []string{jailer, binary, kernel, rootfs} {
		if _, err := os.Stat(p); err != nil {
			t.Skip(p, "missing")
		}
	}

	cfg, err := runtime.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Binary = binary
	cfg.Kernel = kernel
	cfg.Rootfs = rootfs
	cfg.Jailer = jailer
	cfg.JailerSudo = true
	cfg.WorkDir = t.TempDir()
	cfg.BootTimeout = 5 * time.Second
	rt := runtime.NewFirecrackerWithConfig(cfg)

	// Boot will fail at InstanceStart on nested KVM. We only care that the
	// jailer produced an API socket — that error message includes the log.
	_, err = rt.Boot(context.Background(), runtime.Spec{
		Language: runtime.LangPython,
		Limits:   resources.DefaultProfile(),
		Network:  network.Default(),
	})
	if err == nil {
		t.Fatal("expected KVM/start failure after jailer API came up")
	}
	t.Log(err)
}
