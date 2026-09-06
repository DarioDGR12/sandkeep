package runtime_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestConfigValidateMissing(t *testing.T) {
	cfg := runtime.Config{}
	if err := cfg.Validate(); !errors.Is(err, runtime.ErrMissingAssets) {
		t.Fatalf("got %v", err)
	}
}

func TestConfigValidateOK(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fc")
	kern := filepath.Join(dir, "vmlinux")
	root := filepath.Join(dir, "root.ext4")
	for _, p := range []string{bin, kern, root} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := runtime.Config{Binary: bin, Kernel: kern, Rootfs: root}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBootRejectsAllowlist(t *testing.T) {
	dir := t.TempDir()
	touch := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rt := runtime.NewFirecrackerWithConfig(runtime.Config{
		Binary:  touch("fc"),
		Kernel:  touch("vmlinux"),
		Rootfs:  touch("root.ext4"),
		WorkDir: dir,
	})
	_, err := rt.Boot(context.Background(), runtime.Spec{
		Language: runtime.LangPython,
		Limits:   resources.DefaultProfile(),
		Network:  network.Policy{DefaultPolicy: network.PolicyDeny, Allowlist: []string{"pypi.org"}},
	})
	if err == nil {
		t.Fatal("expected allowlist error")
	}
	if !strings.Contains(err.Error(), "TAP factory") {
		t.Fatalf("must refuse silent no-NIC boot: %v", err)
	}
}

func TestLoadConfigEnvOverlay(t *testing.T) {
	t.Setenv("WARDEN_FC_BINARY", "/opt/fc")
	t.Setenv("WARDEN_SNAPSHOT_DIR", "/var/lib/warden/snaps")
	t.Setenv("WARDEN_ROOTFS_POOL", "4")
	cfg, err := runtime.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Binary != "/opt/fc" {
		t.Fatalf("binary=%s", cfg.Binary)
	}
	if cfg.SnapshotDir != "/var/lib/warden/snaps" {
		t.Fatalf("snapshot_dir=%s", cfg.SnapshotDir)
	}
	if cfg.RootfsPoolSize != 4 {
		t.Fatalf("pool=%d", cfg.RootfsPoolSize)
	}
}

func TestBootRejectsOversizedRootfs(t *testing.T) {
	dir := t.TempDir()
	touch := func(name string, n int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	limits := resources.DefaultProfile()
	limits.DiskBytes = 1 << 20
	rt := runtime.NewFirecrackerWithConfig(runtime.Config{
		Binary:  touch("fc", 8),
		Kernel:  touch("vmlinux", 8),
		Rootfs:  touch("root.ext4", (1<<20)+64),
		WorkDir: dir,
	})
	_, err := rt.Boot(context.Background(), runtime.Spec{
		Language: runtime.LangPython,
		Limits:   limits,
		Network:  network.Default(),
	})
	if err == nil || !strings.Contains(err.Error(), "disk limit") {
		t.Fatalf("want disk limit error, got %v", err)
	}
}

func TestLoadConfigSnapshotDirOff(t *testing.T) {
	t.Setenv("WARDEN_SNAPSHOT_DIR", "off")
	cfg, err := runtime.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SnapshotDir != "" {
		t.Fatalf("off must disable snapshots, got %q", cfg.SnapshotDir)
	}
}
