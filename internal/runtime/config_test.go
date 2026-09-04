package runtime_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
}

func TestLoadConfigEnvOverlay(t *testing.T) {
	t.Setenv("WARDEN_FC_BINARY", "/opt/fc")
	t.Setenv("WARDEN_SNAPSHOT_DIR", "/var/lib/warden/snaps")
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
}
