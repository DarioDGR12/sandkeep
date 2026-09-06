package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestFirecrackerRealVM(t *testing.T) {
	if os.Getenv("WARDEN_ITEST") != "1" {
		t.Skip("set WARDEN_ITEST=1 to boot a real microVM")
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
	cfg, err := runtime.LoadConfig(filepath.Join(root, "configs", "firecracker.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Binary = filepath.Join(root, cfg.Binary)
	cfg.Kernel = filepath.Join(root, cfg.Kernel)
	cfg.Rootfs = filepath.Join(root, cfg.Rootfs)
	cfg.WorkDir = t.TempDir()
	cfg.BootTimeout = 30 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Skip(err)
	}
	if _, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skip("no /dev/kvm access:", err)
	}

	rt := runtime.NewFirecrackerWithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	inst, err := rt.Boot(ctx, runtime.Spec{
		Language: runtime.LangPython,
		Limits:   resources.DefaultProfile(),
		Network:  network.Default(),
	})
	if err != nil {
		if strings.Contains(err.Error(), "KVM") {
			t.Skip("host KVM cannot create a vCPU (typical nested virt): ", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = inst.Destroy(context.Background())
	})

	res, err := inst.Execute(ctx, runtime.ExecRequest{Code: "print(1+1)", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.TimedOut {
		t.Fatalf("timed out: %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q stdout=%q", res.ExitCode, res.Stderr, res.Stdout)
	}
	if !strings.Contains(res.Stdout, "2") {
		t.Fatalf("expected python result 2, got %q", res.Stdout)
	}
}
