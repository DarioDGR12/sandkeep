package runtime_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestFilePoolAcquireAndMiss(t *testing.T) {
	dir := t.TempDir()
	golden := filepath.Join(dir, "golden.ext4")
	if err := os.WriteFile(golden, []byte("clean-rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := runtime.NewFilePool(golden, filepath.Join(dir, "pool"), 1)
	if p == nil {
		t.Fatal("pool")
	}
	deadline := time.Now().Add(2 * time.Second)
	for p.Available() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Available() == 0 {
		t.Fatal("warmup never produced a clone")
	}

	dst := filepath.Join(dir, "vm", "rootfs.ext4")
	if err := p.Acquire(dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "clean-rootfs" {
		t.Fatalf("acquired %q %v", got, err)
	}

	miss := filepath.Join(dir, "vm2", "rootfs.ext4")
	if err := p.Acquire(miss); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(miss)
	if err != nil || string(got) != "clean-rootfs" {
		t.Fatalf("miss clone %q %v", got, err)
	}
}

func TestNewFilePoolDisabled(t *testing.T) {
	if p := runtime.NewFilePool("/x", "/y", 0); p != nil {
		t.Fatal("size 0 must disable the pool")
	}
}
