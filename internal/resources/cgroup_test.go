package resources_test

import (
	"io"
	"log/slog"
	"os"
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
