package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuestFenceBlocksMount(t *testing.T) {
	if os.Getenv("WARDEN_FENCE_CHILD") == "1" {
		if err := applyGuestFence(); err != nil {
			t.Fatalf("fence: %v", err)
		}
		err := unix.Mount("none", t.TempDir(), "tmpfs", 0, "")
		if err == nil {
			t.Fatal("mount must be denied after guest fence")
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestGuestFenceBlocksMount")
	cmd.Env = append(os.Environ(), "WARDEN_FENCE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
