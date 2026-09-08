package main

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuestFenceBlocksMount(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("guest denylist is amd64-only")
	}
	if os.Getenv("WARDEN_FENCE_CHILD") == "1" {
		if err := applyGuestFence(); err != nil {
			t.Fatalf("fence: %v", err)
		}
		if err := unix.Mount("none", t.TempDir(), "tmpfs", 0, ""); err == nil {
			t.Fatal("mount must be denied after guest fence")
		}
		if err := unix.Unshare(unix.CLONE_NEWNET); err == nil {
			t.Fatal("unshare must be denied after guest fence")
		}
		if err := unix.Chroot("/"); err == nil {
			t.Fatal("chroot must be denied after guest fence")
		}
		if _, err := unix.OpenTree(unix.AT_FDCWD, "/", 0); err == nil {
			t.Fatal("open_tree must be denied after guest fence")
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
