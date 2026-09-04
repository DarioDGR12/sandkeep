package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateJailerID(t *testing.T) {
	if err := validateJailerID("fc-1"); err != nil {
		t.Fatal(err)
	}
	if err := validateJailerID("has_underscore"); err == nil {
		t.Fatal("underscore must be rejected")
	}
	if err := validateJailerID(""); err == nil {
		t.Fatal("empty id")
	}
}

func TestJailLayoutAndPrepare(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinux")
	rootfs := filepath.Join(dir, "root.ext4")
	if err := os.WriteFile(kernel, []byte("kern"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("fs"), 0o644); err != nil {
		t.Fatal(err)
	}
	layout, err := newJailLayout(dir, "/opt/firecracker", "fc-9")
	if err != nil {
		t.Fatal(err)
	}
	if layout.Root != filepath.Join(dir, "firecracker", "fc-9", "root") {
		t.Fatalf("root=%s", layout.Root)
	}
	if err := prepareJail(layout, kernel, rootfs, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vmlinux", "rootfs.ext4", "firecracker.log"} {
		if _, err := os.Stat(filepath.Join(layout.Root, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestJailerCommand(t *testing.T) {
	layout, err := newJailLayout("/srv/jailer", "/usr/bin/firecracker", "abc-1")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := jailerCommand(Config{
		Jailer:     "/usr/bin/jailer",
		Binary:     "/usr/bin/firecracker",
		JailerUID:  123,
		JailerGID:  123,
		JailerSudo: true,
		NewPIDNS:   true,
	}, layout, "/var/run/netns/warden-abc-1")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(cmd.Args, " ")
	for _, want := range []string{"sudo", "-n", "/usr/bin/jailer", "--id abc-1", "--uid 123", "--new-pid-ns", "--netns /var/run/netns/warden-abc-1", "--api-sock /api.sock"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}

	plain, err := jailerCommand(Config{
		Jailer:    "/usr/bin/jailer",
		Binary:    "/usr/bin/firecracker",
		JailerUID: 123,
		JailerGID: 123,
	}, layout, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain.Args, " "), "--netns") {
		t.Fatalf("empty netns must not pass --netns: %s", strings.Join(plain.Args, " "))
	}
}

func TestCloneAndLink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("hello-warden"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := cloneFile(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "hello-warden" {
		t.Fatalf("clone: %s %v", got, err)
	}
	link := filepath.Join(dir, "link")
	if err := linkOrCopy(src, link); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(link)
	if err != nil || string(got) != "hello-warden" {
		t.Fatalf("link: %s %v", got, err)
	}
}
