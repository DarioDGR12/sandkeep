package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCloneFileRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")
	if err := cloneFile(dir, dst); err == nil {
		t.Fatal("cloning a directory must fail")
	}
}

func TestCloneFileCopiesRegular(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := filepath.Join(t.TempDir(), "dst")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cloneFile(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}
