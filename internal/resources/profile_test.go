package resources_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/resources"
)

func TestDefaultProfileValid(t *testing.T) {
	if err := resources.DefaultProfile().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRepoConfigs(t *testing.T) {
	root := repoRoot(t)
	p, err := resources.LoadProfile(filepath.Join(root, "configs", "cgroups.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryBytes < 16<<20 {
		t.Fatalf("memory=%d", p.MemoryBytes)
	}
	s, err := resources.LoadSeccomp(filepath.Join(root, "configs", "seccomp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("action=%s", s.DefaultAction)
	}
}

func TestSeccompValidateRequiresRules(t *testing.T) {
	s := resources.SeccompProfile{DefaultAction: "SCMP_ACT_ERRNO"}
	if err := s.Validate(); err == nil {
		t.Fatal("empty syscall list must fail")
	}
}

func TestRejectOpenSeccomp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seccomp.json")
	if err := os.WriteFile(path, []byte(`{"default_action":"SCMP_ACT_ALLOW","syscalls":[{"action":"SCMP_ACT_ALLOW","names":["read"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resources.LoadSeccomp(path); err == nil {
		t.Fatal("open-by-default seccomp must be rejected")
	}
}

func TestInvalidMemory(t *testing.T) {
	p := resources.DefaultProfile()
	p.MemoryBytes = 1024
	if err := p.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		wd = filepath.Dir(wd)
	}
	t.Fatal("go.mod not found")
	return ""
}
