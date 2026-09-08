package network_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/network"
)

func TestDenyAllByDefault(t *testing.T) {
	f, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Allows("example.com:443") {
		t.Fatal("deny-all must reject")
	}
	if f.Allows("") {
		t.Fatal("empty host must reject")
	}
}

func TestAllowlistExactAndHost(t *testing.T) {
	f, err := network.NewStaticFilter(network.Policy{
		DefaultPolicy: network.PolicyDeny,
		Allowlist:     []string{"pypi.org:443", "registry.npmjs.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Allows("pypi.org:443") {
		t.Fatal("expected pypi.org:443 allowed")
	}
	if !f.Allows("registry.npmjs.org:443") {
		t.Fatal("host-only allowlist should match any port")
	}
	if f.Allows("evil.example:443") {
		t.Fatal("unknown host must be denied")
	}
	if f.Allows("pypi.org:80") {
		t.Fatal("pypi.org:443 must not allow port 80")
	}
}

func TestRejectAllowDefault(t *testing.T) {
	_, err := network.NewStaticFilter(network.Policy{DefaultPolicy: network.PolicyAllow})
	if err == nil {
		t.Fatal("allow-by-default must be rejected")
	}
}

func TestLoadRepoEgress(t *testing.T) {
	root := findGoMod(t)
	p, err := network.Load(filepath.Join(root, "configs", "egress.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.DefaultPolicy != network.PolicyDeny {
		t.Fatalf("policy=%s", p.DefaultPolicy)
	}
	if len(p.Allowlist) != 0 {
		t.Fatalf("phase-1 allowlist must be empty, got %v", p.Allowlist)
	}
}

func findGoMod(t *testing.T) string {
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
