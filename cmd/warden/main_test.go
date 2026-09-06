package main

import (
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/api"
)

func TestCgroupRequiredDefault(t *testing.T) {
	t.Setenv("WARDEN_CGROUP_REQUIRED", "")
	if !cgroupRequired("0.0.0.0:8080") {
		t.Fatal("public bind must require cgroups by default")
	}
	if cgroupRequired("127.0.0.1:8080") {
		t.Fatal("loopback must stay best-effort unless forced")
	}
	t.Setenv("WARDEN_CGROUP_REQUIRED", "0")
	if cgroupRequired("0.0.0.0:8080") {
		t.Fatal("explicit 0 disables require")
	}
	t.Setenv("WARDEN_CGROUP_REQUIRED", "1")
	if !cgroupRequired("127.0.0.1:8080") {
		t.Fatal("explicit 1 enables require")
	}
}

func TestListenAddr(t *testing.T) {
	t.Setenv("WARDEN_ADDR", "")
	t.Setenv("PORT", "")
	if listenAddr() != "127.0.0.1:8080" {
		t.Fatalf("local default=%s", listenAddr())
	}
	t.Setenv("PORT", "9999")
	if listenAddr() != "0.0.0.0:9999" {
		t.Fatalf("PORT bind=%s", listenAddr())
	}
}

func TestIsLoopbackExported(t *testing.T) {
	if !api.IsLoopbackAddr("127.0.0.1:1") {
		t.Fatal("loopback")
	}
}
