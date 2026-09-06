package resources_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/resources"
)

func TestProfileLimiterRejectsOpenSeccomp(t *testing.T) {
	lim := resources.ProfileLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	open := resources.SeccompProfile{
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
	}
	if err := lim.Apply("vm", resources.DefaultProfile(), open); err == nil {
		t.Fatal("open-by-default seccomp must fail Apply")
	}
}

func TestProfileLimiterRejectsInvalidMemory(t *testing.T) {
	lim := resources.ProfileLimiter{}
	p := resources.DefaultProfile()
	p.MemoryBytes = 1024
	sec := resources.SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
	}
	if err := lim.Apply("vm", p, sec); err == nil {
		t.Fatal("tiny memory must fail Apply")
	}
}

func TestProfileLimiterAcceptsRepoShape(t *testing.T) {
	lim := resources.ProfileLimiter{}
	sec := resources.SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
	}
	if err := lim.Apply("pending-vm", resources.DefaultProfile(), sec); err != nil {
		t.Fatal(err)
	}
}
