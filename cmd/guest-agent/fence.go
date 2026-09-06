package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applyGuestFence sets no_new_privs and a seccomp denylist of syscalls that
// a guest job should never need (mount, ptrace, kexec, …). This is not a
// full allowlist — python/node need a wide syscall set — and it is never
// applied to the Firecracker VMM.
func applyGuestFence() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if err := loadDenyFilter(); err != nil {
		return fmt.Errorf("seccomp denylist: %w", err)
	}
	return nil
}

func loadDenyFilter() error {
	if runtime.GOARCH != "amd64" {
		return nil
	}
	denied := []uint32{
		uint32(unix.SYS_MOUNT),
		uint32(unix.SYS_UMOUNT2),
		uint32(unix.SYS_PIVOT_ROOT),
		uint32(unix.SYS_INIT_MODULE),
		uint32(unix.SYS_FINIT_MODULE),
		uint32(unix.SYS_DELETE_MODULE),
		uint32(unix.SYS_KEXEC_LOAD),
		uint32(unix.SYS_REBOOT),
		uint32(unix.SYS_SWAPON),
		uint32(unix.SYS_SWAPOFF),
		uint32(unix.SYS_SETHOSTNAME),
		uint32(unix.SYS_SETDOMAINNAME),
		uint32(unix.SYS_BPF),
		uint32(unix.SYS_PTRACE),
		uint32(unix.SYS_PROCESS_VM_READV),
		uint32(unix.SYS_PROCESS_VM_WRITEV),
		uint32(unix.SYS_PERF_EVENT_OPEN),
		uint32(unix.SYS_USERFAULTFD),
		uint32(unix.SYS_SYSLOG),
	}

	const (
		auditArchX86_64 = 0xC000003E
		seccompRetAllow = 0x7fff0000
		seccompRetErrno = 0x00050000
	)
	eperm := uint32(seccompRetErrno | uint32(unix.EPERM))

	var ins []unix.SockFilter
	// ld [4] → arch
	ins = append(ins, bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4))
	ins = append(ins, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, auditArchX86_64, 1, 0))
	ins = append(ins, bpfStmt(unix.BPF_RET|unix.BPF_K, uint32(unix.SECCOMP_RET_KILL_PROCESS)))
	// ld [0] → nr
	ins = append(ins, bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0))
	for _, nr := range denied {
		ins = append(ins, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, 1))
		ins = append(ins, bpfStmt(unix.BPF_RET|unix.BPF_K, eperm))
	}
	ins = append(ins, bpfStmt(unix.BPF_RET|unix.BPF_K, seccompRetAllow))

	prog := unix.SockFprog{
		Len:    uint16(len(ins)),
		Filter: &ins[0],
	}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return errno
	}
	return nil
}

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
