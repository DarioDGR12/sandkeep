package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
)

func TestExecutePythonOnHostAgent(t *testing.T) {
	ln, err := listen("tcp:127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := guestproto.WriteRequest(conn, guestproto.Request{
		Code: "print(1+1)", Runtime: "python", TimeoutS: 5,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := guestproto.ReadResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if resp.TimedOut {
		t.Fatalf("timed out: %+v", resp)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", resp.ExitCode, resp.Stderr)
	}
	if resp.Stdout != "2\n" && resp.Stdout != "2\r\n" {
		t.Fatalf("stdout=%q (guest-agent test is allowed to exec on the host; production runtime must not)", resp.Stdout)
	}
}

func TestExecuteUnknownRuntime(t *testing.T) {
	resp := execute(guestproto.Request{Code: "x", Runtime: "ruby", TimeoutS: 1})
	if resp.ExitCode != 127 {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestGuestBusyOnSecondJob(t *testing.T) {
	ln, err := listen("tcp:127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()

	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	slow := dial()
	t.Cleanup(func() { _ = slow.Close() })
	marker := "/tmp/warden-busy-" + t.Name()
	_ = os.Remove(marker)
	t.Cleanup(func() { _ = os.Remove(marker) })
	if err := guestproto.WriteRequest(slow, guestproto.Request{
		Code:     "open(" + strconv.Quote(marker) + ",'w').write('1'); import time; time.sleep(0.8)",
		Runtime:  "python",
		TimeoutS: 5,
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first job never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fast := dial()
	defer fast.Close()
	if err := guestproto.WriteRequest(fast, guestproto.Request{
		Code: "print(1)", Runtime: "python", TimeoutS: 2,
	}); err != nil {
		t.Fatal(err)
	}
	_ = fast.SetDeadline(time.Now().Add(2 * time.Second))
	resp, err := guestproto.ReadResponse(fast)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExitCode != 1 || !strings.Contains(resp.Stderr, "busy") {
		t.Fatalf("second job must be busy: %+v", resp)
	}
	_ = slow.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := guestproto.ReadResponse(slow); err != nil {
		t.Fatalf("drain first job: %v", err)
	}
}

func TestExecuteRejectsHugeCode(t *testing.T) {
	resp := execute(guestproto.Request{
		Code:     strings.Repeat("x", guestproto.MaxCodeBytes+1),
		Runtime:  "python",
		TimeoutS: 1,
	})
	if resp.ExitCode != 127 || !strings.Contains(resp.Stderr, "too large") {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestExecuteHonorsMemoryRlimit(t *testing.T) {
	resp := execute(guestproto.Request{
		Code:        "x = bytearray(80 * 1024 * 1024)",
		Runtime:     "python",
		TimeoutS:    5,
		MemoryBytes: 32 << 20,
	})
	if resp.ExitCode == 0 && !resp.TimedOut {
		t.Fatalf("allocation above RLIMIT_AS must fail: %+v", resp)
	}
}

func TestExecuteUsesMinimalEnv(t *testing.T) {
	t.Setenv("LD_PRELOAD", "evil.so")
	resp := execute(guestproto.Request{
		Code:     "import os; print('PRELOAD='+os.environ.get('LD_PRELOAD','missing')); print(os.environ.get('PATH',''))",
		Runtime:  "python",
		TimeoutS: 5,
	})
	if resp.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", resp.ExitCode, resp.Stderr)
	}
	if strings.Contains(resp.Stdout, "evil.so") {
		t.Fatalf("child inherited LD_PRELOAD: %q", resp.Stdout)
	}
	if !strings.Contains(resp.Stdout, "PRELOAD=missing") {
		t.Fatalf("stdout=%q", resp.Stdout)
	}
	if !strings.Contains(resp.Stdout, "/usr/local/bin:/usr/bin:/bin") {
		t.Fatalf("expected fixed PATH, got %q", resp.Stdout)
	}
}

func TestExecuteHonorsFileSizeRlimit(t *testing.T) {
	resp := execute(guestproto.Request{
		Code:      "open('/tmp/warden-big','wb').write(b'x'*(200*1024))",
		Runtime:   "python",
		TimeoutS:  5,
		DiskBytes: 32 << 10,
	})
	if resp.ExitCode == 0 && !resp.TimedOut {
		t.Fatalf("write above RLIMIT_FSIZE must fail: %+v", resp)
	}
}

func TestExecuteRunsInTmp(t *testing.T) {
	resp := execute(guestproto.Request{
		Code:     "import os; print(os.getcwd())",
		Runtime:  "python",
		TimeoutS: 5,
	})
	if resp.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", resp.ExitCode, resp.Stderr)
	}
	if !strings.Contains(resp.Stdout, "/tmp") {
		t.Fatalf("job cwd must be /tmp, got %q", resp.Stdout)
	}
}

func TestGuestJobSysAttrDropsRoot(t *testing.T) {
	attr := guestJobSysAttr()
	if attr == nil || !attr.Setpgid || attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("attr=%+v", attr)
	}
	if os.Geteuid() == 0 {
		if attr.Credential == nil || attr.Credential.Uid != 65534 {
			t.Fatalf("root guest-agent must drop to nobody: %+v", attr.Credential)
		}
		return
	}
	if attr.Credential != nil {
		t.Fatalf("unprivileged tests must not set Credential: %+v", attr.Credential)
	}
}
