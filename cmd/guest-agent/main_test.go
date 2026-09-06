package main

import (
	"net"
	"strings"
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
