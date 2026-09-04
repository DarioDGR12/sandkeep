package runtime

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
)

func TestDialGuestVsockHandshake(t *testing.T) {
	dir := t.TempDir()
	uds := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", uds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan guestproto.Request, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		line, _ := br.ReadString('\n')
		if line != "CONNECT 52\n" {
			t.Errorf("handshake %q", line)
		}
		_, _ = io.WriteString(conn, "OK 1073741824\n")
		req, err := guestproto.ReadRequest(io.MultiReader(br, conn))
		if err != nil {
			t.Error(err)
			return
		}
		done <- req
		_ = guestproto.WriteResponse(conn, guestproto.Response{Stdout: "ok\n", ExitCode: 0})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialGuestVsock(ctx, uds, 52)
	if err != nil {
		t.Fatal(err)
	}
	if err := guestproto.WriteRequest(conn, guestproto.Request{Code: "print(1)", Runtime: "python", TimeoutS: 5}); err != nil {
		t.Fatal(err)
	}
	resp, err := guestproto.ReadResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if resp.Stdout != "ok\n" || resp.ExitCode != 0 {
		t.Fatalf("resp=%+v", resp)
	}
	select {
	case req := <-done:
		if req.Code != "print(1)" {
			t.Fatalf("guest saw %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("guest did not receive request")
	}
}

func TestDialGuestVsockRejects(t *testing.T) {
	dir := t.TempDir()
	uds := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", uds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		_, _ = br.ReadString('\n')
		_, _ = io.WriteString(conn, "ERROR\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dialGuestVsock(ctx, uds, 52)
	if err == nil {
		t.Fatal("expected handshake error")
	}
}
