// Command guest-agent runs inside the microVM. It is PID 1 when the kernel
// is booted with init=/usr/local/bin/guest-agent.
//
// It mounts a minimal filesystem, listens on AF_VSOCK (or TCP for host-side
// tests), and execs python3/node for one job per connection. This binary
// must not be used as a host executor.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := mountEssential(); err != nil {
		log.Printf("mount: %v", err)
	}

	addr := envOr("WARDEN_AGENT_LISTEN", fmt.Sprintf("vsock:%d", guestproto.DefaultPort))
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := applyGuestFence(); err != nil {
		return fmt.Errorf("guest fence: %w", err)
	}
	log.Printf("guest-agent listening on %s", addr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

var jobSlots = make(chan struct{}, 1)

func handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	req, err := guestproto.ReadRequest(conn)
	if err != nil {
		log.Printf("read: %v", err)
		return
	}
	select {
	case jobSlots <- struct{}{}:
		defer func() { <-jobSlots }()
	default:
		_ = guestproto.WriteResponse(conn, guestproto.Response{Stderr: "guest: busy", ExitCode: 1})
		return
	}
	resp := execute(req)
	if err := guestproto.WriteResponse(conn, resp); err != nil {
		log.Printf("write: %v", err)
	}
}

func execute(req guestproto.Request) guestproto.Response {
	if len(req.Code) > guestproto.MaxCodeBytes {
		return guestproto.Response{Stderr: "guest: code too large", ExitCode: 127}
	}
	timeout := time.Duration(req.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd, err := commandFor(ctx, req.Runtime, req.Code)
	if err != nil {
		return guestproto.Response{Stderr: err.Error(), ExitCode: 127}
	}

	var stdout, stderr limitedBuffer
	stdout.rest = guestproto.MaxOutputBytes
	stderr.rest = guestproto.MaxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return guestproto.Response{Stderr: err.Error(), ExitCode: 1}
	}
	if err := applyGuestLimits(cmd.Process.Pid, req); err != nil {
		killProcessGroup(cmd)
		_ = cmd.Wait()
		return guestproto.Response{Stderr: "guest: rlimit: " + err.Error(), ExitCode: 1}
	}
	runErr := cmd.Wait()
	resp := guestproto.Response{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		resp.TimedOut = true
		resp.ExitCode = -1
		if resp.Stderr != "" {
			resp.Stderr += "\n"
		}
		resp.Stderr += "guest: execution timed out"
		killProcessGroup(cmd)
		return resp
	}
	var exit *exec.ExitError
	if errors.As(runErr, &exit) {
		resp.ExitCode = exit.ExitCode()
		return resp
	}
	if runErr != nil {
		resp.ExitCode = 1
		if resp.Stderr != "" {
			resp.Stderr += "\n"
		}
		resp.Stderr += runErr.Error()
		return resp
	}
	return resp
}

func commandFor(ctx context.Context, runtime, code string) (*exec.Cmd, error) {
	switch strings.ToLower(strings.TrimSpace(runtime)) {
	case "python", "python3":
		bin := firstExisting("python3", "python")
		if bin == "" {
			return nil, fmt.Errorf("python interpreter not found in guest")
		}
		return exec.CommandContext(ctx, bin, "-c", code), nil
	case "node":
		bin := firstExisting("node", "nodejs")
		if bin == "" {
			return nil, fmt.Errorf("node interpreter not found in guest")
		}
		return exec.CommandContext(ctx, bin, "-e", code), nil
	default:
		return nil, fmt.Errorf("unsupported runtime %q", runtime)
	}
}

func firstExisting(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func applyGuestLimits(pid int, req guestproto.Request) error {
	mem := req.MemoryBytes
	if mem <= 0 {
		mem = 256 << 20
	}
	if mem < 16<<20 {
		mem = 16 << 20
	}
	pids := req.PIDsMax
	if pids <= 0 {
		pids = 64
	}
	if pids < 1 {
		pids = 1
	}
	as := unix.Rlimit{Cur: uint64(mem), Max: uint64(mem)}
	if err := unix.Prlimit(pid, unix.RLIMIT_AS, &as, nil); err != nil {
		return fmt.Errorf("RLIMIT_AS: %w", err)
	}
	nproc := unix.Rlimit{Cur: uint64(pids), Max: uint64(pids)}
	if err := unix.Prlimit(pid, unix.RLIMIT_NPROC, &nproc, nil); err != nil {
		return fmt.Errorf("RLIMIT_NPROC: %w", err)
	}
	nofile := unix.Rlimit{Cur: 256, Max: 256}
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &nofile, nil); err != nil {
		return fmt.Errorf("RLIMIT_NOFILE: %w", err)
	}
	return nil
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func listen(addr string) (net.Listener, error) {
	kind, value, ok := strings.Cut(addr, ":")
	if !ok {
		return nil, fmt.Errorf("listen addr %q: want vsock:PORT or tcp:HOST:PORT", addr)
	}
	switch kind {
	case "vsock":
		port, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("vsock port: %w", err)
		}
		return listenVsock(uint32(port))
	case "tcp":
		return net.Listen("tcp", value)
	default:
		return nil, fmt.Errorf("unknown listen scheme %q", kind)
	}
}

func listenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock bind :%d: %w", port, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d", port))
	ln, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("vsock file listener: %w", err)
	}
	return ln, nil
}

func mountEssential() error {
	mounts := []struct{ src, dst, fstype string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	}
	var errs []error
	for _, m := range mounts {
		if err := os.MkdirAll(m.dst, 0o755); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := syscall.Mount(m.src, m.dst, m.fstype, 0, ""); err != nil && !errors.Is(err, syscall.EBUSY) && !errors.Is(err, syscall.EEXIST) {
			errs = append(errs, fmt.Errorf("mount %s: %w", m.dst, err))
		}
	}
	return errors.Join(errs...)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type limitedBuffer struct {
	buf  bytes.Buffer
	rest int
	hit  bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.rest <= 0 {
		l.hit = true
		return len(p), nil
	}
	if len(p) > l.rest {
		_, _ = l.buf.Write(p[:l.rest])
		l.rest = 0
		l.hit = true
		return len(p), nil
	}
	n, err := l.buf.Write(p)
	l.rest -= n
	return n, err
}

func (l *limitedBuffer) String() string {
	s := l.buf.String()
	if l.hit {
		return s + "\n[truncated]"
	}
	return s
}

var _ io.Writer = (*limitedBuffer)(nil)
