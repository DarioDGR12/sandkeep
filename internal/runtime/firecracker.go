package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
	"github.com/DarioDGR12/sandkeep/internal/network"
)

// Firecracker boots a disposable microVM per request and talks to a guest
// agent over vsock. There is no virtio-net device when the egress allowlist
// is empty — that is the phase-2 enforcement of deny-all. A non-empty
// allowlist fails closed until TAP/iptables lands.
type Firecracker struct {
	cfg  Config
	log  *slog.Logger
	seq  atomic.Uint64
	cids atomic.Uint32
}

// NewFirecracker returns a backend that fails on Boot until assets exist.
// Prefer NewFirecrackerWithConfig from main after LoadConfig.
func NewFirecracker() *Firecracker {
	return NewFirecrackerWithConfig(DefaultConfig())
}

// NewFirecrackerWithConfig wires a configured backend. Missing files are
// reported at Boot, so the HTTP server can still start.
func NewFirecrackerWithConfig(cfg Config) *Firecracker {
	if cfg.AgentPort == 0 {
		cfg.AgentPort = guestproto.DefaultPort
	}
	if cfg.BootTimeout <= 0 {
		cfg.BootTimeout = 20 * time.Second
	}
	if cfg.VCPUCount <= 0 {
		cfg.VCPUCount = 1
	}
	if cfg.BootArgs == "" {
		cfg.BootArgs = defaultBootArgs
	}
	cfg.Binary = absPath(cfg.Binary)
	cfg.Kernel = absPath(cfg.Kernel)
	cfg.Rootfs = absPath(cfg.Rootfs)
	cfg.WorkDir = absPath(cfg.WorkDir)
	f := &Firecracker{cfg: cfg, log: slog.Default()}
	f.cids.Store(2) // next CID is 3 (0-2 are reserved)
	return f
}

// Name implements Runtime.
func (*Firecracker) Name() string { return "firecracker" }

// Ready reports whether a real Boot can succeed.
func (f *Firecracker) Ready() error { return f.cfg.Validate() }

// Boot starts Firecracker, configures the VM, and waits for the guest agent.
func (f *Firecracker) Boot(ctx context.Context, spec Spec) (Instance, error) {
	if !Supported(spec.Language) {
		return nil, fmt.Errorf("unsupported runtime %q", spec.Language)
	}
	if err := spec.Limits.Validate(); err != nil {
		return nil, fmt.Errorf("boot firecracker: %w", err)
	}
	if err := f.cfg.Validate(); err != nil {
		return nil, err
	}
	if err := denyNetworkOrFail(spec.Network); err != nil {
		return nil, err
	}

	id := fmt.Sprintf("fc-%d", f.seq.Add(1))
	cid := f.cids.Add(1)
	if cid < 3 {
		cid = f.cids.Add(3)
	}
	workDir := filepath.Join(f.cfg.WorkDir, id)
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return nil, fmt.Errorf("vm workdir: %w", err)
	}

	inst := &firecrackerInstance{
		id:       id,
		language: spec.Language,
		cid:      cid,
		port:     f.cfg.AgentPort,
		workDir:  workDir,
		apiSock:  filepath.Join(workDir, "api.sock"),
		vsockUDS: filepath.Join(workDir, "v.sock"),
		logFile:  filepath.Join(workDir, "firecracker.log"),
		log:      f.log,
	}

	if err := f.launch(ctx, spec, inst); err != nil {
		_ = inst.cleanupFiles()
		return nil, err
	}
	return inst, nil
}

func denyNetworkOrFail(p network.Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("network policy: %w", err)
	}
	if len(p.Allowlist) > 0 {
		return fmt.Errorf("egress allowlist is not empty but TAP networking is not implemented; refusing to boot a VM that would silently have no network")
	}
	return nil
}

func (f *Firecracker) launch(ctx context.Context, spec Spec, inst *firecrackerInstance) error {
	rootCopy := filepath.Join(inst.workDir, "rootfs.ext4")
	if err := cloneFile(f.cfg.Rootfs, rootCopy); err != nil {
		return fmt.Errorf("clone rootfs: %w", err)
	}
	st, err := os.Stat(rootCopy)
	if err != nil {
		return err
	}
	if spec.Limits.DiskBytes > 0 && st.Size() > spec.Limits.DiskBytes {
		return fmt.Errorf("rootfs size %d exceeds disk limit %d", st.Size(), spec.Limits.DiskBytes)
	}

	logF, err := os.OpenFile(inst.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("firecracker log: %w", err)
	}
	_ = logF.Close()

	// Do not use CommandContext: cancelling the boot ctx must not SIGKILL
	// the VM while Execute is still running. Destroy owns the lifecycle.
	cmd := exec.Command(f.cfg.Binary, "--api-sock", inst.apiSock)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = inst.workDir
	stderr, err := os.OpenFile(filepath.Join(inst.workDir, "fc.stderr"), os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stderr.Close()
		return fmt.Errorf("start firecracker: %w", err)
	}
	inst.cmd = cmd
	inst.stderr = stderr

	if f.cfg.Cgroup != nil {
		cleanup, err := f.cfg.Cgroup.Attach(inst.id, cmd.Process.Pid, spec.Limits)
		if err != nil {
			inst.kill()
			return err
		}
		inst.cgroupCleanup = cleanup
	}

	if err := waitForSocket(ctx, inst.apiSock, 5*time.Second); err != nil {
		inst.kill()
		return fmt.Errorf("firecracker api socket: %w", err)
	}
	inst.client = newFCClient(inst.apiSock, 10*time.Second)

	memMiB := int(spec.Limits.MemoryBytes / (1 << 20))
	if memMiB < 128 {
		memMiB = 128
	}
	if err := inst.client.configure(ctx,
		fcMachineConfig{VCPUCount: f.cfg.VCPUCount, MemSizeMiB: memMiB, SMT: false},
		fcBootSource{KernelImagePath: f.cfg.Kernel, BootArgs: f.cfg.BootArgs},
		fcDrive{DriveID: "rootfs", PathOnHost: rootCopy, IsRootDevice: true, IsReadOnly: false},
		fcVsock{GuestCID: inst.cid, UDSPath: inst.vsockUDS},
		&fcLogger{LogPath: inst.logFile, Level: "Info", ShowLevel: true},
	); err != nil {
		inst.kill()
		return err
	}
	if err := inst.client.startInstance(ctx); err != nil {
		inst.kill()
		return err
	}

	bootCtx, cancel := context.WithTimeout(ctx, f.cfg.BootTimeout)
	defer cancel()
	if err := waitForSocket(bootCtx, inst.vsockUDS, f.cfg.BootTimeout); err != nil {
		inst.kill()
		return fmt.Errorf("vsock uds: %w", err)
	}
	if err := waitForGuestAgent(bootCtx, inst.vsockUDS, inst.port); err != nil {
		inst.kill()
		return err
	}
	f.log.Info("microvm ready", "vm_id", inst.id, "pid", cmd.Process.Pid, "cid", inst.cid)
	return nil
}

type firecrackerInstance struct {
	id            string
	language      string
	cid           uint32
	port          uint32
	workDir       string
	apiSock       string
	vsockUDS      string
	logFile       string
	cmd           *exec.Cmd
	client        *fcClient
	stderr        *os.File
	cgroupCleanup func() error
	log           *slog.Logger
	dead          atomic.Bool
}

func (i *firecrackerInstance) ID() string { return i.id }

func (i *firecrackerInstance) Execute(ctx context.Context, req ExecRequest) (Result, error) {
	if i.dead.Load() {
		return Result{}, fmt.Errorf("vm %s already destroyed", i.id)
	}
	if req.Timeout <= 0 {
		req.Timeout = 30 * time.Second
	}
	conn, err := dialGuestVsock(ctx, i.vsockUDS, i.port)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := guestproto.WriteRequest(conn, guestproto.Request{
		Code:     req.Code,
		Runtime:  i.language,
		TimeoutS: int(req.Timeout / time.Second),
	}); err != nil {
		return Result{}, err
	}
	resp, err := guestproto.ReadResponse(conn)
	if err != nil {
		if ctx.Err() != nil {
			return Result{VMID: i.id, ExitCode: -1, TimedOut: true, Stderr: ctx.Err().Error()}, nil
		}
		return Result{}, err
	}
	return Result{
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		ExitCode: resp.ExitCode,
		VMID:     i.id,
		TimedOut: resp.TimedOut,
	}, nil
}

func (i *firecrackerInstance) Destroy(ctx context.Context) error {
	if !i.dead.CompareAndSwap(false, true) {
		return fmt.Errorf("vm %s already destroyed", i.id)
	}
	var errs []error
	if i.client != nil {
		if err := i.client.sendCtrlAltDel(ctx); err != nil && i.log != nil {
			i.log.Debug("SendCtrlAltDel", "vm_id", i.id, "err", err)
		}
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	if i.cmd != nil && i.cmd.Process != nil {
		go func() { done <- i.cmd.Wait() }()
		select {
		case <-waitCtx.Done():
			i.kill()
			<-done
		case err := <-done:
			if err != nil && i.log != nil {
				i.log.Debug("firecracker exit", "vm_id", i.id, "err", err)
			}
		}
	}
	if i.stderr != nil {
		_ = i.stderr.Close()
	}
	if i.cgroupCleanup != nil {
		if err := i.cgroupCleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := i.cleanupFiles(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (i *firecrackerInstance) kill() {
	if i.cmd == nil || i.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-i.cmd.Process.Pid, syscall.SIGKILL)
	_, _ = i.cmd.Process.Wait()
}

func (i *firecrackerInstance) cleanupFiles() error {
	return os.RemoveAll(i.workDir)
}

func waitForSocket(ctx context.Context, path string, max time.Duration) error {
	if max <= 0 {
		max = 5 * time.Second
	}
	deadline := time.Now().Add(max)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func cloneFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
