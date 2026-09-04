package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

// Firecracker boots a disposable microVM per request and talks to a guest
// agent over vsock. There is no virtio-net device when the egress allowlist
// is empty. A non-empty allowlist creates a TAP inside a dedicated netns
// (jailer --netns / ip netns exec) so the TAP is never in the host netns.
// session_id + a snapshot.Store restores a previous VM instead of cold boot.
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
	if cfg.Jailer != "" {
		cfg.Jailer = absPath(cfg.Jailer)
	}
	if cfg.SnapshotDir != "" {
		cfg.SnapshotDir = absPath(cfg.SnapshotDir)
	}
	if cfg.Snapshots == nil && cfg.SnapshotDir != "" {
		cfg.Snapshots = snapshot.NewDirStore(cfg.SnapshotDir)
	}
	if cfg.Pool == nil && cfg.RootfsPoolSize > 0 && cfg.Rootfs != "" && cfg.WorkDir != "" {
		cfg.Pool = NewFilePool(cfg.Rootfs, filepath.Join(cfg.WorkDir, "pool"), cfg.RootfsPoolSize)
	}
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
	if err := denyNetworkOrFail(spec.Network, f.cfg.Tap); err != nil {
		return nil, err
	}

	if spec.SessionID != "" && f.cfg.Snapshots != nil {
		rec, err := f.cfg.Snapshots.Restore(ctx, spec.SessionID)
		switch {
		case err == nil && networkMatches(rec, spec.Network):
			inst, rerr := f.bootOne(ctx, spec, rec)
			if rerr == nil {
				return inst, nil
			}
			f.log.Warn("snapshot restore failed; cold boot", "session_id", spec.SessionID, "err", rerr)
			_ = f.cfg.Snapshots.Delete(ctx, spec.SessionID)
		case err == nil && !networkMatches(rec, spec.Network):
			f.log.Info("snapshot network mismatch; cold boot", "session_id", spec.SessionID)
			_ = f.cfg.Snapshots.Delete(ctx, spec.SessionID)
		case err != nil && !errors.Is(err, snapshot.ErrNotFound) && !errors.Is(err, snapshot.ErrNotImplemented):
			return nil, err
		}
	}
	return f.bootOne(ctx, spec, nil)
}

func (f *Firecracker) bootOne(ctx context.Context, spec Spec, rec *snapshot.Record) (Instance, error) {
	id := fmt.Sprintf("fc-%d", f.seq.Add(1))
	cid := f.cids.Add(1)
	if cid < 3 {
		cid = f.cids.Add(3)
	}
	if rec != nil && rec.GuestCID >= 3 {
		cid = rec.GuestCID
	}
	workDir := filepath.Join(f.cfg.WorkDir, id)
	if f.cfg.Jailer == "" {
		if err := os.MkdirAll(workDir, 0o750); err != nil {
			return nil, fmt.Errorf("vm workdir: %w", err)
		}
	}

	inst := &firecrackerInstance{
		id:        id,
		language:  spec.Language,
		sessionID: spec.SessionID,
		store:     f.cfg.Snapshots,
		cid:       cid,
		port:      f.cfg.AgentPort,
		workDir:   workDir,
		apiSock:   filepath.Join(workDir, "api.sock"),
		vsockUDS:  filepath.Join(workDir, "v.sock"),
		logFile:   filepath.Join(workDir, "firecracker.log"),
		log:       f.log,
		exited:    make(chan struct{}),
	}
	if rec == nil && spec.SessionID != "" && f.cfg.Snapshots != nil {
		prepared, err := f.cfg.Snapshots.Prepare(ctx, spec.SessionID, id)
		if err != nil && !errors.Is(err, snapshot.ErrNotImplemented) {
			return nil, err
		}
		inst.snapRec = prepared
	} else {
		inst.snapRec = rec
	}

	var err error
	if rec != nil {
		err = f.launchRestore(ctx, spec, inst, rec)
	} else {
		err = f.launch(ctx, spec, inst)
	}
	if err != nil {
		if inst.tap != nil && inst.tapTeardown != nil {
			_ = inst.tapTeardown(inst.tap)
		}
		_ = inst.cleanupFiles()
		return nil, err
	}
	return inst, nil
}

func denyNetworkOrFail(p network.Policy, tap network.TapFactory) error {
	if p.DefaultPolicy == "" {
		p = network.Default()
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("network policy: %w", err)
	}
	if len(p.Allowlist) > 0 && tap == nil {
		return fmt.Errorf("egress allowlist is not empty but no TAP factory is configured; refusing to boot a VM that would silently have no network")
	}
	return nil
}

func (f *Firecracker) launch(ctx context.Context, spec Spec, inst *firecrackerInstance) error {
	paths, err := f.preparePaths(inst)
	if err != nil {
		return err
	}
	st, err := os.Stat(paths.hostRootfs)
	if err != nil {
		return err
	}
	if spec.Limits.DiskBytes > 0 && st.Size() > spec.Limits.DiskBytes {
		return fmt.Errorf("rootfs size %d exceeds disk limit %d", st.Size(), spec.Limits.DiskBytes)
	}

	var nic *fcNetIface
	bootArgs := f.cfg.BootArgs
	if len(spec.Network.Allowlist) > 0 {
		link, err := f.cfg.Tap.Setup(tapID(inst.id, spec.SessionID), spec.Network)
		if err != nil {
			return fmt.Errorf("tap: %w", err)
		}
		inst.tap = link
		inst.tapTeardown = f.cfg.Tap.Teardown
		nic = &fcNetIface{IfaceID: "eth0", GuestMAC: link.GuestMAC, HostDevName: link.Name}
		bootArgs = bootArgs + fmt.Sprintf(" ip=%s::%s:255.255.255.252:warden:eth0:off", link.GuestIP, link.HostIP)
	}

	cmd, err := f.spawnCmd(inst, paths)
	if err != nil {
		return err
	}
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
	go inst.reap()

	if f.cfg.Cgroup != nil && f.cfg.Jailer == "" {
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
	if err := inst.whileAlive(ctx, func() error {
		return inst.client.configure(ctx,
			fcMachineConfig{VCPUCount: f.cfg.VCPUCount, MemSizeMiB: memMiB, SMT: false},
			fcBootSource{KernelImagePath: paths.guestKernel, BootArgs: bootArgs},
			fcDrive{DriveID: "rootfs", PathOnHost: paths.guestRootfs, IsRootDevice: true, IsReadOnly: false},
			fcVsock{GuestCID: inst.cid, UDSPath: paths.guestVsock},
			&fcLogger{LogPath: paths.guestLog, Level: "Info", ShowLevel: true},
			nic,
		)
	}); err != nil {
		inst.kill()
		return err
	}
	startCtx, startCancel := context.WithTimeout(ctx, 8*time.Second)
	err = inst.whileAlive(startCtx, func() error {
		return inst.client.startInstance(startCtx)
	})
	startCancel()
	if err != nil {
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
	sessionID     string
	store         snapshot.Store
	snapRec       *snapshot.Record
	jailed        bool
	hostRootfs    string
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
	tap           *network.Link
	tapTeardown   func(*network.Link) error
	log           *slog.Logger
	dead          atomic.Bool
	waitOnce      sync.Once
	waitErr       error
	exited        chan struct{}
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
	res := Result{
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		ExitCode: resp.ExitCode,
		VMID:     i.id,
		TimedOut: resp.TimedOut,
	}
	i.maybeSnapshot()
	return res, nil
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
	if i.cmd != nil && i.cmd.Process != nil {
		waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		select {
		case <-waitCtx.Done():
			i.kill()
			_ = i.wait()
		case <-i.done():
			_ = i.wait()
		}
		cancel()
	}
	if i.stderr != nil {
		_ = i.stderr.Close()
	}
	if i.cgroupCleanup != nil {
		if err := i.cgroupCleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	if i.tap != nil && i.tapTeardown != nil {
		if err := i.tapTeardown(i.tap); err != nil {
			errs = append(errs, err)
		}
	}
	if err := i.cleanupFiles(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (i *firecrackerInstance) reap() {
	if i.cmd == nil {
		return
	}
	err := i.cmd.Wait()
	i.waitOnce.Do(func() { i.waitErr = err })
	if i.exited != nil {
		close(i.exited)
	}
}

func (i *firecrackerInstance) wait() error {
	if i.exited != nil {
		<-i.exited
	}
	return i.waitErr
}

func (i *firecrackerInstance) done() <-chan struct{} {
	return i.exited
}

func (i *firecrackerInstance) whileAlive(ctx context.Context, fn func() error) error {
	errCh := make(chan error, 1)
	go func() { errCh <- fn() }()
	select {
	case err := <-errCh:
		if err != nil {
			return i.annotateDeath(err)
		}
		return nil
	case <-i.done():
		return i.annotateDeath(fmt.Errorf("firecracker exited: %v", i.wait()))
	case <-ctx.Done():
		return i.annotateDeath(ctx.Err())
	}
}

func (i *firecrackerInstance) annotateDeath(err error) error {
	if err == nil {
		return nil
	}
	tail := tailFile(i.logFile, 2048)
	stderr := tailFile(filepath.Join(i.workDir, "fc.stderr"), 1024)
	if tail == "" && stderr == "" {
		return err
	}
	msg := err.Error()
	hungStart := strings.Contains(tail, "InstanceStart")
	if hungStart || strings.Contains(tail, "kvm") || strings.Contains(stderr, "KVM") || strings.Contains(msg, "exited") {
		return fmt.Errorf("%w: KVM/VMM failed during InstanceStart (nested virt often oopses on KVM_CREATE_VCPU)\nlog: %s\nstderr: %s", err, tail, stderr)
	}
	return fmt.Errorf("%w\nlog: %s\nstderr: %s", err, tail, stderr)
}

func tailFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	if len(data) > n {
		data = data[len(data)-n:]
	}
	return strings.TrimSpace(string(data))
}

func (i *firecrackerInstance) kill() {
	if i.cmd == nil || i.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-i.cmd.Process.Pid, syscall.SIGKILL)
}

func (i *firecrackerInstance) cleanupFiles() error {
	// Session vsock lives outside workDir so restore can reuse the path.
	// A stale UDS blocks the next PUT /snapshot/load.
	if i.snapRec != nil && i.snapRec.Path != "" && i.vsockUDS != "" {
		if strings.HasPrefix(i.vsockUDS, i.snapRec.Path+string(os.PathSeparator)) {
			_ = os.Remove(i.vsockUDS)
		}
	}
	return os.RemoveAll(i.workDir)
}

type vmPaths struct {
	hostRootfs  string
	guestKernel string
	guestRootfs string
	guestVsock  string
	guestLog    string
}

func (f *Firecracker) preparePaths(inst *firecrackerInstance) (vmPaths, error) {
	return f.preparePathsFrom(inst, f.cfg.Rootfs)
}

func (f *Firecracker) preparePathsFrom(inst *firecrackerInstance, rootfsSrc string) (vmPaths, error) {
	if f.cfg.Jailer != "" {
		layout, err := newJailLayout(f.cfg.WorkDir, f.cfg.Binary, inst.id)
		if err != nil {
			return vmPaths{}, err
		}
		if err := prepareJail(layout, f.cfg.Kernel, rootfsSrc, f.placeRootfs); err != nil {
			return vmPaths{}, err
		}
		inst.jailed = true
		inst.workDir = layout.JailDir
		inst.apiSock = filepath.Join(layout.Root, "api.sock")
		inst.vsockUDS = filepath.Join(layout.Root, "v.sock")
		inst.logFile = filepath.Join(layout.Root, "firecracker.log")
		inst.hostRootfs = filepath.Join(layout.Root, "rootfs.ext4")
		return vmPaths{
			hostRootfs:  inst.hostRootfs,
			guestKernel: "/vmlinux",
			guestRootfs: "/rootfs.ext4",
			guestVsock:  "/v.sock",
			guestLog:    "/firecracker.log",
		}, nil
	}

	rootCopy := filepath.Join(inst.workDir, "rootfs.ext4")
	if inst.snapRec != nil && inst.snapRec.RootfsPath != "" {
		if err := os.MkdirAll(inst.snapRec.Path, 0o750); err != nil {
			return vmPaths{}, err
		}
		rootCopy = inst.snapRec.RootfsPath
		inst.vsockUDS = filepath.Join(inst.snapRec.Path, "v.sock")
	}
	if err := f.placeRootfs(rootfsSrc, rootCopy); err != nil {
		return vmPaths{}, fmt.Errorf("clone rootfs: %w", err)
	}
	logF, err := os.OpenFile(inst.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return vmPaths{}, fmt.Errorf("firecracker log: %w", err)
	}
	_ = logF.Close()
	inst.hostRootfs = rootCopy
	return vmPaths{
		hostRootfs:  rootCopy,
		guestKernel: f.cfg.Kernel,
		guestRootfs: rootCopy,
		guestVsock:  inst.vsockUDS,
		guestLog:    inst.logFile,
	}, nil
}

func (f *Firecracker) placeRootfs(src, dst string) error {
	if f.cfg.Pool != nil && absPath(src) == absPath(f.cfg.Rootfs) {
		return f.cfg.Pool.Acquire(dst)
	}
	return cloneFile(src, dst)
}

func (f *Firecracker) spawnCmd(inst *firecrackerInstance, _ vmPaths) (*exec.Cmd, error) {
	// Do not use CommandContext: cancelling the boot ctx must not SIGKILL
	// the VM while Execute is still running. Destroy owns the lifecycle.
	netnsPath := ""
	netnsName := ""
	if inst.tap != nil {
		netnsPath = inst.tap.NetNSPath
		netnsName = inst.tap.NetNS
	}
	if f.cfg.Jailer != "" {
		layout, err := newJailLayout(f.cfg.WorkDir, f.cfg.Binary, inst.id)
		if err != nil {
			return nil, err
		}
		return jailerCommand(f.cfg, layout, netnsPath)
	}
	if netnsName != "" {
		ip := network.IPCommand()
		cmd := exec.Command(ip, "netns", "exec", netnsName, f.cfg.Binary, "--api-sock", inst.apiSock)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Dir = inst.workDir
		return cmd, nil
	}
	cmd := exec.Command(f.cfg.Binary, "--api-sock", inst.apiSock)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = inst.workDir
	return cmd, nil
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
