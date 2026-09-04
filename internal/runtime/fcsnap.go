package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

func tapID(vmID, sessionID string) string {
	if sessionID != "" {
		return "s" + sessionID
	}
	return vmID
}

func networkMatches(rec *snapshot.Record, p network.Policy) bool {
	if rec == nil {
		return false
	}
	return rec.HasNetwork == (len(p.Allowlist) > 0)
}

func (i *firecrackerInstance) maybeSnapshot() {
	if i.sessionID == "" || i.store == nil || i.client == nil {
		return
	}
	// Execute's ctx may already be expired (job timeout). Snapshot has its own budget.
	snapCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := i.saveSnapshot(snapCtx); err != nil {
		if i.log != nil {
			i.log.Warn("session snapshot failed", "session_id", i.sessionID, "vm_id", i.id, "err", err)
		}
	}
}

func (i *firecrackerInstance) saveSnapshot(ctx context.Context) error {
	rec := i.snapRec
	if rec == nil {
		prepared, err := i.store.Prepare(ctx, i.sessionID, i.id)
		if err != nil {
			return err
		}
		rec = prepared
		i.snapRec = rec
	}
	rec.VMID = i.id
	rec.GuestCID = i.cid
	fillRecordNetwork(rec, i.tap)

	kind := "Full"
	if rec.Generation > 0 {
		kind = "Diff"
	}
	snapPath, memPath := rec.SnapshotPath, rec.MemoryPath
	diffHost := ""
	if rec.Path != "" {
		diffHost = filepath.Join(rec.Path, "vm.diff.mem")
	}
	if i.jailed {
		snapPath = "/vm.snap"
		if kind == "Diff" {
			memPath = "/vm.diff.mem"
		} else {
			memPath = "/vm.mem"
		}
	} else if kind == "Diff" && diffHost != "" {
		memPath = diffHost
	}

	snapCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := i.client.pauseVM(snapCtx); err != nil {
		return fmt.Errorf("pause vm: %w", err)
	}
	if err := i.client.createSnapshot(snapCtx, kind, snapPath, memPath); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	if i.jailed {
		if err := cloneFile(filepath.Join(i.workDir, "root", "vm.snap"), rec.SnapshotPath); err != nil {
			return fmt.Errorf("export snap: %w", err)
		}
		if kind == "Full" {
			if err := cloneFile(filepath.Join(i.workDir, "root", "vm.mem"), rec.MemoryPath); err != nil {
				return fmt.Errorf("export mem: %w", err)
			}
		} else if diffHost != "" {
			if err := cloneFile(filepath.Join(i.workDir, "root", "vm.diff.mem"), diffHost); err != nil {
				return fmt.Errorf("export diff: %w", err)
			}
		}
	}
	if kind == "Diff" && diffHost != "" {
		if err := applySparseDiff(rec.MemoryPath, diffHost); err != nil {
			return fmt.Errorf("rebase diff onto base mem: %w", err)
		}
		_ = os.Remove(diffHost)
	}
	if i.hostRootfs != "" && rec.RootfsPath != "" && i.hostRootfs != rec.RootfsPath {
		if err := cloneFile(i.hostRootfs, rec.RootfsPath); err != nil {
			return fmt.Errorf("export rootfs: %w", err)
		}
	}
	rec.LastKind = kind
	rec.Generation++
	return i.store.Commit(ctx, rec)
}

func fillRecordNetwork(rec *snapshot.Record, link *network.Link) {
	if rec == nil {
		return
	}
	if link == nil {
		rec.HasNetwork = false
		return
	}
	rec.HasNetwork = true
	rec.HostDevName = link.Name
	rec.GuestMAC = link.GuestMAC
	rec.GuestIP = ipString(link.GuestIP)
	rec.HostIP = ipString(link.HostIP)
	rec.NetNS = link.NetNS
	rec.NetNSPath = link.NetNSPath
	rec.HostVeth = link.HostVeth
	rec.NSVeth = link.NSVeth
	rec.UplinkHost = ipString(link.UplinkHost)
	rec.UplinkNS = ipString(link.UplinkNS)
	rec.Table = link.Table
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func linkFromRecord(rec *snapshot.Record) *network.Link {
	if rec == nil || !rec.HasNetwork {
		return nil
	}
	return &network.Link{
		Name:       rec.HostDevName,
		HostIP:     net.ParseIP(rec.HostIP),
		GuestIP:    net.ParseIP(rec.GuestIP),
		Prefix:     30,
		GuestMAC:   rec.GuestMAC,
		Table:      rec.Table,
		NetNS:      rec.NetNS,
		NetNSPath:  rec.NetNSPath,
		HostVeth:   rec.HostVeth,
		NSVeth:     rec.NSVeth,
		UplinkHost: net.ParseIP(rec.UplinkHost),
		UplinkNS:   net.ParseIP(rec.UplinkNS),
	}
}

func (f *Firecracker) launchRestore(ctx context.Context, spec Spec, inst *firecrackerInstance, rec *snapshot.Record) error {
	if rec.SnapshotPath == "" || rec.MemoryPath == "" {
		return fmt.Errorf("snapshot record missing file paths")
	}

	if rec.HasNetwork {
		link := linkFromRecord(rec)
		if link == nil || link.Name == "" {
			return fmt.Errorf("snapshot has network but no TAP name")
		}
		recreator, ok := f.cfg.Tap.(network.Recreator)
		if !ok {
			if t, is := f.cfg.Tap.(*network.TAP); is {
				recreator = t
			}
		}
		if recreator == nil {
			return fmt.Errorf("snapshot restore needs a TAP Recreator")
		}
		if err := recreator.Recreate(link, spec.Network); err != nil {
			return fmt.Errorf("tap recreate: %w", err)
		}
		inst.tap = link
		inst.tapTeardown = f.cfg.Tap.Teardown
	}

	paths, guestSnap, guestMem, err := f.prepareRestore(inst, rec)
	if err != nil {
		return err
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
		return fmt.Errorf("start firecracker (restore): %w", err)
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

	if err := inst.whileAlive(ctx, func() error {
		if err := inst.client.put(ctx, "/logger", &fcLogger{LogPath: paths.guestLog, Level: "Info", ShowLevel: true}); err != nil {
			return err
		}
		return inst.client.loadSnapshot(ctx, guestSnap, guestMem)
	}); err != nil {
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
	f.log.Info("microvm restored", "vm_id", inst.id, "session_id", spec.SessionID, "cid", inst.cid)
	return nil
}

func (f *Firecracker) prepareRestore(inst *firecrackerInstance, rec *snapshot.Record) (paths vmPaths, guestSnap, guestMem string, err error) {
	if f.cfg.Jailer != "" {
		paths, err = f.preparePathsFrom(inst, rec.RootfsPath)
		if err != nil {
			return vmPaths{}, "", "", err
		}
		if err := cloneFile(rec.SnapshotPath, filepath.Join(inst.workDir, "root", "vm.snap")); err != nil {
			return vmPaths{}, "", "", fmt.Errorf("import snap: %w", err)
		}
		if err := cloneFile(rec.MemoryPath, filepath.Join(inst.workDir, "root", "vm.mem")); err != nil {
			return vmPaths{}, "", "", fmt.Errorf("import mem: %w", err)
		}
		return paths, "/vm.snap", "/vm.mem", nil
	}

	if err := os.MkdirAll(inst.workDir, 0o750); err != nil {
		return vmPaths{}, "", "", err
	}
	logF, err := os.OpenFile(inst.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return vmPaths{}, "", "", err
	}
	_ = logF.Close()
	inst.hostRootfs = rec.RootfsPath
	if rec.Path != "" {
		inst.vsockUDS = filepath.Join(rec.Path, "v.sock")
		_ = os.Remove(inst.vsockUDS)
	}
	return vmPaths{
		hostRootfs:  rec.RootfsPath,
		guestKernel: f.cfg.Kernel,
		guestRootfs: rec.RootfsPath,
		guestVsock:  inst.vsockUDS,
		guestLog:    inst.logFile,
	}, rec.SnapshotPath, rec.MemoryPath, nil
}
