// Command warden is the HTTP control plane for the sandbox.
//
// It only wires dependencies and listens. Isolation lives in internal/*.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/api"
	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfgDir := envOr("WARDEN_CONFIG_DIR", "configs")
	listen := listenAddr()
	backend := envOr("WARDEN_RUNTIME", "stub")
	auditPath := envOr("WARDEN_AUDIT_LOG", "audit.jsonl")

	limits, err := resources.LoadProfile(filepath.Join(cfgDir, "cgroups.json"))
	if err != nil {
		return fmt.Errorf("load cgroups: %w", err)
	}
	seccomp, err := resources.LoadSeccomp(filepath.Join(cfgDir, "seccomp.json"))
	if err != nil {
		return fmt.Errorf("load seccomp: %w", err)
	}
	netPolicy, err := network.Load(filepath.Join(cfgDir, "egress.json"))
	if err != nil {
		return fmt.Errorf("load egress: %w", err)
	}
	netFilter, err := network.NewStaticFilter(netPolicy)
	if err != nil {
		return err
	}

	rt, err := runtime.New(backend)
	if err != nil {
		return err
	}
	snaps := snapshot.Store(snapshot.Unsupported{})
	if backend == "firecracker" {
		fcCfg, err := runtime.LoadConfig(filepath.Join(cfgDir, "firecracker.json"))
		if err != nil {
			return fmt.Errorf("load firecracker config: %w", err)
		}
		fcCfg.Cgroup = resources.CgroupV2{
			Log:     log,
			Require: os.Getenv("WARDEN_CGROUP_REQUIRED") == "1",
		}
		tap := network.NewTAP(log)
		if os.Getenv("WARDEN_NET_SUDO") == "1" || os.Getenv("WARDEN_JAILER_SUDO") == "1" {
			tap.Sudo = true
		}
		fcCfg.Tap = tap
		if fcCfg.SnapshotDir != "" {
			snaps = snapshot.NewDirStore(fcCfg.SnapshotDir)
			fcCfg.Snapshots = snaps
		}
		rt = runtime.NewFirecrackerWithConfig(fcCfg)
	}

	cgroupLimiter := resources.NoopLimiter{Log: log}
	srv := api.NewServer(api.DefaultConfig(listen), api.Dependencies{
		Runtime:     rt,
		Limiter:     cgroupLimiter,
		Limits:      limits,
		Seccomp:     seccomp,
		Network:     netFilter,
		Audit:       audit.NewJSONLLogger(auditPath),
		Snapshots:   snaps,
		Log:         log,
		BootTimeout: 20 * time.Second,
	})

	ready := "unknown"
	if r, ok := rt.(interface{ Ready() error }); ok {
		if err := r.Ready(); err != nil {
			ready = err.Error()
		} else {
			ready = "yes"
		}
	}

	log.Info("warden starting",
		"addr", listen,
		"backend", rt.Name(),
		"ready", ready,
		"config_dir", cfgDir,
		"audit_log", auditPath,
		"egress_allowlist", len(netPolicy.Allowlist),
		"memory_bytes", limits.MemoryBytes,
		"snapshots", fmt.Sprintf("%T", snaps),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

func listenAddr() string {
	if addr := os.Getenv("WARDEN_ADDR"); addr != "" {
		return addr
	}
	port := envOr("PORT", "8080")
	// Bind all interfaces so cloud proxies (Render, etc.) can reach us.
	return "0.0.0.0:" + port
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
