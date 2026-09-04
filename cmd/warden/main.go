// Command warden is the HTTP control plane for the sandbox.
//
// It only wires dependencies and listens. Isolation lives in internal/*.
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
		if os.Getenv("WARDEN_ROOTFS_POOL") == "0" {
			fcCfg.RootfsPoolSize = 0
		} else if fcCfg.RootfsPoolSize <= 0 {
			fcCfg.RootfsPoolSize = 2
		}
		rt = runtime.NewFirecrackerWithConfig(fcCfg)
	}

	maxVMs := 1
	if v := os.Getenv("WARDEN_MAX_VMS"); v != "" {
		fmt.Sscanf(v, "%d", &maxVMs)
	}
	queueWait := 15 * time.Second
	if v := os.Getenv("WARDEN_VM_QUEUE_WAIT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			queueWait = d
		}
	}
	rt = runtime.NewGate(rt, maxVMs, queueWait)

	apiKey := strings.TrimSpace(os.Getenv("WARDEN_API_KEY"))
	allowAnon := os.Getenv("WARDEN_ALLOW_ANON") == "1"
	tlsCfg, err := api.LoadTLS(api.TLSFiles{
		CertFile:     os.Getenv("WARDEN_TLS_CERT"),
		KeyFile:      os.Getenv("WARDEN_TLS_KEY"),
		ClientCAFile: os.Getenv("WARDEN_TLS_CLIENT_CA"),
	})
	if err != nil {
		return err
	}
	mtls := tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert
	jwksURL := strings.TrimSpace(os.Getenv("WARDEN_JWT_JWKS"))
	var jwt *api.JWTVerifier
	if jwksURL != "" {
		jwt = &api.JWTVerifier{
			JWKSURL:  jwksURL,
			Issuer:   os.Getenv("WARDEN_JWT_ISSUER"),
			Audience: envOr("WARDEN_JWT_AUDIENCE", "warden"),
		}
	}
	if err := api.CheckBindPolicy(listen, api.AuthPolicy{
		APIKey:    apiKey,
		AllowAnon: allowAnon,
		JWKSURL:   jwksURL,
		MTLS:      mtls,
	}); err != nil {
		return err
	}

	auditLog, dbCloser, err := buildAudit(log, auditPath)
	if err != nil {
		return err
	}
	if dbCloser != nil {
		defer dbCloser.Close()
	}

	httpCfg := api.DefaultConfig(listen)
	httpCfg.APIKey = apiKey
	httpCfg.JWT = jwt
	httpCfg.TLS = tlsCfg
	httpCfg.MTLS = mtls
	httpCfg.RequireAll = os.Getenv("WARDEN_AUTH_REQUIRE_ALL") == "1"
	httpCfg.MTLSSuffices = !httpCfg.RequireAll
	cgroupLimiter := resources.NoopLimiter{Log: log}
	srv := api.NewServer(httpCfg, api.Dependencies{
		Runtime:     rt,
		Limiter:     cgroupLimiter,
		Limits:      limits,
		Seccomp:     seccomp,
		Network:     netFilter,
		Audit:       auditLog,
		AuditStrict: os.Getenv("WARDEN_AUDIT_STRICT") == "1",
		Snapshots:   snaps,
		Log:         log,
		BootTimeout: 20 * time.Second,
		QueueWait:   queueWait,
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
		"auth", apiKey != "",
		"jwt", jwt != nil,
		"tls", tlsCfg != nil,
		"mtls", mtls,
		"max_vms", maxVMs,
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
	if port := os.Getenv("PORT"); port != "" {
		// Cloud proxies inject PORT and expect all interfaces.
		return "0.0.0.0:" + port
	}
	// Local default is loopback so `go run` does not need an API key.
	return "127.0.0.1:8080"
}

func buildAudit(log *slog.Logger, jsonlPath string) (audit.Logger, *sql.DB, error) {
	sinks := []audit.Logger{
		audit.NewJSONLLogger(jsonlPath),
		audit.SlogSink{Log: log},
	}
	if u := strings.TrimSpace(os.Getenv("WARDEN_AUDIT_URL")); u != "" {
		sinks = append(sinks, audit.HTTPSink{
			URL:   u,
			Token: os.Getenv("WARDEN_AUDIT_TOKEN"),
		})
	}
	dsn := strings.TrimSpace(os.Getenv("WARDEN_AUDIT_DATABASE_URL"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	var db *sql.DB
	if dsn != "" {
		sink, opened, err := audit.OpenPostgres(dsn)
		if err != nil {
			return nil, nil, err
		}
		db = opened
		sinks = append(sinks, sink)
	}
	return audit.Fanout{Sinks: sinks}, db, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
