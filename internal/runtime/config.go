package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

// ErrMissingAssets is returned when Firecracker cannot boot because the
// binary, kernel, or rootfs is not on disk.
var ErrMissingAssets = fmt.Errorf("firecracker assets missing")

// Config is host-side Firecracker settings. Paths are required for a real boot.
type Config struct {
	Binary       string        `json:"binary"`
	Kernel       string        `json:"kernel"`
	Rootfs       string        `json:"rootfs"`
	WorkDir      string        `json:"work_dir"`
	BootArgs     string        `json:"boot_args"`
	AgentPort    uint32        `json:"agent_port"`
	BootTimeout  time.Duration `json:"-"`
	VCPUCount    int           `json:"vcpu_count"`
	Jailer       string        `json:"jailer"`
	JailerUID    int           `json:"jailer_uid"`
	JailerGID    int           `json:"jailer_gid"`
	JailerSudo   bool          `json:"jailer_sudo"`
	JailerCgroup bool          `json:"jailer_cgroup"`
	NewPIDNS     bool          `json:"new_pid_ns"`
	SnapshotDir  string        `json:"snapshot_dir"`
	Cgroup       resources.CgroupAttacher
	Tap          network.TapFactory
	Snapshots    snapshot.Store
}

const defaultBootArgs = "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/guest-agent"

// DefaultConfig looks in ./assets and ./data/vms — the layout scripts/fetch-assets.sh writes.
func DefaultConfig() Config {
	return Config{
		Binary:      "assets/firecracker",
		Kernel:      "assets/vmlinux",
		Rootfs:      "assets/rootfs.ext4",
		WorkDir:     "data/vms",
		BootArgs:    defaultBootArgs,
		AgentPort:   guestproto.DefaultPort,
		BootTimeout: 20 * time.Second,
		VCPUCount:   1,
		SnapshotDir: "data/snapshots",
	}
}

// LoadConfig reads a JSON file and overlays environment variables.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("read firecracker config %s: %w", path, err)
		}
		if err == nil {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return Config{}, fmt.Errorf("parse firecracker config %s: %w", path, err)
			}
		}
	}
	overlayEnv(&cfg)
	if cfg.AgentPort == 0 {
		cfg.AgentPort = guestproto.DefaultPort
	}
	if cfg.BootArgs == "" {
		cfg.BootArgs = defaultBootArgs
	}
	if cfg.VCPUCount <= 0 {
		cfg.VCPUCount = 1
	}
	if cfg.BootTimeout <= 0 {
		cfg.BootTimeout = 20 * time.Second
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = "data/vms"
	}
	return cfg, nil
}

func overlayEnv(cfg *Config) {
	if v := os.Getenv("WARDEN_FC_BINARY"); v != "" {
		cfg.Binary = v
	}
	if v := os.Getenv("WARDEN_FC_KERNEL"); v != "" {
		cfg.Kernel = v
	}
	if v := os.Getenv("WARDEN_FC_ROOTFS"); v != "" {
		cfg.Rootfs = v
	}
	if v := os.Getenv("WARDEN_FC_WORKDIR"); v != "" {
		cfg.WorkDir = v
	}
	if v := os.Getenv("WARDEN_BOOT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.BootTimeout = d
		}
	}
	if v := os.Getenv("WARDEN_JAILER"); v != "" {
		cfg.Jailer = v
	}
	if v := os.Getenv("WARDEN_JAILER_UID"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.JailerUID)
	}
	if v := os.Getenv("WARDEN_JAILER_GID"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.JailerGID)
	}
	if os.Getenv("WARDEN_JAILER_SUDO") == "1" {
		cfg.JailerSudo = true
	}
	if os.Getenv("WARDEN_JAILER_CGROUP") == "1" {
		cfg.JailerCgroup = true
	}
	if os.Getenv("WARDEN_JAILER_NEWPID") == "1" {
		cfg.NewPIDNS = true
	}
	if v := os.Getenv("WARDEN_SNAPSHOT_DIR"); v != "" {
		cfg.SnapshotDir = v
	}
}

// Validate checks that the three boot assets exist and are readable.
func (c Config) Validate() error {
	for _, p := range []struct{ name, path string }{
		{"binary", c.Binary},
		{"kernel", c.Kernel},
		{"rootfs", c.Rootfs},
	} {
		if p.path == "" {
			return fmt.Errorf("%w: %s path is empty", ErrMissingAssets, p.name)
		}
		st, err := os.Stat(p.path)
		if err != nil {
			return fmt.Errorf("%w: %s %s: %v", ErrMissingAssets, p.name, p.path, err)
		}
		if st.IsDir() {
			return fmt.Errorf("%w: %s %s is a directory", ErrMissingAssets, p.name, p.path)
		}
	}
	if c.Jailer != "" {
		st, err := os.Stat(c.Jailer)
		if err != nil {
			return fmt.Errorf("%w: jailer %s: %v", ErrMissingAssets, c.Jailer, err)
		}
		if st.IsDir() {
			return fmt.Errorf("%w: jailer %s is a directory", ErrMissingAssets, c.Jailer)
		}
	}
	return nil
}

func absPath(p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return p
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
