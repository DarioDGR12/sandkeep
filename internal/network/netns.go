package network

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultNetNSDir is where `ip netns add` places the bind-mount.
const DefaultNetNSDir = "/var/run/netns"

// IPCommand returns a usable `ip` binary. This environment (and many
// containers) put iproute2 in /usr/sbin, which is often not on PATH.
func IPCommand() string {
	for _, p := range []string{"ip", "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "ip"
}

// NetNSPath is the jailer --netns argument for a namespace created by
// `ip netns add <name>`.
func NetNSPath(name string) string {
	return filepath.Join(DefaultNetNSDir, name)
}

func netnsName(id string) string {
	s := "warden-" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return -1
	}, id)
	if s == "warden-" {
		s = "warden-tap"
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func vethNames(tap string) (host, ns string) {
	base := strings.TrimPrefix(tap, "w")
	if base == "" {
		base = "tap"
	}
	host = "h" + base
	ns = "g" + base
	if len(host) > 15 {
		host = host[:15]
	}
	if len(ns) > 15 {
		ns = ns[:15]
	}
	return host, ns
}

func validateNetNSName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.Contains(name, "..") {
		return fmt.Errorf("netns: invalid name %q", name)
	}
	return nil
}
