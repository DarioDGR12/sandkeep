// Package network also owns the host TAP + nftables path in front of a
// microVM. An empty allowlist still means "do not create a NIC". A non-empty
// allowlist creates a TAP, NATs it, and installs a fail-closed forward chain.
package network

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
)

// Link is one host TAP bound to a single microVM.
type Link struct {
	Name     string
	HostIP   net.IP
	GuestIP  net.IP
	Prefix   int
	GuestMAC string
	Table    string
}

// TapFactory creates and tears down a Link for one VM.
type TapFactory interface {
	Setup(id string, policy Policy) (*Link, error)
	Teardown(link *Link) error
}

// Runner runs host commands. Tests replace it with a recorder.
type Runner func(name string, args ...string) error

// TAP implements TapFactory with ip + nft.
type TAP struct {
	Log    *slog.Logger
	Run    Runner
	Lookup func(host string) ([]net.IP, error)
	seq    atomic.Uint32
}

// NewTAP uses the real ip/nft binaries. Tests set Run and Lookup.
func NewTAP(log *slog.Logger) *TAP {
	return &TAP{Log: log, Lookup: net.LookupIP}
}

func defaultRun(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Setup allocates a /30, creates the TAP, enables forwarding, and installs nft.
func (t *TAP) Setup(id string, policy Policy) (*Link, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if len(policy.Allowlist) == 0 {
		return nil, fmt.Errorf("tap: refusing to create a NIC for an empty allowlist")
	}
	ips, err := resolveAllowlist(policy.Allowlist, t.Lookup)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("tap: allowlist resolved to zero addresses")
	}

	n := t.seq.Add(1)
	hostIP, guestIP, err := subnet30(n)
	if err != nil {
		return nil, err
	}
	link := &Link{
		Name:     tapName(id),
		HostIP:   hostIP,
		GuestIP:  guestIP,
		Prefix:   30,
		GuestMAC: macFromIP(guestIP),
		Table:    nftTable(id),
	}
	run := t.Run
	if run == nil {
		run = defaultRun
	}

	if err := run("ip", "tuntap", "add", "dev", link.Name, "mode", "tap"); err != nil {
		return nil, err
	}
	cleanupTap := true
	defer func() {
		if cleanupTap {
			_ = run("ip", "link", "del", link.Name)
		}
	}()
	if err := run("ip", "addr", "add", fmt.Sprintf("%s/%d", hostIP, link.Prefix), "dev", link.Name); err != nil {
		return nil, err
	}
	if err := run("ip", "link", "set", "dev", link.Name, "up"); err != nil {
		return nil, err
	}
	_ = run("sysctl", "-w", "net.ipv4.ip_forward=1")

	script := RenderNFT(link, ips)
	if err := t.applyRules(script); err != nil {
		return nil, err
	}
	if t.Log != nil {
		t.Log.Info("tap ready", "id", id, "dev", link.Name, "guest", guestIP.String(), "allow", len(ips))
	}
	cleanupTap = false
	return link, nil
}

// Teardown removes the nft table and the TAP.
func (t *TAP) Teardown(link *Link) error {
	if link == nil {
		return nil
	}
	run := t.Run
	if run == nil {
		run = defaultRun
	}
	var errs []string
	if err := run("nft", "delete", "table", "inet", link.Table); err != nil {
		errs = append(errs, err.Error())
	}
	if err := run("ip", "link", "del", link.Name); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("tap teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (t *TAP) applyRules(script string) error {
	if t.Run != nil {
		return t.Run("nft", "-f", "-", script)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func tapName(id string) string {
	s := "w" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, id)
	if len(s) > 15 {
		s = s[:15]
	}
	if s == "w" {
		s = "wtap"
	}
	return s
}

func nftTable(id string) string {
	s := "warden_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, id)
	return s
}

func subnet30(n uint32) (host, guest net.IP, err error) {
	// 172.25.0.0/16 carved into /30s. n starts at 1.
	if n == 0 || n > 16383 {
		return nil, nil, fmt.Errorf("tap: subnet index %d out of range", n)
	}
	off := (n - 1) * 4
	b2 := byte(off >> 8)
	b3 := byte(off)
	host = net.IPv4(172, 25, b2, b3+1).To4()
	guest = net.IPv4(172, 25, b2, b3+2).To4()
	return host, guest, nil
}

func macFromIP(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return "06:00:00:00:00:01"
	}
	return fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", ip[0], ip[1], ip[2], ip[3])
}

func resolveAllowlist(entries []string, lookup func(string) ([]net.IP, error)) ([]net.IP, error) {
	if lookup == nil {
		lookup = net.LookupIP
	}
	seen := map[string]struct{}{}
	var out []net.IP
	for _, raw := range entries {
		host := strings.TrimSpace(raw)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if _, ok := seen[ip.String()]; !ok {
				seen[ip.String()] = struct{}{}
				out = append(out, ip)
			}
			continue
		}
		ips, err := lookup(host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		for _, ip := range ips {
			if _, ok := seen[ip.String()]; ok {
				continue
			}
			seen[ip.String()] = struct{}{}
			out = append(out, ip)
		}
	}
	return out, nil
}
