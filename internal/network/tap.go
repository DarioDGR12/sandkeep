// Package network also owns the host TAP + nftables path in front of a
// microVM. An empty allowlist still means "do not create a NIC". A non-empty
// allowlist creates a netns, a TAP inside it, a veth uplink to the host, NAT,
// and a fail-closed forward chain on the host veth — never on the host TAP.
package network

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
)

// Link is one TAP bound to a single microVM, plus the netns/veth that
// keep that TAP out of the host network namespace.
type Link struct {
	Name       string
	HostIP     net.IP
	GuestIP    net.IP
	Prefix     int
	GuestMAC   string
	Table      string
	NetNS      string
	NetNSPath  string
	HostVeth   string
	NSVeth     string
	UplinkHost net.IP
	UplinkNS   net.IP
}

// FilterIface is the host-visible device the nft forward chain attaches to.
// With a netns that is the uplink veth, not the TAP (the TAP is inside the ns).
func (l *Link) FilterIface() string {
	if l == nil {
		return ""
	}
	if l.HostVeth != "" {
		return l.HostVeth
	}
	return l.Name
}

// GuestSubnet is the /30 on the TAP, used for the host route via the veth.
func (l *Link) GuestSubnet() string {
	if l == nil {
		return ""
	}
	ip := l.HostIP.To4()
	if ip == nil {
		return ""
	}
	network := net.IPv4(ip[0], ip[1], ip[2], ip[3]&^3).To4()
	prefix := l.Prefix
	if prefix == 0 {
		prefix = 30
	}
	return fmt.Sprintf("%s/%d", network.String(), prefix)
}

// TapFactory creates and tears down a Link for one VM.
type TapFactory interface {
	Setup(id string, policy Policy) (*Link, error)
	Teardown(link *Link) error
}

// Recreator rebuilds a previously allocated Link (same names and addresses)
// so a snapshot restore can reattach the virtio-net host_dev_name.
type Recreator interface {
	Recreate(link *Link, policy Policy) error
}

// Runner runs host commands. Tests replace it with a recorder.
// The last argument may be stdin for `nft -f -`.
type Runner func(name string, args ...string) error

// TAP implements TapFactory with ip + nft.
type TAP struct {
	Log    *slog.Logger
	Run    Runner
	Lookup func(host string) ([]net.IP, error)
	IP     string
	Sudo   bool
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

func (t *TAP) ipBin() string {
	if t != nil && t.IP != "" {
		return t.IP
	}
	return IPCommand()
}

func (t *TAP) run(name string, args ...string) error {
	fn := t.Run
	if fn == nil {
		fn = defaultRun
	}
	if t.Sudo {
		return fn("sudo", append([]string{"-n", name}, args...)...)
	}
	return fn(name, args...)
}

func (t *TAP) runIP(args ...string) error {
	return t.run(t.ipBin(), args...)
}

func (t *TAP) runInNS(ns string, args ...string) error {
	ip := t.ipBin()
	return t.runNS(ns, ip, args...)
}

func (t *TAP) runNS(ns, name string, args ...string) error {
	ip := t.ipBin()
	return t.run(ip, append([]string{"netns", "exec", ns, name}, args...)...)
}

// Setup allocates a /30, creates a netns + TAP + veth uplink, and installs nft.
func (t *TAP) Setup(id string, policy Policy) (*Link, error) {
	ips, err := t.precheck(policy)
	if err != nil {
		return nil, err
	}
	n := t.seq.Add(1)
	hostIP, guestIP, err := subnet30(n)
	if err != nil {
		return nil, err
	}
	uplinkHost, uplinkNS, err := uplink30(n)
	if err != nil {
		return nil, err
	}
	name := tapName(id)
	hostVeth, nsVeth := vethNames(name)
	ns := netnsName(id)
	link := &Link{
		Name:       name,
		HostIP:     hostIP,
		GuestIP:    guestIP,
		Prefix:     30,
		GuestMAC:   macFromIP(guestIP),
		Table:      nftTable(id),
		NetNS:      ns,
		NetNSPath:  NetNSPath(ns),
		HostVeth:   hostVeth,
		NSVeth:     nsVeth,
		UplinkHost: uplinkHost,
		UplinkNS:   uplinkNS,
	}
	if err := t.apply(link, ips); err != nil {
		return nil, err
	}
	if t.Log != nil {
		t.Log.Info("tap ready",
			"id", id,
			"dev", link.Name,
			"netns", link.NetNS,
			"veth", link.HostVeth,
			"guest", guestIP.String(),
			"allow", len(ips),
		)
	}
	return link, nil
}

// Recreate brings an existing Link (names + addresses from a snapshot) back
// up and installs the current allowlist. It does not allocate a new subnet.
func (t *TAP) Recreate(link *Link, policy Policy) error {
	if link == nil || link.Name == "" {
		return fmt.Errorf("tap: recreate requires a named link")
	}
	ips, err := t.precheck(policy)
	if err != nil {
		return err
	}
	t.fillDerived(link)
	return t.apply(link, ips)
}

func (t *TAP) fillDerived(link *Link) {
	if link.HostVeth == "" || link.NSVeth == "" {
		link.HostVeth, link.NSVeth = vethNames(link.Name)
	}
	if link.NetNS == "" {
		link.NetNS = netnsName(link.Name)
	}
	if link.NetNSPath == "" {
		link.NetNSPath = NetNSPath(link.NetNS)
	}
	if link.Table == "" {
		link.Table = nftTable(link.Name)
	}
	if link.Prefix == 0 {
		link.Prefix = 30
	}
}

func (t *TAP) precheck(policy Policy) ([]net.IP, error) {
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
	return ips, nil
}

func (t *TAP) apply(link *Link, ips []net.IP) error {
	if err := validateNetNSName(link.NetNS); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = t.Teardown(link)
		}
	}()

	if err := t.runIP("netns", "add", link.NetNS); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := t.runIP("tuntap", "add", "dev", link.Name, "mode", "tap"); err != nil {
		return err
	}
	if err := t.runIP("link", "set", "dev", link.Name, "netns", link.NetNS); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "addr", "add", fmt.Sprintf("%s/%d", link.HostIP, link.Prefix), "dev", link.Name); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "link", "set", "dev", link.Name, "up"); err != nil {
		return err
	}

	if err := t.runIP("link", "add", link.HostVeth, "type", "veth", "peer", "name", link.NSVeth); err != nil {
		return err
	}
	if err := t.runIP("link", "set", "dev", link.NSVeth, "netns", link.NetNS); err != nil {
		return err
	}
	if err := t.runIP("addr", "add", fmt.Sprintf("%s/%d", link.UplinkHost, link.Prefix), "dev", link.HostVeth); err != nil {
		return err
	}
	if err := t.runIP("link", "set", "dev", link.HostVeth, "up"); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "addr", "add", fmt.Sprintf("%s/%d", link.UplinkNS, link.Prefix), "dev", link.NSVeth); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "link", "set", "dev", link.NSVeth, "up"); err != nil {
		return err
	}
	if err := t.runInNS(link.NetNS, "route", "add", "default", "via", link.UplinkHost.String()); err != nil {
		return err
	}
	if subnet := link.GuestSubnet(); subnet != "" && link.UplinkNS != nil {
		if err := t.runIP("route", "add", subnet, "via", link.UplinkNS.String()); err != nil {
			return err
		}
	}

	_ = t.run("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = t.runNS(link.NetNS, "sysctl", "-w", "net.ipv4.ip_forward=1")

	if err := t.applyRules(RenderNFT(link, ips)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// Teardown removes the nft table, the host route, the netns (TAP + ns veth
// die with it), and the host veth if it is still around.
func (t *TAP) Teardown(link *Link) error {
	if link == nil {
		return nil
	}
	var errs []string
	if link.Table != "" {
		if err := t.run("nft", "delete", "table", "inet", link.Table); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if subnet := link.GuestSubnet(); subnet != "" {
		_ = t.runIP("route", "del", subnet)
	}
	if link.NetNS != "" {
		if err := t.runIP("netns", "del", link.NetNS); err != nil {
			errs = append(errs, err.Error())
		}
	} else if link.Name != "" {
		if err := t.runIP("link", "del", link.Name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if link.HostVeth != "" {
		_ = t.runIP("link", "del", link.HostVeth)
	}
	if len(errs) > 0 {
		return fmt.Errorf("tap teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (t *TAP) applyRules(script string) error {
	if t.Run != nil {
		if t.Sudo {
			return t.Run("sudo", "-n", "nft", "-f", "-", script)
		}
		return t.Run("nft", "-f", "-", script)
	}
	name := "nft"
	args := []string{"-f", "-"}
	if t.Sudo {
		name = "sudo"
		args = []string{"-n", "nft", "-f", "-"}
	}
	cmd := exec.Command(name, args...)
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
	a, b, err := pair30(172, 25, n)
	return a, b, err
}

func uplink30(n uint32) (host, ns net.IP, err error) {
	// 172.27.0.0/16 — veth /30s, same index as the TAP /30.
	return pair30(172, 27, n)
}

func pair30(b0, b1 byte, n uint32) (a, b net.IP, err error) {
	if n == 0 || n > 16383 {
		return nil, nil, fmt.Errorf("tap: subnet index %d out of range", n)
	}
	off := (n - 1) * 4
	hi := byte(off >> 8)
	lo := byte(off)
	a = net.IPv4(b0, b1, hi, lo+1).To4()
	b = net.IPv4(b0, b1, hi, lo+2).To4()
	return a, b, nil
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
