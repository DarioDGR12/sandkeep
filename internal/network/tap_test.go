package network_test

import (
	"net"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/network"
)

func TestTapSetupRecordsNetnsAndVeth(t *testing.T) {
	var cmds []string
	tap := &network.TAP{
		IP: "ip",
		Run: func(name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
		Lookup: func(host string) ([]net.IP, error) {
			if host == "pypi.org" {
				return []net.IP{net.ParseIP("151.101.0.223")}, nil
			}
			return nil, nil
		},
	}
	link, err := tap.Setup("fc-1", network.Policy{
		DefaultPolicy: network.PolicyDeny,
		Allowlist:     []string{"pypi.org:443", "1.2.3.4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if link.Name != "wfc1" {
		t.Fatalf("tap name=%s", link.Name)
	}
	if link.NetNS != "warden-fc-1" || link.NetNSPath != "/var/run/netns/warden-fc-1" {
		t.Fatalf("netns=%s path=%s", link.NetNS, link.NetNSPath)
	}
	if link.HostVeth != "hfc1" || link.NSVeth != "gfc1" {
		t.Fatalf("veth host=%s ns=%s", link.HostVeth, link.NSVeth)
	}
	if link.GuestIP.String() != "172.25.0.2" || link.HostIP.String() != "172.25.0.1" {
		t.Fatalf("subnet host=%s guest=%s", link.HostIP, link.GuestIP)
	}
	if link.UplinkHost.String() != "172.27.0.1" || link.UplinkNS.String() != "172.27.0.2" {
		t.Fatalf("uplink host=%s ns=%s", link.UplinkHost, link.UplinkNS)
	}
	if link.GuestSubnet() != "172.25.0.0/30" {
		t.Fatalf("guest subnet=%s", link.GuestSubnet())
	}
	if !strings.HasPrefix(link.GuestMAC, "06:00:") {
		t.Fatalf("mac=%s", link.GuestMAC)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ip netns add warden-fc-1",
		"ip netns exec warden-fc-1 ip link set lo up",
		"ip tuntap add dev wfc1 mode tap",
		"ip link set dev wfc1 netns warden-fc-1",
		"ip link add hfc1 type veth peer name gfc1",
		"ip link set dev gfc1 netns warden-fc-1",
		"ip route add 172.25.0.0/30 via 172.27.0.2",
		"nft -f -",
		"151.101.0.223",
		"tcp dport 443",
		"1.2.3.4",
		"ip netns exec warden-fc-1 sysctl -w net.ipv4.ip_forward=1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in cmds:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "ip sysctl") {
		t.Fatalf("sysctl inside netns must not be invoked as `ip sysctl`:\n%s", joined)
	}
	if strings.Contains(joined, `iifname "wfc1"`) {
		t.Fatalf("nft must attach to the host veth, not the TAP:\n%s", joined)
	}
	if !strings.Contains(joined, `iifname "hfc1"`) {
		t.Fatalf("nft must filter the uplink veth:\n%s", joined)
	}
	if strings.Contains(joined, "ip daddr { 151.101.0.223 }") {
		t.Fatalf("pypi.org:443 must not open all ports:\n%s", joined)
	}
}

func TestTapSetupEmptyAllowlist(t *testing.T) {
	called := false
	tap := &network.TAP{Run: func(string, ...string) error {
		called = true
		return nil
	}}
	_, err := tap.Setup("x", network.Default())
	if err == nil {
		t.Fatal("empty allowlist must not create a NIC")
	}
	if called {
		t.Fatal("empty allowlist must not run ip/nft")
	}
}

func TestTapRecreateUsesStoredNames(t *testing.T) {
	var cmds []string
	tap := &network.TAP{
		IP: "ip",
		Run: func(name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
		Lookup: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
	}
	link := &network.Link{
		Name:       "wsess1",
		HostIP:     net.ParseIP("172.25.0.5"),
		GuestIP:    net.ParseIP("172.25.0.6"),
		Prefix:     30,
		GuestMAC:   "06:00:ac:19:00:06",
		Table:      "warden_sess1",
		NetNS:      "warden-sess1",
		NetNSPath:  "/var/run/netns/warden-sess1",
		HostVeth:   "hsess1",
		NSVeth:     "gsess1",
		UplinkHost: net.ParseIP("172.27.0.5"),
		UplinkNS:   net.ParseIP("172.27.0.6"),
	}
	if err := tap.Recreate(link, network.Policy{
		DefaultPolicy: network.PolicyDeny,
		Allowlist:     []string{"8.8.8.8"},
	}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip netns add warden-sess1") {
		t.Fatalf("must reuse stored netns:\n%s", joined)
	}
	if !strings.Contains(joined, "tuntap add dev wsess1") {
		t.Fatalf("must reuse stored TAP:\n%s", joined)
	}
	if strings.Contains(joined, "wfc") {
		t.Fatalf("recreate must not allocate a new name:\n%s", joined)
	}
}

func TestRenderNFTFailClosed(t *testing.T) {
	link := &network.Link{Name: "wfc1", Table: "warden_fc_1", GuestIP: net.ParseIP("172.25.0.2")}
	script := network.RenderNFT(link, []network.Dest{{IP: net.ParseIP("1.2.3.4")}})
	for _, want := range []string{"policy drop", `iifname "wfc1"`, "1.2.3.4", "masquerade"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
	if !strings.Contains(script, "chain forward") || !strings.Contains(script, "type filter hook forward") {
		t.Fatal(script)
	}
	if strings.Contains(script, "chain forward") && strings.Contains(script, "type filter hook forward") {
		forward := script[strings.Index(script, "chain forward"):strings.Index(script, "chain postrouting")]
		if strings.Contains(forward, "policy accept") {
			t.Fatalf("forward chain must stay drop: %s", forward)
		}
	}
}

func TestRenderNFTUsesHostVeth(t *testing.T) {
	link := &network.Link{
		Name:     "wfc1",
		HostVeth: "hfc1",
		Table:    "warden_fc_1",
		GuestIP:  net.ParseIP("172.25.0.2"),
	}
	script := network.RenderNFT(link, []network.Dest{{IP: net.ParseIP("9.9.9.9")}})
	if !strings.Contains(script, `iifname "hfc1"`) {
		t.Fatal(script)
	}
	if strings.Contains(script, `iifname "wfc1"`) {
		t.Fatalf("must not filter the TAP when a veth exists: %s", script)
	}
}

func TestRenderNFTPortSpecific(t *testing.T) {
	link := &network.Link{Name: "wfc1", HostVeth: "hfc1", Table: "warden_fc_1", GuestIP: net.ParseIP("172.25.0.2")}
	script := network.RenderNFT(link, []network.Dest{
		{IP: net.ParseIP("151.101.0.223"), Port: 443},
		{IP: net.ParseIP("1.2.3.4")},
	})
	if !strings.Contains(script, "tcp dport 443") || !strings.Contains(script, "udp dport 443") {
		t.Fatalf("missing port rules: %s", script)
	}
	if !strings.Contains(script, "ip daddr { 1.2.3.4 }") {
		t.Fatalf("host-only entry must allow any port: %s", script)
	}
	if strings.Contains(script, "ip daddr { 151.101.0.223 }") {
		t.Fatalf("ported dest must not be in the any-port set: %s", script)
	}
}

func TestTapNameLength(t *testing.T) {
	tap := &network.TAP{
		IP:     "ip",
		Run:    func(string, ...string) error { return nil },
		Lookup: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil },
	}
	link, err := tap.Setup("fc-this-is-a-very-long-identifier", network.Policy{
		DefaultPolicy: network.PolicyDeny,
		Allowlist:     []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(link.Name) > 15 || len(link.HostVeth) > 15 || len(link.NSVeth) > 15 {
		t.Fatalf("iface name too long: tap=%s host=%s ns=%s", link.Name, link.HostVeth, link.NSVeth)
	}
}

func TestTapTeardownDeletesNetns(t *testing.T) {
	var cmds []string
	tap := &network.TAP{
		IP: "ip",
		Run: func(name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
	}
	err := tap.Teardown(&network.Link{
		Name:     "wfc1",
		HostIP:   net.ParseIP("172.25.0.1"),
		Prefix:   30,
		Table:    "warden_fc_1",
		NetNS:    "warden-fc-1",
		HostVeth: "hfc1",
		UplinkNS: net.ParseIP("172.27.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"nft delete table inet warden_fc_1",
		"ip netns del warden-fc-1",
		"ip link del hfc1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
}

func TestNetNSPath(t *testing.T) {
	if got := network.NetNSPath("warden-fc-1"); got != "/var/run/netns/warden-fc-1" {
		t.Fatalf("path=%s", got)
	}
}
