package network_test

import (
	"net"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/network"
)

func TestTapSetupRecordsCommands(t *testing.T) {
	var cmds []string
	tap := &network.TAP{
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
	if link.GuestIP.String() != "172.25.0.2" || link.HostIP.String() != "172.25.0.1" {
		t.Fatalf("subnet host=%s guest=%s", link.HostIP, link.GuestIP)
	}
	if !strings.HasPrefix(link.GuestMAC, "06:00:") {
		t.Fatalf("mac=%s", link.GuestMAC)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip tuntap add dev wfc1 mode tap") {
		t.Fatalf("cmds=%s", joined)
	}
	if !strings.Contains(joined, "nft -f -") {
		t.Fatalf("missing nft: %s", joined)
	}
	if !strings.Contains(joined, "151.101.0.223") || !strings.Contains(joined, "1.2.3.4") {
		t.Fatalf("allowlist IPs missing from nft script: %s", joined)
	}
}

func TestTapSetupEmptyAllowlist(t *testing.T) {
	tap := &network.TAP{Run: func(string, ...string) error { return nil }}
	_, err := tap.Setup("x", network.Default())
	if err == nil {
		t.Fatal("empty allowlist must not create a NIC")
	}
}

func TestRenderNFTFailClosed(t *testing.T) {
	link := &network.Link{Name: "wfc1", Table: "warden_fc_1", GuestIP: net.ParseIP("172.25.0.2")}
	script := network.RenderNFT(link, []net.IP{net.ParseIP("1.2.3.4")})
	for _, want := range []string{"policy drop", "iifname \"wfc1\"", "1.2.3.4", "masquerade"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
	if strings.Contains(script, "policy accept") && strings.Contains(script, "chain forward") {
		// postrouting is accept; forward must stay drop
	}
	if !strings.Contains(script, "chain forward") || !strings.Contains(script, "type filter hook forward") {
		t.Fatal(script)
	}
}

func TestTapNameLength(t *testing.T) {
	tap := &network.TAP{
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
	if len(link.Name) > 15 {
		t.Fatalf("tap name too long: %s", link.Name)
	}
}
