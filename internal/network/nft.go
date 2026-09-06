package network

import (
	"fmt"
	"net"
	"strings"
)

// Dest is one allowlisted destination. Port 0 means any port on IP.
type Dest struct {
	IP   net.IP
	Port int
}

// RenderNFT builds a fail-closed inet table on the host-visible iface
// (the uplink veth when the TAP lives in a netns). Only forwarded packets
// to the allowlisted destinations (plus established replies) pass.
// Entries with a port require tcp/udp dport; entries without a port allow
// all ports to that IP (host-only allowlist).
func RenderNFT(link *Link, allow []Dest) string {
	dev := link.FilterIface()
	var any4, any6 []string
	var port4, port6 []Dest
	for _, d := range allow {
		if d.IP == nil {
			continue
		}
		if d.Port > 0 {
			if d.IP.To4() != nil {
				port4 = append(port4, d)
			} else {
				port6 = append(port6, d)
			}
			continue
		}
		if d.IP.To4() != nil {
			any4 = append(any4, d.IP.String())
		} else {
			any6 = append(any6, d.IP.String())
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", link.Table)
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    iifname %q ct state established,related accept\n", dev)
	fmt.Fprintf(&b, "    oifname %q ct state established,related accept\n", dev)
	if len(any4) > 0 {
		fmt.Fprintf(&b, "    iifname %q ip daddr { %s } accept\n", dev, strings.Join(any4, ", "))
	}
	if len(any6) > 0 {
		fmt.Fprintf(&b, "    iifname %q ip6 daddr { %s } accept\n", dev, strings.Join(any6, ", "))
	}
	for _, d := range port4 {
		fmt.Fprintf(&b, "    iifname %q ip daddr %s tcp dport %d accept\n", dev, d.IP.String(), d.Port)
		fmt.Fprintf(&b, "    iifname %q ip daddr %s udp dport %d accept\n", dev, d.IP.String(), d.Port)
	}
	for _, d := range port6 {
		fmt.Fprintf(&b, "    iifname %q ip6 daddr %s tcp dport %d accept\n", dev, d.IP.String(), d.Port)
		fmt.Fprintf(&b, "    iifname %q ip6 daddr %s udp dport %d accept\n", dev, d.IP.String(), d.Port)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority 100; policy accept;\n")
	fmt.Fprintf(&b, "    oifname != %q ip saddr %s masquerade\n", dev, link.GuestIP)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}
