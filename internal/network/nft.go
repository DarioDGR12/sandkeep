package network

import (
	"fmt"
	"net"
	"strings"
)

// RenderNFT builds a fail-closed inet table on the host-visible iface
// (the uplink veth when the TAP lives in a netns). Only forwarded packets
// to the allowlisted destinations (plus established replies) pass.
func RenderNFT(link *Link, allow []net.IP) string {
	dev := link.FilterIface()
	var v4, v6 []string
	for _, ip := range allow {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", link.Table)
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    iifname %q ct state established,related accept\n", dev)
	fmt.Fprintf(&b, "    oifname %q ct state established,related accept\n", dev)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "    iifname %q ip daddr { %s } accept\n", dev, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "    iifname %q ip6 daddr { %s } accept\n", dev, strings.Join(v6, ", "))
	}
	b.WriteString("  }\n")
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority 100; policy accept;\n")
	fmt.Fprintf(&b, "    oifname != %q ip saddr %s masquerade\n", dev, link.GuestIP)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}
