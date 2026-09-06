// Package network enforces guest egress: the sandbox may only open outbound
// connections to an explicit allowlist. The default policy is deny.
//
// Enforcement sits on the host veth (nft fail-closed) in front of the
// microVM TAP, which lives in a dedicated netns. The in-process Allows()
// check is the same policy the TAP factory resolves into nft rules.
package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

const PolicyDeny = "deny"
const PolicyAllow = "allow"

// Policy is a fail-closed egress filter.
type Policy struct {
	DefaultPolicy string   `json:"default_policy"`
	Allowlist     []string `json:"allowlist"`
}

// Filter is the interface the execute pipeline uses.
type Filter interface {
	Policy() Policy
	Allows(hostport string) bool
}

// StaticFilter is an immutable policy loaded at process start.
type StaticFilter struct {
	policy Policy
}

// Fingerprint is a stable hash of the allowlist. Used so a session snapshot
// is not restored after the egress policy changes.
func (p Policy) Fingerprint() string {
	entries := append([]string(nil), p.Allowlist...)
	for i := range entries {
		entries[i] = strings.TrimSpace(strings.ToLower(entries[i]))
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

// Default returns a deny-all policy with an empty allowlist.
func Default() Policy {
	return Policy{DefaultPolicy: PolicyDeny, Allowlist: nil}
}

// Load reads configs/egress.json. Unknown extra fields are ignored.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read egress policy %s: %w", path, err)
	}
	p := Default()
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse egress policy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("invalid egress policy %s: %w", path, err)
	}
	return p, nil
}

// Validate rejects open-by-default policies and empty allowlist entries.
func (p Policy) Validate() error {
	switch p.DefaultPolicy {
	case PolicyDeny:
	case PolicyAllow:
		return fmt.Errorf("default_policy %q is not allowed; Warden is fail-closed", p.DefaultPolicy)
	default:
		return fmt.Errorf("default_policy %q is unknown", p.DefaultPolicy)
	}
	for i, entry := range p.Allowlist {
		if strings.TrimSpace(entry) == "" {
			return fmt.Errorf("allowlist[%d] is empty", i)
		}
	}
	return nil
}

// NewStaticFilter wraps a validated policy.
func NewStaticFilter(p Policy) (*StaticFilter, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &StaticFilter{policy: p}, nil
}

// Policy returns a copy of the loaded rules.
func (f *StaticFilter) Policy() Policy {
	cp := f.policy
	if f.policy.Allowlist != nil {
		cp.Allowlist = append([]string(nil), f.policy.Allowlist...)
	}
	return cp
}

// Allows reports whether a guest dial to hostport is permitted.
// A host-only allowlist entry matches any port. A host:port entry
// matches only that port (pypi.org:443 does not allow :80).
func (f *StaticFilter) Allows(hostport string) bool {
	hostport = strings.TrimSpace(strings.ToLower(hostport))
	if hostport == "" {
		return false
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = ""
	}
	for _, raw := range f.policy.Allowlist {
		entry := strings.TrimSpace(strings.ToLower(raw))
		eHost, ePort, eerr := net.SplitHostPort(entry)
		if eerr != nil {
			if entry == host || entry == hostport {
				return true
			}
			continue
		}
		if eHost == host && ePort == port {
			return true
		}
	}
	return false
}
