// Package network enforces guest egress: the sandbox may only open outbound
// connections to an explicit allowlist. The default policy is deny.
//
// Enforcement in phase 2 will sit on the host TAP/iptables path in front of
// the microVM. Phase 1 loads, validates, and consults the policy so the
// execute pipeline already has a single place to ask "is this dial allowed?".
package network

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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

// Allows reports whether a guest dial to hostport (host, host:port, or CIDR-ish
// host) is permitted. Matching is exact host or host:port against the allowlist.
func (f *StaticFilter) Allows(hostport string) bool {
	hostport = strings.TrimSpace(strings.ToLower(hostport))
	if hostport == "" {
		return false
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	for _, raw := range f.policy.Allowlist {
		entry := strings.TrimSpace(strings.ToLower(raw))
		if entry == hostport || entry == host {
			return true
		}
		entryHost, _, err := net.SplitHostPort(entry)
		if err == nil && (entryHost == host || entry == hostport) {
			return true
		}
	}
	return false
}
