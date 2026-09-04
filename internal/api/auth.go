package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var errUnauthorized = fmt.Errorf("unauthorized")

// ErrAnonymousPublic is returned when Warden would listen on a non-loopback
// address without an API key. Localhost is allowed without a key.
var ErrAnonymousPublic = fmt.Errorf("refusing to bind a public address without WARDEN_API_KEY (set WARDEN_ALLOW_ANON=1 only for a trusted network)")

// CheckBind fails closed if addr is reachable from the network and no API key
// is configured. Loopback binds and an explicit anon override are allowed.
func CheckBind(addr, apiKey string, allowAnon bool) error {
	if strings.TrimSpace(apiKey) != "" || allowAnon {
		return nil
	}
	if isLoopbackAddr(addr) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAnonymousPublic, addr)
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func tokenFromRequest(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get(HeaderAPIKey)); k != "" {
		return k
	}
	al := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(al) >= 7 && strings.EqualFold(al[:7], "bearer ") {
		return strings.TrimSpace(al[7:])
	}
	return ""
}

func apiKeyEqual(got, want string) bool {
	if want == "" {
		return false
	}
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
