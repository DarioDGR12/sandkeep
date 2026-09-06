package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var errUnauthorized = fmt.Errorf("unauthorized")

// ErrAnonymousPublic is returned when Warden would listen on a non-loopback
// address without any authentication.
var ErrAnonymousPublic = fmt.Errorf("refusing to bind a public address without WARDEN_API_KEY, WARDEN_JWT_JWKS, or mTLS (set WARDEN_ALLOW_ANON=1 only for a trusted network)")

// AuthPolicy is the process-wide authentication configuration.
type AuthPolicy struct {
	APIKey       string
	AllowAnon    bool
	JWKSURL      string
	MTLS         bool
	RequireAll   bool
	MTLSSuffices bool
}

// CheckBind fails closed if addr is reachable from the network and no
// authentication is configured. Loopback binds are allowed without a key.
func CheckBind(addr, apiKey string, allowAnon bool) error {
	return CheckBindPolicy(addr, AuthPolicy{APIKey: apiKey, AllowAnon: allowAnon})
}

// CheckBindPolicy is CheckBind with JWT/mTLS as valid public-bind credentials.
func CheckBindPolicy(addr string, p AuthPolicy) error {
	if p.AllowAnon || strings.TrimSpace(p.APIKey) != "" || strings.TrimSpace(p.JWKSURL) != "" || p.MTLS {
		return nil
	}
	if isLoopbackAddr(addr) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAnonymousPublic, addr)
}

// IsLoopbackAddr reports whether addr is only reachable from this host.
func IsLoopbackAddr(addr string) bool {
	return isLoopbackAddr(addr)
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

func clientCN(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

func hasPeerCert(r *http.Request) bool {
	return r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0
}

// authorize returns the auth method on success. HTTP-layer auth is required
// only when an API key or JWT is configured. mTLS is enforced by the
// handshake when a client CA is set.
func (s *Server) authorize(r *http.Request) (method, cn string, ok bool) {
	cn = clientCN(r.TLS)
	keyOK := s.cfg.APIKey != "" && apiKeyEqual(tokenFromRequest(r), s.cfg.APIKey)
	token := tokenFromRequest(r)
	jwtOK := s.cfg.JWT != nil && looksLikeJWT(token) && s.cfg.JWT.Valid(token)
	mtlsOK := hasPeerCert(r)

	needKey := s.cfg.APIKey != ""
	needJWT := s.cfg.JWT != nil
	if !needKey && !needJWT {
		return "none", cn, true
	}

	if s.cfg.RequireAll {
		ok = (!needKey || keyOK) && (!needJWT || jwtOK)
		if s.cfg.MTLS && !mtlsOK {
			ok = false
		}
		switch {
		case keyOK && jwtOK:
			return "api_key+jwt", cn, ok
		case keyOK:
			return "api_key", cn, ok
		case jwtOK:
			return "jwt", cn, ok
		default:
			return "", cn, false
		}
	}

	if keyOK {
		return "api_key", cn, true
	}
	if jwtOK {
		return "jwt", cn, true
	}
	if mtlsOK && (s.cfg.MTLSSuffices || s.cfg.APIKey == "") {
		return "mtls", cn, true
	}
	return "", cn, false
}
