package api

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWTVerifier validates RS256 bearer tokens against a JWKS URL.
type JWTVerifier struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Client   *http.Client
	TTL      time.Duration

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss string `json:"iss"`
	Aud any    `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Sub string `json:"sub"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
}

// Valid reports whether token is a live RS256 JWT for this verifier.
func (v *JWTVerifier) Valid(token string) bool {
	if v == nil || v.JWKSURL == "" || token == "" || strings.Count(token, ".") != 2 {
		return false
	}
	parts := strings.Split(token, ".")
	hdrJSON, err := b64JSON(parts[0])
	if err != nil {
		return false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return false
	}
	if !strings.EqualFold(hdr.Alg, "RS256") {
		return false
	}
	claimsJSON, err := b64JSON(parts[1])
	if err != nil {
		return false
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return false
	}
	now := time.Now().Unix()
	if claims.Exp != 0 && now > claims.Exp {
		return false
	}
	if claims.Nbf != 0 && now < claims.Nbf {
		return false
	}
	if strings.TrimSpace(v.Issuer) == "" || claims.Iss != v.Issuer {
		return false
	}
	if strings.TrimSpace(v.Audience) == "" || !audContains(claims.Aud, v.Audience) {
		return false
	}
	key, err := v.key(hdr.Kid)
	if err != nil || key == nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) == nil
}

func (v *JWTVerifier) key(kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ttl := v.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if v.keys == nil || time.Since(v.fetched) > ttl {
		if err := v.refreshLocked(); err != nil {
			if v.keys == nil {
				return nil, err
			}
		}
	}
	if kid == "" && len(v.keys) == 1 {
		for _, k := range v.keys {
			return k, nil
		}
	}
	return v.keys[kid], nil
}

func (v *JWTVerifier) refreshLocked() error {
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if err := checkJWKSURL(v.JWKSURL); err != nil {
		return err
	}
	resp, err := client.Get(v.JWKSURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	const maxJWKS = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil {
		return err
	}
	if len(raw) > maxJWKS {
		return fmt.Errorf("jwks: document exceeds %d bytes", maxJWKS)
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if len(doc.Keys) > 16 {
		doc.Keys = doc.Keys[:16]
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		pub, err := jwkRSA(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks: no RSA keys")
	}
	v.keys = keys
	v.fetched = time.Now()
	return nil
}

func jwkRSA(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	var e int
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("jwks: bad exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func b64JSON(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// CheckJWTConfig fail-closes incomplete JWT settings. JWKS without an
// issuer would accept any RS256 token signed by those keys.
func CheckJWTConfig(jwksURL, issuer, audience string) error {
	if strings.TrimSpace(jwksURL) == "" {
		return nil
	}
	if strings.TrimSpace(issuer) == "" {
		return fmt.Errorf("WARDEN_JWT_JWKS requires WARDEN_JWT_ISSUER")
	}
	if strings.TrimSpace(audience) == "" {
		return fmt.Errorf("WARDEN_JWT_JWKS requires a non-empty audience")
	}
	return checkJWKSURL(jwksURL)
}

func checkJWKSURL(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), "https://") && !strings.HasPrefix(strings.ToLower(raw), "http://127.0.0.1") && !strings.HasPrefix(strings.ToLower(raw), "http://localhost") {
		if strings.HasPrefix(strings.ToLower(raw), "http://") {
			return fmt.Errorf("jwks: HTTP JWKS is only allowed on loopback")
		}
	}
	return nil
}
