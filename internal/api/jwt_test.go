package api_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/api"
)

func TestJWTVerifierRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "alg": "RS256", "n": n, "e": e, "use": "sig",
			}},
		})
	}))
	t.Cleanup(jwks.Close)

	v := &api.JWTVerifier{
		JWKSURL:  jwks.URL,
		Issuer:   "https://issuer.test",
		Audience: "warden",
		Client:   jwks.Client(),
	}
	good := signJWT(t, key, "k1", map[string]any{
		"iss": "https://issuer.test",
		"aud": "warden",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "agent",
	})
	if !v.Valid(good) {
		t.Fatal("valid token rejected")
	}
	expired := signJWT(t, key, "k1", map[string]any{
		"iss": "https://issuer.test",
		"aud": "warden",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	if v.Valid(expired) {
		t.Fatal("expired token accepted")
	}
	wrongIss := signJWT(t, key, "k1", map[string]any{
		"iss": "https://evil.test",
		"aud": "warden",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if v.Valid(wrongIss) {
		t.Fatal("wrong issuer accepted")
	}
	if v.Valid("not-a-jwt") {
		t.Fatal("opaque token accepted")
	}
	wrongAud := signJWT(t, key, "k1", map[string]any{
		"iss": "https://issuer.test",
		"aud": "other",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if v.Valid(wrongAud) {
		t.Fatal("wrong audience accepted")
	}
	noIss := &api.JWTVerifier{JWKSURL: jwks.URL, Audience: "warden", Client: jwks.Client()}
	if noIss.Valid(good) {
		t.Fatal("empty issuer must reject every token")
	}
}

func TestCheckJWTConfig(t *testing.T) {
	if err := api.CheckJWTConfig("", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckJWTConfig("https://issuer.test/jwks", "", "warden"); err == nil {
		t.Fatal("JWKS without issuer must fail")
	}
	if err := api.CheckJWTConfig("http://evil.example/jwks", "iss", "warden"); err == nil {
		t.Fatal("non-loopback HTTP JWKS must fail")
	}
	if err := api.CheckJWTConfig("https://issuer.test/jwks", "iss", "warden"); err != nil {
		t.Fatal(err)
	}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(pl)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}
