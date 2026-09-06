package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/api"
	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestCheckBind(t *testing.T) {
	if err := api.CheckBind("127.0.0.1:8080", "", false); err != nil {
		t.Fatalf("loopback without key must be allowed: %v", err)
	}
	if err := api.CheckBind("localhost:8080", "", false); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckBind("0.0.0.0:8080", "", false); !errors.Is(err, api.ErrAnonymousPublic) {
		t.Fatalf("public bind without key must fail closed: %v", err)
	}
	if err := api.CheckBind(":8080", "", false); !errors.Is(err, api.ErrAnonymousPublic) {
		t.Fatalf("empty host is public: %v", err)
	}
	if err := api.CheckBind("0.0.0.0:8080", "secret", false); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckBind("0.0.0.0:8080", "", true); err != nil {
		t.Fatal(err)
	}
}

type countingRuntime struct {
	boots atomic.Int32
}

func (c *countingRuntime) Name() string { return "count" }

func (c *countingRuntime) Boot(_ context.Context, spec runtime.Spec) (runtime.Instance, error) {
	c.boots.Add(1)
	return runtime.NewStub().Boot(context.Background(), spec)
}

func authServer(t *testing.T, key string, rt runtime.Runtime) http.Handler {
	t.Helper()
	filter, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	if rt == nil {
		rt = runtime.NewStub()
	}
	cfg := api.DefaultConfig("127.0.0.1:0")
	cfg.APIKey = key
	srv := api.NewServer(cfg, api.Dependencies{
		Runtime: rt,
		Limiter: resources.ProfileLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Limits:  resources.DefaultProfile(),
		Seccomp: resources.SeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
		},
		Network: filter,
		Audit:   &audit.MemoryLogger{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return srv.Handler()
}

func TestExecuteRequiresAPIKey(t *testing.T) {
	rt := &countingRuntime{}
	h := authServer(t, "s3cret", rt)

	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"print(1)","runtime":"python"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var errBody api.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody.Code != api.CodeUnauthorized {
		t.Fatalf("code=%q", errBody.Code)
	}
	if rt.boots.Load() != 0 {
		t.Fatal("unauthorized request must not boot a VM")
	}

	req = httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	req.Header.Set(api.HeaderAPIKey, "wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key status=%d", rec.Code)
	}
	if rt.boots.Load() != 0 {
		t.Fatal("wrong key must not boot")
	}

	req = httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	req.Header.Set(api.HeaderAPIKey, "s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("good X-Api-Key status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer status=%d", rec.Code)
	}
	if rt.boots.Load() != 2 {
		t.Fatalf("boots=%d", rt.boots.Load())
	}
}

func TestHealthDoesNotRequireAPIKey(t *testing.T) {
	h := authServer(t, "s3cret", nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health must stay public: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExecuteAcceptsJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "n": n, "e": e}},
		})
	}))
	t.Cleanup(jwks.Close)

	filter, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.DefaultConfig("127.0.0.1:0")
	cfg.JWT = &api.JWTVerifier{
		JWKSURL:  jwks.URL,
		Issuer:   "https://issuer.test",
		Audience: "warden",
		Client:   jwks.Client(),
	}
	srv := api.NewServer(cfg, api.Dependencies{
		Runtime: runtime.NewStub(),
		Limiter: resources.ProfileLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Limits:  resources.DefaultProfile(),
		Seccomp: resources.SeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
		},
		Network: filter,
		Audit:   &audit.MemoryLogger{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing jwt status=%d", rec.Code)
	}

	tok := signJWT(t, key, "k1", map[string]any{
		"iss": "https://issuer.test",
		"aud": "warden",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req = httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwt status=%d body=%s", rec.Code, rec.Body.String())
	}
}
