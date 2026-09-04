package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
		Limiter: resources.NoopLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Limits:  resources.DefaultProfile(),
		Seccomp: resources.SeccompProfile{DefaultAction: "SCMP_ACT_ERRNO"},
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
