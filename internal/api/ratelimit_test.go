package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/api"
	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
)

func TestFixedWindowPerKey(t *testing.T) {
	rl := api.NewFixedWindow(1, time.Minute)
	if !rl.Allow("a") {
		t.Fatal("first a")
	}
	if rl.Allow("a") {
		t.Fatal("second a must be denied")
	}
	if !rl.Allow("b") {
		t.Fatal("b is a different identity")
	}
}

func TestFixedWindowDisabled(t *testing.T) {
	var rl *api.FixedWindow
	if !rl.Allow("x") {
		t.Fatal("nil limiter must allow")
	}
	if !api.NewFixedWindow(0, time.Minute).Allow("x") {
		t.Fatal("limit 0 must allow")
	}
}

func TestExecuteRateLimitedIs429AndDoesNotBoot(t *testing.T) {
	rt := &countingRuntime{}
	filter, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.DefaultConfig("127.0.0.1:0")
	cfg.APIKey = "dev"
	cfg.Rate = api.NewFixedWindow(1, time.Minute)
	srv := api.NewServer(cfg, api.Dependencies{
		Runtime: rt,
		Limiter: resources.NoopLimiter{},
		Limits:  resources.DefaultProfile(),
		Seccomp: resources.SeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
		},
		Network: filter,
		Audit:   &audit.MemoryLogger{},
	})
	h := srv.Handler()

	body := `{"code":"x","runtime":"python"}`
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
		req.Header.Set(api.HeaderAPIKey, "dev")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := post()
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := post()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	var errBody api.ErrorBody
	if err := json.Unmarshal(second.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody.Code != api.CodeRateLimited {
		t.Fatalf("code=%q want %q (must not be busy)", errBody.Code, api.CodeRateLimited)
	}
	if rt.boots.Load() != 1 {
		t.Fatalf("boots=%d; rate limit must run before Boot", rt.boots.Load())
	}

	health := httptest.NewRequest(http.MethodGet, "/health", nil)
	hrec := httptest.NewRecorder()
	h.ServeHTTP(hrec, health)
	if hrec.Code != http.StatusOK {
		t.Fatalf("health must stay unlimited: %d", hrec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	if !api.IsLoopbackAddr("127.0.0.1:8080") {
		t.Fatal("loopback")
	}
	if api.IsLoopbackAddr("0.0.0.0:8080") {
		t.Fatal("public")
	}
}
