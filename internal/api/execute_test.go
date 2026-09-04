package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/api"
	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func testServer(t *testing.T, rt runtime.Runtime, log audit.Logger) http.Handler {
	t.Helper()
	filter, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	if log == nil {
		log = &audit.MemoryLogger{}
	}
	if rt == nil {
		rt = runtime.NewStub()
	}
	seccomp := resources.SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls:      []resources.SeccompSyscall{{Action: "SCMP_ACT_ALLOW", Names: []string{"read"}}},
	}
	srv := api.NewServer(api.DefaultConfig("127.0.0.1:0"), api.Dependencies{
		Runtime: rt,
		Limiter: resources.NoopLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Limits:  resources.DefaultProfile(),
		Seccomp: seccomp,
		Network: filter,
		Audit:   log,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return srv.Handler()
}

func TestExecuteSuccessDoesNotRunGuestCode(t *testing.T) {
	mem := &audit.MemoryLogger{}
	h := testServer(t, nil, mem)

	body := `{"code":"print(1+1)","runtime":"python","timeout":5,"session_id":"agent-1"}`
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got api.ExecuteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 0 {
		t.Fatalf("exit_code=%d", got.ExitCode)
	}
	if !strings.Contains(got.Stdout, "warden-stub") {
		t.Fatalf("expected stub banner, got %q", got.Stdout)
	}
	if strings.Contains(got.Stdout, "2") && !strings.Contains(got.Stdout, "bytes=") {
		t.Fatalf("stub must not evaluate guest code: %q", got.Stdout)
	}
	if got.SessionID != "agent-1" || got.Runtime != "python" || got.Backend != "stub" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if rec.Header().Get(api.HeaderRequestID) == "" {
		t.Fatal("missing X-Request-Id")
	}

	events := mem.Events()
	if len(events) != 1 {
		t.Fatalf("audit events=%d", len(events))
	}
	if events[0].SessionID != "agent-1" || events[0].CodeBytes != len("print(1+1)") {
		t.Fatalf("audit event=%+v", events[0])
	}
}

func TestExecuteValidation(t *testing.T) {
	h := testServer(t, nil, nil)
	cases := []struct {
		name string
		body string
		want int
		code string
	}{
		{"empty code", `{"code":"","runtime":"python"}`, http.StatusBadRequest, api.CodeInvalidRequest},
		{"whitespace code", `{"code":"   \n","runtime":"python"}`, http.StatusBadRequest, api.CodeInvalidRequest},
		{"bad runtime", `{"code":"x","runtime":"ruby"}`, http.StatusBadRequest, api.CodeInvalidRequest},
		{"timeout high", `{"code":"x","runtime":"python","timeout":9999}`, http.StatusBadRequest, api.CodeInvalidRequest},
		{"bad json", `{`, http.StatusBadRequest, api.CodeInvalidJSON},
		{"unknown field", `{"code":"x","runtime":"python","nope":1}`, http.StatusBadRequest, api.CodeInvalidJSON},
		{"trailing junk", `{"code":"x","runtime":"python"}{"x":1}`, http.StatusBadRequest, api.CodeInvalidJSON},
		{"bad session", `{"code":"x","runtime":"python","session_id":"../etc"}`, http.StatusBadRequest, api.CodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
			var errBody api.ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatal(err)
			}
			if errBody.Code != tc.code {
				t.Fatalf("code=%q want=%q", errBody.Code, tc.code)
			}
		})
	}
}

func TestExecuteRejectsAreAudited(t *testing.T) {
	mem := &audit.MemoryLogger{}
	h := testServer(t, nil, mem)
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"","runtime":"python","session_id":"probe"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
	events := mem.Events()
	if len(events) != 1 {
		t.Fatalf("audit events=%d", len(events))
	}
	if events[0].SessionID != "probe" || events[0].Error == "" {
		t.Fatalf("event=%+v", events[0])
	}
}

func TestExecuteMethodNotAllowed(t *testing.T) {
	h := testServer(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/execute", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestExecuteBodyTooLarge(t *testing.T) {
	h := testServer(t, nil, nil)
	payload := `{"code":"` + strings.Repeat("a", api.MaxRequestBytes+8) + `","runtime":"python"}`
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExecuteAuditStrictIs500(t *testing.T) {
	filter, err := network.NewStaticFilter(network.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(api.DefaultConfig("127.0.0.1:0"), api.Dependencies{
		Runtime:     runtime.NewStub(),
		Limiter:     resources.NoopLimiter{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Limits:      resources.DefaultProfile(),
		Seccomp:     resources.SeccompProfile{DefaultAction: "SCMP_ACT_ERRNO"},
		Network:     filter,
		Audit:       failAudit{},
		AuditStrict: true,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), api.CodeAuditFailed) {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

type failAudit struct{}

func (failAudit) Record(audit.Event) error { return fmt.Errorf("sink down") }

func TestExecuteBusyIs429(t *testing.T) {
	h := testServer(t, busyRuntime{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"code":"x","runtime":"python"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var errBody api.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody.Code != api.CodeBusy {
		t.Fatalf("code=%q", errBody.Code)
	}
}

type busyRuntime struct{}

func (busyRuntime) Name() string { return "busy" }

func (busyRuntime) Boot(context.Context, runtime.Spec) (runtime.Instance, error) {
	return nil, runtime.ErrBusy
}

func TestExecuteFirecrackerUnavailable(t *testing.T) {
	h := testServer(t, runtime.NewFirecracker(), nil)
	body := `{"code":"print(1)","runtime":"python"}`
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHealth(t *testing.T) {
	h := testServer(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestPython3Alias(t *testing.T) {
	h := testServer(t, nil, nil)
	body := `{"code":"x","runtime":"python3"}`
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got api.ExecuteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Runtime != "python" {
		t.Fatalf("runtime=%q", got.Runtime)
	}
}

func TestDefaultTimeoutAccepted(t *testing.T) {
	h := testServer(t, nil, nil)
	body := `{"code":"x","runtime":"node"}`
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
