// Package api is the HTTP surface of Warden. Handlers stay thin: decode,
// validate, call the sandbox pipeline, write JSON. Isolation details live
// under internal/runtime, internal/resources, and internal/network.
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

// Config is process-wide HTTP settings.
type Config struct {
	Addr            string
	APIKey          string
	JWT             *JWTVerifier
	TLS             *tls.Config
	MTLS            bool
	MTLSSuffices    bool
	RequireAll      bool
	Rate            *FixedWindow
	HealthMinimal   bool
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DefaultConfig binds all interfaces and honors cloud PORT injection via Addr.
func DefaultConfig(addr string) Config {
	return Config{
		Addr:            addr,
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    (MaxTimeoutS + 15) * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
}

// Dependencies are the isolation and observability backends. All of them are
// interfaces so tests inject fakes and production can swap Firecracker in.
type Dependencies struct {
	Runtime     runtime.Runtime
	Limiter     resources.Limiter
	Limits      resources.Profile
	Seccomp     resources.SeccompProfile
	Network     network.Filter
	Audit       audit.Logger
	AuditStrict bool
	Snapshots   snapshot.Store
	Log         *slog.Logger
	BootTimeout time.Duration
	QueueWait   time.Duration
}

// Server is the HTTP API.
type Server struct {
	cfg  Config
	deps Dependencies
	http *http.Server
}

// NewServer wires routes and middleware. Snapshots may be nil (treated as Unsupported).
func NewServer(cfg Config, deps Dependencies) *Server {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Snapshots == nil {
		deps.Snapshots = snapshot.Unsupported{}
	}
	s := &Server{cfg: cfg, deps: deps}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/execute", s.handleExecute)

	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.middleware(mux),
		TLSConfig:         cfg.TLS,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
	return s
}

// Handler exposes the fully wrapped mux for tests (httptest).
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// ListenAndServe binds cfg.Addr. When TLS is configured it serves HTTPS
// (and mTLS if ClientAuth is RequireAndVerifyClientCert).
func (s *Server) ListenAndServe() error {
	if s.cfg.TLS != nil {
		ln, err := net.Listen("tcp", s.cfg.Addr)
		if err != nil {
			return err
		}
		return s.http.Serve(tls.NewListener(ln, s.cfg.TLS))
	}
	return s.http.ListenAndServe()
}

// Shutdown drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get(HeaderRequestID)
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set(HeaderRequestID, requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r = r.WithContext(context.WithValue(r.Context(), ctxRequestID, requestID))

		defer func() {
			if rec := recover(); rec != nil {
				s.deps.Log.Error("panic recovered", "request_id", requestID, "panic", rec)
				writeError(w, requestID, http.StatusInternalServerError, CodeInternal, "internal error")
			}
		}()

		rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		if r.URL.Path != "/health" {
			method, cn, ok := s.authorize(r)
			if !ok {
				_ = s.recordAudit(r.Context(), ExecuteRequest{}, requestID, runtime.Result{}, 0, errUnauthorized)
				writeError(rw, requestID, http.StatusUnauthorized, CodeUnauthorized, "unauthorized")
				s.deps.Log.Info("http",
					"method", r.Method,
					"path", r.URL.Path,
					"status", rw.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", requestID,
					"remote", remoteHost(r),
				)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxAuthMethod, method))
			r = r.WithContext(context.WithValue(r.Context(), ctxClientCN, cn))
			if s.cfg.Rate != nil && !s.cfg.Rate.Allow(rateKey(r, method, cn)) {
				writeError(rw, requestID, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
				s.deps.Log.Info("http",
					"method", r.Method,
					"path", r.URL.Path,
					"status", rw.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", requestID,
					"remote", remoteHost(r),
				)
				return
			}
		}
		next.ServeHTTP(rw, r)
		s.deps.Log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", requestID,
			"remote", remoteHost(r),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type ctxKey int

const (
	ctxRequestID  ctxKey = 1
	ctxAuthMethod ctxKey = 2
	ctxClientCN   ctxKey = 3
)

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func authMethodFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxAuthMethod).(string); ok {
		return v
	}
	return ""
}

func clientCNFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxClientCN).(string); ok {
		return v
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(body)
}

func writeError(w http.ResponseWriter, requestID string, status int, code, msg string) {
	writeJSON(w, status, ErrorBody{Error: msg, Code: code, RequestID: requestID})
}
