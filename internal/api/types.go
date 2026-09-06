package api

import "github.com/DarioDGR12/sandkeep/internal/runtime"

// ExecuteRequest is the phase-1 contract for POST /execute.
type ExecuteRequest struct {
	Code      string `json:"code"`
	Runtime   string `json:"runtime"`
	Timeout   int    `json:"timeout"`
	SessionID string `json:"session_id"`
}

// ExecuteResponse is what an agent consumes after a sandbox run.
//
// A completed guest run — including non-zero exit and timeout — is HTTP 200.
// HTTP 4xx/5xx means Warden itself rejected or failed the request.
type ExecuteResponse struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	VMID       string `json:"vm_id"`
	Runtime    string `json:"runtime"`
	RequestID  string `json:"request_id"`
	SessionID  string `json:"session_id,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	Backend    string `json:"backend"`
}

// ErrorBody is a machine-readable API error.
type ErrorBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}

const (
	CodeInvalidJSON    = "invalid_json"
	CodeInvalidRequest = "invalid_request"
	CodeUnsupported    = "unsupported_runtime"
	CodeBodyTooLarge   = "body_too_large"
	CodeMethodNotAllow = "method_not_allowed"
	CodeInternal       = "internal_error"
	CodeUnavailable    = "backend_unavailable"
	CodeUnauthorized   = "unauthorized"
	CodeBusy           = "busy"
	CodeRateLimited    = "rate_limited"
	CodeAuditFailed    = "audit_failed"
)

const (
	MaxCodeBytes    = 64 << 10 // 64 KiB of guest source
	MaxRequestBytes = 1 << 20  // 1 MiB raw HTTP body
	DefaultTimeoutS = 30
	MaxTimeoutS     = 300
	MaxSessionIDLen = 128
	HeaderRequestID = "X-Request-Id"
	HeaderAPIKey    = "X-Api-Key"
)

func resultToResponse(req ExecuteRequest, requestID string, backend string, res runtime.Result, durationMS int64) ExecuteResponse {
	return ExecuteResponse{
		Stdout:     res.Stdout,
		Stderr:     res.Stderr,
		ExitCode:   res.ExitCode,
		VMID:       res.VMID,
		Runtime:    req.Runtime,
		RequestID:  requestID,
		SessionID:  req.SessionID,
		DurationMS: durationMS,
		TimedOut:   res.TimedOut,
		Backend:    backend,
	}
}
