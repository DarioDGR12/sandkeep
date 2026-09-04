// Package audit records every sandbox execution: what ran, when, for which
// session, and how it finished. Agents (and humans) need this trail when a
// run misbehaves.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// MaxCodePreview is the maximum number of code bytes stored verbatim in a
// log entry. The full payload is still identified by CodeSHA256.
const MaxCodePreview = 256

// Event is one executed (or attempted) sandbox job.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id"`
	SessionID   string    `json:"session_id"`
	Runtime     string    `json:"runtime"`
	CodeSHA256  string    `json:"code_sha256"`
	CodeBytes   int       `json:"code_bytes"`
	CodePreview string    `json:"code_preview,omitempty"`
	VMID        string    `json:"vm_id,omitempty"`
	ExitCode    int       `json:"exit_code"`
	TimedOut    bool      `json:"timed_out"`
	DurationMS  int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
	AuthMethod  string    `json:"auth_method,omitempty"`
	ClientCN    string    `json:"client_cn,omitempty"`
}

// Logger persists audit events. Implementations must be safe for concurrent use.
type Logger interface {
	Record(event Event) error
}

// SummarizeCode fills hash, length, and a bounded preview so we can answer
// "what ran?" without writing unbounded agent output into the log.
func SummarizeCode(code string) (sha string, n int, preview string) {
	sum := sha256.Sum256([]byte(code))
	sha = hex.EncodeToString(sum[:])
	n = len(code)
	preview = code
	if len(preview) > MaxCodePreview {
		preview = preview[:MaxCodePreview]
	}
	return sha, n, preview
}
