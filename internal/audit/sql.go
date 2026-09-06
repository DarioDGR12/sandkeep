package audit

import (
	"context"
	"fmt"
	"time"
)

// Execer runs a SQL statement. Tests inject a recorder; production wraps
// *sql.DB so this package does not import a driver.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) error
}

// SQLSink inserts events into warden_audit.
type SQLSink struct {
	DB           Execer
	EnsureSchema bool
	Timeout      time.Duration
	ensured      bool
}

const auditDDL = `CREATE TABLE IF NOT EXISTS warden_audit (
	ts TIMESTAMPTZ NOT NULL,
	request_id TEXT NOT NULL,
	session_id TEXT,
	runtime TEXT,
	code_sha256 TEXT,
	code_bytes INTEGER,
	code_preview TEXT,
	vm_id TEXT,
	exit_code INTEGER,
	timed_out BOOLEAN,
	duration_ms BIGINT,
	error TEXT,
	auth_method TEXT,
	client_cn TEXT
)`

const auditInsert = `INSERT INTO warden_audit (
	ts, request_id, session_id, runtime, code_sha256, code_bytes, code_preview,
	vm_id, exit_code, timed_out, duration_ms, error, auth_method, client_cn
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

// Record implements Logger.
func (s *SQLSink) Record(event Event) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("audit sql: no database")
	}
	ctx := context.Background()
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	if !s.ensured && s.EnsureSchema {
		if err := s.DB.ExecContext(ctx, auditDDL); err != nil {
			return fmt.Errorf("audit sql schema: %w", err)
		}
		s.ensured = true
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if err := s.DB.ExecContext(ctx, auditInsert,
		event.Timestamp, event.RequestID, event.SessionID, event.Runtime,
		event.CodeSHA256, event.CodeBytes, event.CodePreview, event.VMID,
		event.ExitCode, event.TimedOut, event.DurationMS, event.Error,
		event.AuthMethod, event.ClientCN,
	); err != nil {
		return fmt.Errorf("audit sql insert: %w", err)
	}
	return nil
}

// StdSQL adapts the database/sql ExecContext signature (rows, err).
type StdSQL struct {
	Do func(ctx context.Context, query string, args ...any) error
}

// ExecContext implements Execer.
func (s StdSQL) ExecContext(ctx context.Context, query string, args ...any) error {
	if s.Do == nil {
		return fmt.Errorf("audit sql: nil adapter")
	}
	return s.Do(ctx, query, args...)
}
