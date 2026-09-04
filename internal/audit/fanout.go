package audit

import (
	"errors"
	"log/slog"
)

// Fanout writes every event to all sinks. Record joins the errors so a
// strict caller can fail the request if any durable sink is down.
type Fanout struct {
	Sinks []Logger
}

// Record implements Logger.
func (f Fanout) Record(event Event) error {
	var errs []error
	for _, s := range f.Sinks {
		if s == nil {
			continue
		}
		if err := s.Record(event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SlogSink emits one structured log line so platform log drains keep a copy.
type SlogSink struct {
	Log *slog.Logger
}

// Record implements Logger.
func (s SlogSink) Record(event Event) error {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	log.Info("audit",
		"request_id", event.RequestID,
		"session_id", event.SessionID,
		"runtime", event.Runtime,
		"code_sha256", event.CodeSHA256,
		"code_bytes", event.CodeBytes,
		"vm_id", event.VMID,
		"exit_code", event.ExitCode,
		"timed_out", event.TimedOut,
		"duration_ms", event.DurationMS,
		"error", event.Error,
		"auth_method", event.AuthMethod,
		"client_cn", event.ClientCN,
	)
	return nil
}
