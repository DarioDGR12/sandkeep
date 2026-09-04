package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/audit"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	if r.Method != http.MethodPost {
		writeError(w, requestID, http.StatusMethodNotAllowed, CodeMethodNotAllow, "POST required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	defer r.Body.Close()

	var req ExecuteRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if maxBytesExceeded(err) {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "request body too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, CodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validateExecute(&req); err != nil {
		writeError(w, requestID, http.StatusBadRequest, CodeInvalidRequest, err.Error())
		return
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.Timeout)*time.Second)
	defer cancel()

	res, execErr := s.run(ctx, req)
	durationMS := time.Since(started).Milliseconds()

	s.recordAudit(req, requestID, res, durationMS, execErr)

	if execErr != nil {
		s.deps.Log.Error("execute failed",
			"request_id", requestID,
			"session_id", req.SessionID,
			"err", execErr,
		)
		status, code, msg := mapExecError(execErr)
		writeError(w, requestID, status, code, msg)
		return
	}

	writeJSON(w, http.StatusOK, resultToResponse(req, requestID, s.deps.Runtime.Name(), res, durationMS))
}

func (s *Server) run(ctx context.Context, req ExecuteRequest) (runtime.Result, error) {
	spec := runtime.Spec{
		Language:  req.Runtime,
		SessionID: req.SessionID,
		Limits:    s.deps.Limits,
		Seccomp:   s.deps.Seccomp,
		Network:   s.deps.Network.Policy(),
	}

	// Resource limits wrap the VM process. In phase 1 this is a staged noop
	// so the call order matches the future jailer integration.
	if s.deps.Limiter != nil {
		if err := s.deps.Limiter.Apply("pending-vm", spec.Limits, spec.Seccomp); err != nil {
			return runtime.Result{}, err
		}
	}

	inst, err := s.deps.Runtime.Boot(ctx, spec)
	if err != nil {
		return runtime.Result{}, err
	}
	// Destroy must run even if Execute times out or panics.
	defer func() {
		destroyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := inst.Destroy(destroyCtx); err != nil {
			s.deps.Log.Error("vm destroy failed", "vm_id", inst.ID(), "err", err)
		}
	}()

	return inst.Execute(ctx, runtime.ExecRequest{
		Code:    req.Code,
		Timeout: time.Duration(req.Timeout) * time.Second,
	})
}

func (s *Server) recordAudit(req ExecuteRequest, requestID string, res runtime.Result, durationMS int64, execErr error) {
	if s.deps.Audit == nil {
		return
	}
	hash, n, preview := audit.SummarizeCode(req.Code)
	ev := audit.Event{
		RequestID:   requestID,
		SessionID:   req.SessionID,
		Runtime:     req.Runtime,
		CodeSHA256:  hash,
		CodeBytes:   n,
		CodePreview: preview,
		VMID:        res.VMID,
		ExitCode:    res.ExitCode,
		TimedOut:    res.TimedOut,
		DurationMS:  durationMS,
	}
	if execErr != nil {
		ev.Error = execErr.Error()
		if ev.ExitCode == 0 {
			ev.ExitCode = -1
		}
	}
	if err := s.deps.Audit.Record(ev); err != nil {
		s.deps.Log.Error("audit record failed", "request_id", requestID, "err", err)
	}
}

func mapExecError(err error) (status int, code, msg string) {
	if errors.Is(err, runtime.ErrNotImplemented) {
		return http.StatusServiceUnavailable, CodeUnavailable, "firecracker backend is not wired yet"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, CodeInternal, "execution timed out before a VM result"
	}
	return http.StatusInternalServerError, CodeInternal, "failed to execute in sandbox"
}

// maxBytesExceeded reports a MaxBytesReader cutoff. Incomplete JSON also
// surfaces as io.ErrUnexpectedEOF; that must stay a 400, not a 413.
func maxBytesExceeded(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}
