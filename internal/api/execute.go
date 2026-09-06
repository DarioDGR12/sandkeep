package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		_ = s.recordAudit(r.Context(), req, requestID, runtime.Result{}, 0, err)
		writeError(w, requestID, http.StatusBadRequest, CodeInvalidJSON, "invalid JSON body")
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		trail := fmt.Errorf("trailing data after JSON object")
		_ = s.recordAudit(r.Context(), req, requestID, runtime.Result{}, 0, trail)
		writeError(w, requestID, http.StatusBadRequest, CodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validateExecute(&req); err != nil {
		_ = s.recordAudit(r.Context(), req, requestID, runtime.Result{}, 0, err)
		writeError(w, requestID, http.StatusBadRequest, CodeInvalidRequest, err.Error())
		return
	}

	started := time.Now()
	res, execErr := s.run(r.Context(), req)
	durationMS := time.Since(started).Milliseconds()

	auditErr := s.recordAudit(r.Context(), req, requestID, res, durationMS, execErr)
	if auditErr != nil && s.deps.AuditStrict {
		writeError(w, requestID, http.StatusInternalServerError, CodeAuditFailed, "audit sink failed")
		return
	}

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

	// Validate profiles before Boot. Cgroup attach needs a live VMM PID and
	// happens inside Firecracker.Boot — this call must not claim it did.
	if s.deps.Limiter != nil {
		if err := s.deps.Limiter.Apply("pending-vm", spec.Limits, spec.Seccomp); err != nil {
			return runtime.Result{}, err
		}
	}

	bootTimeout := s.bootTimeout()
	if s.deps.QueueWait > 0 {
		bootTimeout += s.deps.QueueWait
	}
	bootCtx, bootCancel := context.WithTimeout(ctx, bootTimeout)
	defer bootCancel()

	inst, err := s.deps.Runtime.Boot(bootCtx, spec)
	if err != nil {
		if bootCtx.Err() != nil {
			return runtime.Result{}, fmt.Errorf("%w: %v", runtime.ErrBootTimeout, err)
		}
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

	execCtx, execCancel := context.WithTimeout(ctx, time.Duration(req.Timeout)*time.Second)
	defer execCancel()
	return inst.Execute(execCtx, runtime.ExecRequest{
		Code:    req.Code,
		Timeout: time.Duration(req.Timeout) * time.Second,
	})
}

func (s *Server) bootTimeout() time.Duration {
	if s.deps.BootTimeout > 0 {
		return s.deps.BootTimeout
	}
	return 20 * time.Second
}

func (s *Server) recordAudit(ctx context.Context, req ExecuteRequest, requestID string, res runtime.Result, durationMS int64, execErr error) error {
	if s.deps.Audit == nil {
		return nil
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
		AuthMethod:  authMethodFrom(ctx),
		ClientCN:    clientCNFrom(ctx),
	}
	if execErr != nil {
		ev.Error = execErr.Error()
		if ev.ExitCode == 0 {
			ev.ExitCode = -1
		}
	}
	if err := s.deps.Audit.Record(ev); err != nil {
		s.deps.Log.Error("audit record failed", "request_id", requestID, "err", err)
		return err
	}
	return nil
}

func mapExecError(err error) (status int, code, msg string) {
	if errors.Is(err, runtime.ErrNotImplemented) || errors.Is(err, runtime.ErrMissingAssets) {
		return http.StatusServiceUnavailable, CodeUnavailable, "firecracker backend is not ready"
	}
	if errors.Is(err, runtime.ErrBusy) {
		return http.StatusTooManyRequests, CodeBusy, "too many concurrent VMs"
	}
	if errors.Is(err, runtime.ErrBootTimeout) {
		return http.StatusGatewayTimeout, CodeBootTimeout, "VM boot timed out"
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
