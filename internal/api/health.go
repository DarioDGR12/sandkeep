package api

import "net/http"

type healthResponse struct {
	Status  string `json:"status"`
	Backend string `json:"backend,omitempty"`
	Ready   bool   `json:"ready"`
}

type readier interface {
	Ready() error
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, requestIDFrom(r.Context()), http.StatusMethodNotAllowed, CodeMethodNotAllow, "method not allowed")
		return
	}
	ready := true
	if rdy, ok := s.deps.Runtime.(readier); ok {
		ready = rdy.Ready() == nil
	}
	status := "ok"
	if !ready {
		status = "degraded"
	}
	if s.cfg.HealthMinimal {
		writeJSON(w, http.StatusOK, healthResponse{Status: status, Ready: ready})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  status,
		Backend: s.deps.Runtime.Name(),
		Ready:   ready,
	})
}
