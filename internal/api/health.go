package api

import "net/http"

type healthResponse struct {
	Status  string `json:"status"`
	Backend string `json:"backend"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, requestIDFrom(r.Context()), http.StatusMethodNotAllowed, CodeMethodNotAllow, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Backend: s.deps.Runtime.Name(),
	})
}
