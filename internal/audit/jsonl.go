package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// JSONLLogger appends one JSON object per line. Concurrent Record calls are
// serialized with a mutex so lines are never interleaved.
//
// On Render (and most PaaS hosts) the local disk is ephemeral. Treat this
// file as a local buffer; a later phase should ship events to durable storage.
type JSONLLogger struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

// NewJSONLLogger writes to path, creating the file if needed.
func NewJSONLLogger(path string) *JSONLLogger {
	return &JSONLLogger{path: path, now: time.Now}
}

// Record appends event. Timestamp is set if the caller left it zero.
func (l *JSONLLogger) Record(event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = l.now().UTC()
	}
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit marshal: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("audit open %s: %w", l.path, err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	return nil
}
