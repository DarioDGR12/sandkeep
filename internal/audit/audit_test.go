package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/audit"
)

func TestSummarizeCodeTruncatesPreview(t *testing.T) {
	code := strings.Repeat("a", audit.MaxCodePreview+32)
	sha, n, preview := audit.SummarizeCode(code)
	if n != len(code) {
		t.Fatalf("n=%d", n)
	}
	if len(preview) != audit.MaxCodePreview {
		t.Fatalf("preview=%d", len(preview))
	}
	if len(sha) != 64 {
		t.Fatalf("sha=%s", sha)
	}
}

func TestJSONLLoggerAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := audit.NewJSONLLogger(path)
	if err := l.Record(audit.Event{RequestID: "r1", SessionID: "s1", Runtime: "python", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(audit.Event{RequestID: "r2", SessionID: "s1", Runtime: "python", ExitCode: 1, Timestamp: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines=%d data=%s", len(lines), data)
	}
	var ev audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.RequestID != "r1" || ev.Timestamp.IsZero() {
		t.Fatalf("event=%+v", ev)
	}
}

func TestMemoryLoggerConcurrentSafeSnapshot(t *testing.T) {
	m := &audit.MemoryLogger{}
	if err := m.Record(audit.Event{RequestID: "a"}); err != nil {
		t.Fatal(err)
	}
	got := m.Events()
	got[0].RequestID = "mutated"
	if m.Events()[0].RequestID != "a" {
		t.Fatal("Events must return a copy")
	}
}
