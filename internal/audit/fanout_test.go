package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/audit"
)

func TestFanoutJoinsErrors(t *testing.T) {
	var got []string
	ok := recorder{fn: func(e audit.Event) error {
		got = append(got, e.RequestID)
		return nil
	}}
	bad := recorder{fn: func(audit.Event) error { return fmt.Errorf("sink down") }}
	f := audit.Fanout{Sinks: []audit.Logger{ok, bad}}
	err := f.Record(audit.Event{RequestID: "r1"})
	if err == nil || !strings.Contains(err.Error(), "sink down") {
		t.Fatalf("want joined sink error, got %v", err)
	}
	if len(got) != 1 || got[0] != "r1" {
		t.Fatalf("first sink must still run: %v", got)
	}
}

func TestHTTPSinkPostsJSON(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	h := audit.HTTPSink{URL: srv.URL, Token: "tok", Client: srv.Client()}
	if err := h.Record(audit.Event{RequestID: "abc", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if auth != "Bearer tok" {
		t.Fatalf("auth=%q", auth)
	}
	var ev audit.Event
	if err := json.Unmarshal([]byte(bodies[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.RequestID != "abc" {
		t.Fatalf("%+v", ev)
	}
}

func TestHTTPSinkRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	h := audit.HTTPSink{URL: srv.URL, Client: srv.Client()}
	if err := h.Record(audit.Event{RequestID: "x"}); err == nil {
		t.Fatal("non-2xx must fail")
	}
}

func TestSQLSinkInsertsAfterSchema(t *testing.T) {
	var queries []string
	db := audit.StdSQL{Do: func(_ context.Context, query string, args ...any) error {
		queries = append(queries, query)
		if strings.Contains(query, "INSERT") && len(args) != 14 {
			return fmt.Errorf("want 14 args, got %d", len(args))
		}
		return nil
	}}
	s := &audit.SQLSink{DB: db, EnsureSchema: true}
	if err := s.Record(audit.Event{RequestID: "r", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "CREATE TABLE") || !strings.Contains(queries[1], "INSERT") {
		t.Fatalf("queries=%v", queries)
	}
}

type recorder struct {
	fn func(audit.Event) error
}

func (r recorder) Record(e audit.Event) error { return r.fn(e) }
