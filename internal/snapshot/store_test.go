package snapshot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

func TestUnsupported(t *testing.T) {
	var s snapshot.Store = snapshot.Unsupported{}
	if _, err := s.Save(context.Background(), "abc", "vm-1"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("save: %v", err)
	}
	if _, err := s.Restore(context.Background(), "abc"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("restore: %v", err)
	}
	if err := s.Delete(context.Background(), "abc"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("delete: %v", err)
	}
}
