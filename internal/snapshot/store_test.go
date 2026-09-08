package snapshot_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

func TestUnsupported(t *testing.T) {
	var s snapshot.Store = snapshot.Unsupported{}
	if _, err := s.Prepare(context.Background(), "abc", "vm-1"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("prepare: %v", err)
	}
	if err := s.Commit(context.Background(), &snapshot.Record{SessionID: "abc"}); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("commit: %v", err)
	}
	if _, err := s.Restore(context.Background(), "abc"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("restore: %v", err)
	}
	if err := s.Delete(context.Background(), "abc"); !errors.Is(err, snapshot.ErrNotImplemented) {
		t.Fatalf("delete: %v", err)
	}
}

func TestDirStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := snapshot.NewDirStore(dir)
	ctx := context.Background()

	rec, err := store.Prepare(ctx, "agent-1", "fc-9")
	if err != nil {
		t.Fatal(err)
	}
	if rec.SnapshotPath == "" || rec.MemoryPath == "" || rec.RootfsPath == "" {
		t.Fatalf("paths: %+v", rec)
	}
	if _, err := store.Restore(ctx, "agent-1"); !errors.Is(err, snapshot.ErrNotFound) {
		t.Fatalf("restore before commit: %v", err)
	}

	if err := store.Commit(ctx, rec); err == nil {
		t.Fatal("commit without files must fail")
	}

	for _, p := range []string{rec.SnapshotPath, rec.MemoryPath, rec.RootfsPath} {
		if err := os.WriteFile(p, []byte("not-empty"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	rec.HasNetwork = true
	rec.HostDevName = "wsess1"
	rec.GuestCID = 7
	if err := store.Commit(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := store.Restore(ctx, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.VMID != "fc-9" || got.HostDevName != "wsess1" || got.GuestCID != 7 || !got.HasNetwork {
		t.Fatalf("got %+v", got)
	}
	if got.SnapshotPath != rec.SnapshotPath {
		t.Fatalf("snap path %s != %s", got.SnapshotPath, rec.SnapshotPath)
	}

	if err := store.Delete(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore(ctx, "agent-1"); !errors.Is(err, snapshot.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestDirStoreRejectsEscapingMetaPaths(t *testing.T) {
	dir := t.TempDir()
	store := snapshot.NewDirStore(dir)
	ctx := context.Background()
	rec, err := store.Prepare(ctx, "s1", "vm")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rec.SnapshotPath, rec.MemoryPath, rec.RootfsPath} {
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(outside, []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	rec.SnapshotPath = outside
	if err := store.Commit(ctx, rec); err == nil {
		t.Fatal("commit must reject paths outside the session dir")
	}

	// Restore of tampered meta
	rec.SnapshotPath = filepath.Join(dir, "s1", "vm.snap")
	if err := store.Commit(ctx, rec); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "s1", "meta.json")
	raw, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), rec.MemoryPath, outside, 1)
	if err := os.WriteFile(meta, []byte(tampered), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore(ctx, "s1"); err == nil {
		t.Fatal("restore must reject escaping memory path")
	}
}

func TestDirStoreRejectsTraversal(t *testing.T) {
	store := snapshot.NewDirStore(t.TempDir())
	for _, id := range []string{"../etc", "/tmp/x", "..", "", "a/b"} {
		if _, err := store.Prepare(context.Background(), id, "vm"); err == nil {
			t.Fatalf("accepted session id %q", id)
		}
	}
}

func TestDirStoreRestoreCorrupt(t *testing.T) {
	dir := t.TempDir()
	store := snapshot.NewDirStore(dir)
	ctx := context.Background()
	rec, err := store.Prepare(ctx, "s1", "vm")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rec.SnapshotPath, rec.MemoryPath, rec.RootfsPath} {
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Commit(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rec.SnapshotPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore(ctx, "s1"); err == nil || errors.Is(err, snapshot.ErrNotFound) {
		t.Fatalf("corrupt session must not look like not-found: %v", err)
	}
	_ = filepath.Join(dir, "s1")
}
