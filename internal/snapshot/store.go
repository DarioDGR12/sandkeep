// Package snapshot persists Firecracker microVM images so a session_id
// can resume instead of cold-booting every /execute call.
//
// An empty or Unsupported store keeps the old behavior: session_id is
// logged and ignored. DirStore writes snap + memory + dirty rootfs under
// a dedicated directory that must NOT live inside the per-VM work dir
// (Destroy deletes that tree).
package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotImplemented is returned by Unsupported.
var ErrNotImplemented = errors.New("snapshot: not implemented")

// ErrNotFound means this session has no committed snapshot.
var ErrNotFound = errors.New("snapshot: not found")

// Record is a saved VM image tied to an agent session. SnapshotPath and
// MemoryPath are what Firecracker wrote; RootfsPath is the dirty ext4
// the snapshot's virtio-blk still points at. Network fields are the TAP
// names/addresses baked into the snap (host_dev_name cannot change).
type Record struct {
	SessionID     string    `json:"session_id"`
	VMID          string    `json:"vm_id"`
	Path          string    `json:"path"`
	SnapshotPath  string    `json:"snapshot_path"`
	MemoryPath    string    `json:"memory_path"`
	RootfsPath    string    `json:"rootfs_path,omitempty"`
	GuestCID      uint32    `json:"guest_cid,omitempty"`
	HasNetwork    bool      `json:"has_network"`
	HostDevName   string    `json:"host_dev_name,omitempty"`
	GuestMAC      string    `json:"guest_mac,omitempty"`
	GuestIP       string    `json:"guest_ip,omitempty"`
	HostIP        string    `json:"host_ip,omitempty"`
	NetNS         string    `json:"netns,omitempty"`
	NetNSPath     string    `json:"netns_path,omitempty"`
	HostVeth      string    `json:"host_veth,omitempty"`
	NSVeth        string    `json:"ns_veth,omitempty"`
	UplinkHost    string    `json:"uplink_host,omitempty"`
	UplinkNS      string    `json:"uplink_ns,omitempty"`
	Table         string    `json:"table,omitempty"`
	AllowlistHash string    `json:"allowlist_hash,omitempty"`
	Generation    int       `json:"generation"`
	LastKind      string    `json:"last_kind,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Store allocates snapshot destinations and remembers committed records.
type Store interface {
	// Prepare returns host paths. Snapshot files need not exist yet.
	Prepare(ctx context.Context, sessionID, vmID string) (*Record, error)
	// Commit writes metadata after the VMM created the files. Fail-closed
	// if the snap or memory file is missing.
	Commit(ctx context.Context, rec *Record) error
	Restore(ctx context.Context, sessionID string) (*Record, error)
	Delete(ctx context.Context, sessionID string) error
}

// Unsupported keeps session_id visible in logs but refuses to snapshot.
type Unsupported struct{}

// Prepare implements Store.
func (Unsupported) Prepare(_ context.Context, sessionID, _ string) (*Record, error) {
	return nil, fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}

// Commit implements Store.
func (Unsupported) Commit(_ context.Context, rec *Record) error {
	id := ""
	if rec != nil {
		id = rec.SessionID
	}
	return fmt.Errorf("%w (session %s)", ErrNotImplemented, id)
}

// Restore implements Store.
func (Unsupported) Restore(_ context.Context, sessionID string) (*Record, error) {
	return nil, fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}

// Delete implements Store.
func (Unsupported) Delete(_ context.Context, sessionID string) error {
	return fmt.Errorf("%w (session %s)", ErrNotImplemented, sessionID)
}

const metaName = "meta.json"

// DirStore is a directory tree: {root}/{session_id}/{vm.snap,vm.mem,rootfs.ext4,meta.json}.
type DirStore struct {
	Root string
}

// NewDirStore writes under root. Root is created on first Prepare.
func NewDirStore(root string) *DirStore {
	return &DirStore{Root: root}
}

func sanitizeSession(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("snapshot: empty session id")
	}
	if id != filepath.Base(id) || filepath.IsAbs(id) || id == "." || id == ".." {
		return "", fmt.Errorf("snapshot: invalid session id %q", id)
	}
	return id, nil
}

func (d *DirStore) sessionDir(id string) (string, error) {
	clean, err := sanitizeSession(id)
	if err != nil {
		return "", err
	}
	if d.Root == "" {
		return "", fmt.Errorf("snapshot: store root is empty")
	}
	return filepath.Join(d.Root, clean), nil
}

// Prepare implements Store.
func (d *DirStore) Prepare(_ context.Context, sessionID, vmID string) (*Record, error) {
	dir, err := d.sessionDir(sessionID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("snapshot mkdir %s: %w", dir, err)
	}
	return &Record{
		SessionID:    sessionID,
		VMID:         vmID,
		Path:         dir,
		SnapshotPath: filepath.Join(dir, "vm.snap"),
		MemoryPath:   filepath.Join(dir, "vm.mem"),
		RootfsPath:   filepath.Join(dir, "rootfs.ext4"),
	}, nil
}

// Commit implements Store.
func (d *DirStore) Commit(_ context.Context, rec *Record) error {
	if rec == nil {
		return fmt.Errorf("snapshot: nil record")
	}
	dir, err := d.sessionDir(rec.SessionID)
	if err != nil {
		return err
	}
	for _, p := range []struct{ name, path string }{
		{"snapshot", rec.SnapshotPath},
		{"memory", rec.MemoryPath},
	} {
		if p.path == "" {
			return fmt.Errorf("snapshot: %s path is empty", p.name)
		}
		st, err := os.Stat(p.path)
		if err != nil {
			return fmt.Errorf("snapshot: refusing to commit %s: missing %s: %w", rec.SessionID, p.name, err)
		}
		if st.IsDir() || st.Size() == 0 {
			return fmt.Errorf("snapshot: refusing to commit %s: %s is empty", rec.SessionID, p.name)
		}
	}
	if rec.RootfsPath != "" {
		if _, err := os.Stat(rec.RootfsPath); err != nil {
			return fmt.Errorf("snapshot: refusing to commit %s: missing rootfs: %w", rec.SessionID, err)
		}
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	rec.Path = dir
	if err := pathsContained(dir, rec); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, metaName+".tmp")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("snapshot meta: %w", err)
	}
	return os.Rename(tmp, filepath.Join(dir, metaName))
}

// Restore implements Store.
func (d *DirStore) Restore(_ context.Context, sessionID string) (*Record, error) {
	dir, err := d.sessionDir(sessionID)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w (session %s)", ErrNotFound, sessionID)
		}
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("snapshot: corrupt meta for %s: %w", sessionID, err)
	}
	if err := pathsContained(dir, &rec); err != nil {
		return nil, err
	}
	for _, p := range []string{rec.SnapshotPath, rec.MemoryPath} {
		if p == "" {
			return nil, fmt.Errorf("snapshot: corrupt session %s: missing path in meta", sessionID)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("snapshot: corrupt session %s: %w", sessionID, err)
		}
	}
	return &rec, nil
}

func pathsContained(dir string, rec *Record) error {
	for _, p := range []string{rec.SnapshotPath, rec.MemoryPath, rec.RootfsPath} {
		if p == "" {
			continue
		}
		if err := mustContain(dir, p); err != nil {
			return err
		}
	}
	return nil
}

func mustContain(dir, p string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	absP, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absDir, absP)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("snapshot: path %s is outside %s", p, dir)
	}
	return nil
}

// Delete implements Store.
func (d *DirStore) Delete(_ context.Context, sessionID string) error {
	dir, err := d.sessionDir(sessionID)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}
