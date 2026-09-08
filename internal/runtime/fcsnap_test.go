package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/network"
	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/snapshot"
)

func TestNetworkMatches(t *testing.T) {
	deny := network.Default()
	allow := network.Policy{DefaultPolicy: network.PolicyDeny, Allowlist: []string{"1.2.3.4"}}
	if networkMatches(nil, deny) {
		t.Fatal("nil record")
	}
	if !networkMatches(&snapshot.Record{HasNetwork: false}, deny) {
		t.Fatal("isolated snap + deny-all")
	}
	if networkMatches(&snapshot.Record{HasNetwork: true}, deny) {
		t.Fatal("nic snap + deny-all must not restore")
	}
	if networkMatches(&snapshot.Record{HasNetwork: true}, allow) {
		t.Fatal("nic snap without allowlist hash must not restore")
	}
	if !networkMatches(&snapshot.Record{HasNetwork: true, AllowlistHash: allow.Fingerprint()}, allow) {
		t.Fatal("nic snap + matching allowlist")
	}
	other := network.Policy{DefaultPolicy: network.PolicyDeny, Allowlist: []string{"9.9.9.9"}}
	if networkMatches(&snapshot.Record{HasNetwork: true, AllowlistHash: allow.Fingerprint()}, other) {
		t.Fatal("allowlist change must invalidate the snap")
	}
	if networkMatches(&snapshot.Record{HasNetwork: false}, allow) {
		t.Fatal("isolated snap + allowlist must not restore")
	}
}

func TestRootfsReadOnlyEphemeral(t *testing.T) {
	if !rootfsReadOnly("") {
		t.Fatal("ephemeral VM rootfs must be read-only")
	}
	if rootfsReadOnly("agent-1") {
		t.Fatal("session VM rootfs must stay writable")
	}
}

func TestTapIDStableForSession(t *testing.T) {
	if tapID("fc-9", "agent") != "sagent" {
		t.Fatal(tapID("fc-9", "agent"))
	}
	if tapID("fc-9", "") != "fc-9" {
		t.Fatal(tapID("fc-9", ""))
	}
}

func TestRecordNetworkRoundTrip(t *testing.T) {
	rec := &snapshot.Record{SessionID: "s"}
	fillRecordNetwork(rec, &network.Link{
		Name:       "wsess1",
		HostIP:     net.ParseIP("172.25.0.5"),
		GuestIP:    net.ParseIP("172.25.0.6"),
		GuestMAC:   "06:00:ac:19:00:06",
		Table:      "warden_s",
		NetNS:      "warden-s",
		NetNSPath:  "/var/run/netns/warden-s",
		HostVeth:   "hsess1",
		NSVeth:     "gsess1",
		UplinkHost: net.ParseIP("172.27.0.5"),
		UplinkNS:   net.ParseIP("172.27.0.6"),
	})
	if !rec.HasNetwork || rec.HostDevName != "wsess1" {
		t.Fatalf("%+v", rec)
	}
	link := linkFromRecord(rec)
	if link.Name != "wsess1" || link.GuestIP.String() != "172.25.0.6" || link.HostVeth != "hsess1" {
		t.Fatalf("%+v", link)
	}
	fillRecordNetwork(rec, nil)
	if rec.HasNetwork || linkFromRecord(rec) != nil {
		t.Fatal("clearing tap must drop network")
	}
}

type boomStore struct{}

func (boomStore) Prepare(context.Context, string, string) (*snapshot.Record, error) {
	return nil, fmt.Errorf("disk exploded")
}
func (boomStore) Commit(context.Context, *snapshot.Record) error {
	return fmt.Errorf("disk exploded")
}
func (boomStore) Restore(context.Context, string) (*snapshot.Record, error) {
	return nil, fmt.Errorf("disk exploded")
}
func (boomStore) Delete(context.Context, string) error { return nil }

func TestBootSnapshotStoreErrorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	touch := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rt := NewFirecrackerWithConfig(Config{
		Binary:      touch("fc"),
		Kernel:      touch("vmlinux"),
		Rootfs:      touch("root.ext4"),
		WorkDir:     dir,
		SnapshotDir: "",
		Snapshots:   boomStore{},
	})
	_, err := rt.Boot(context.Background(), Spec{
		Language:  LangPython,
		SessionID: "agent-1",
		Limits:    resources.DefaultProfile(),
		Network:   network.Default(),
	})
	if err == nil || !strings.Contains(err.Error(), "disk exploded") {
		t.Fatalf("corrupt/unreadable store must fail closed, got %v", err)
	}
	if errors.Is(err, ErrMissingAssets) {
		t.Fatalf("must not hide store error behind missing assets: %v", err)
	}
}

func TestBootNotFoundSnapshotColdBoots(t *testing.T) {
	dir := t.TempDir()
	touch := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	store := snapshot.NewDirStore(filepath.Join(dir, "snaps"))
	rt := NewFirecrackerWithConfig(Config{
		Binary:      touch("fc"),
		Kernel:      touch("vmlinux"),
		Rootfs:      touch("root.ext4"),
		WorkDir:     filepath.Join(dir, "vms"),
		Snapshots:   store,
		SnapshotDir: "",
	})
	_, err := rt.Boot(context.Background(), Spec{
		Language:  LangPython,
		SessionID: "fresh",
		Limits:    resources.DefaultProfile(),
		Network:   network.Default(),
	})
	if err == nil {
		t.Fatal("dummy firecracker must fail to start")
	}
	if strings.Contains(err.Error(), "disk exploded") {
		t.Fatal(err)
	}
	// NotFound must not fail closed — we attempted a cold boot (clone + spawn).
	if errors.Is(err, snapshot.ErrNotFound) {
		t.Fatalf("NotFound must fall through to cold boot: %v", err)
	}
}
