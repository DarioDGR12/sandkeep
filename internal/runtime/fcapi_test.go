package runtime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestFCClientConfigureAndStart(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := map[string]int{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got[r.URL.Path]++
		if r.Method != http.MethodPut {
			t.Errorf("method %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newFCClient(sock, 2*time.Second)
	ctx := context.Background()
	if err := c.configure(ctx,
		fcMachineConfig{VCPUCount: 1, MemSizeMiB: 256},
		fcBootSource{KernelImagePath: "/k", BootArgs: "console=ttyS0"},
		fcDrive{DriveID: "rootfs", PathOnHost: "/r", IsRootDevice: true},
		fcVsock{GuestCID: 3, UDSPath: "/v.sock"},
		&fcLogger{LogPath: "/l", Level: "Info"},
	); err != nil {
		t.Fatal(err)
	}
	if err := c.startInstance(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/logger", "/machine-config", "/boot-source", "/drives/rootfs", "/vsock", "/actions"} {
		if got[p] == 0 {
			t.Fatalf("missing PUT %s: %#v", p, got)
		}
	}
}

func TestFCClientSurfaceFault(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"fault_message":"bad drive"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newFCClient(sock, time.Second)
	err = c.startInstance(context.Background())
	if err == nil || err.Error() == "" {
		t.Fatalf("want fault, got %v", err)
	}
}
