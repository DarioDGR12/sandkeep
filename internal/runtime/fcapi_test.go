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
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := c.startInstance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.configure(ctx,
		fcMachineConfig{VCPUCount: 1, MemSizeMiB: 128},
		fcBootSource{KernelImagePath: "/k"},
		fcDrive{DriveID: "rootfs", PathOnHost: "/r", IsRootDevice: true},
		fcVsock{GuestCID: 4, UDSPath: "/v.sock"},
		nil,
		&fcNetIface{IfaceID: "eth0", GuestMAC: "06:00:ac:19:00:02", HostDevName: "wfc1"},
	); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/logger", "/machine-config", "/boot-source", "/drives/rootfs", "/vsock", "/actions", "/network-interfaces/eth0"} {
		if got[p] == 0 {
			t.Fatalf("missing PUT %s: %#v", p, got)
		}
	}
}

func TestFCClientSnapshotAPI(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type hit struct {
		method string
		body   map[string]any
	}
	got := map[string]hit{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got[r.URL.Path] = hit{method: r.Method, body: body}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newFCClient(sock, 2*time.Second)
	ctx := context.Background()
	if err := c.pauseVM(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.createSnapshot(ctx, "/vm.snap", "/vm.mem"); err != nil {
		t.Fatal(err)
	}
	if err := c.loadSnapshot(ctx, "/vm.snap", "/vm.mem"); err != nil {
		t.Fatal(err)
	}

	if got["/vm"].method != http.MethodPatch {
		t.Fatalf("pause method=%s", got["/vm"].method)
	}
	if got["/vm"].body["state"] != "Paused" {
		t.Fatalf("pause body=%v", got["/vm"].body)
	}
	if got["/snapshot/create"].method != http.MethodPut {
		t.Fatalf("create method=%s", got["/snapshot/create"].method)
	}
	if got["/snapshot/create"].body["snapshot_type"] != "Full" {
		t.Fatalf("create body=%v", got["/snapshot/create"].body)
	}
	if got["/snapshot/create"].body["snapshot_path"] != "/vm.snap" || got["/snapshot/create"].body["mem_file_path"] != "/vm.mem" {
		t.Fatalf("create paths=%v", got["/snapshot/create"].body)
	}
	load := got["/snapshot/load"]
	if load.method != http.MethodPut {
		t.Fatalf("load method=%s", load.method)
	}
	if load.body["resume_vm"] != true {
		t.Fatalf("load must resume: %v", load.body)
	}
	backend, _ := load.body["mem_backend"].(map[string]any)
	if backend["backend_type"] != "File" || backend["backend_path"] != "/vm.mem" {
		t.Fatalf("mem backend=%v", backend)
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
