package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// fcClient talks to a Firecracker process over its API Unix socket.
type fcClient struct {
	http *http.Client
}

func newFCClient(sock string, timeout time.Duration) *fcClient {
	// Timeouts live on the request context. A client-level timeout hid
	// Firecracker dying mid-InstanceStart behind "awaiting headers".
	_ = timeout
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}
	return &fcClient{http: &http.Client{Transport: transport}}
}

type fcMachineConfig struct {
	VCPUCount       int  `json:"vcpu_count"`
	MemSizeMiB      int  `json:"mem_size_mib"`
	SMT             bool `json:"smt"`
	TrackDirtyPages bool `json:"track_dirty_pages,omitempty"`
}

type fcBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
}

type fcDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type fcVsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type fcLogger struct {
	LogPath       string `json:"log_path"`
	Level         string `json:"level"`
	ShowLevel     bool   `json:"show_level"`
	ShowLogOrigin bool   `json:"show_log_origin"`
}

type fcNetIface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

type fcAction struct {
	ActionType string `json:"action_type"`
}

type fcError struct {
	FaultMessage string `json:"fault_message"`
}

type fcSnapshotCreate struct {
	SnapshotType string `json:"snapshot_type"`
	SnapshotPath string `json:"snapshot_path"`
	MemFilePath  string `json:"mem_file_path"`
}

type fcMemBackend struct {
	BackendType string `json:"backend_type"`
	BackendPath string `json:"backend_path"`
}

type fcSnapshotLoad struct {
	SnapshotPath    string       `json:"snapshot_path"`
	MemBackend      fcMemBackend `json:"mem_backend"`
	ResumeVM        bool         `json:"resume_vm"`
	TrackDirtyPages bool         `json:"track_dirty_pages"`
}

type fcVMState struct {
	State string `json:"state"`
}

func (c *fcClient) do(ctx context.Context, method, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("firecracker marshal %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		var fe fcError
		_ = json.Unmarshal(payload, &fe)
		if fe.FaultMessage == "" {
			fe.FaultMessage = string(payload)
		}
		return fmt.Errorf("firecracker %s %s: %s (%d)", method, path, fe.FaultMessage, resp.StatusCode)
	}
	return nil
}

func (c *fcClient) put(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodPut, path, body)
}

func (c *fcClient) patch(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodPatch, path, body)
}

func (c *fcClient) pauseVM(ctx context.Context) error {
	return c.patch(ctx, "/vm", fcVMState{State: "Paused"})
}

func (c *fcClient) resumeVM(ctx context.Context) error {
	return c.patch(ctx, "/vm", fcVMState{State: "Resumed"})
}

func (c *fcClient) createSnapshot(ctx context.Context, kind, snapPath, memPath string) error {
	if kind == "" {
		kind = "Full"
	}
	return c.put(ctx, "/snapshot/create", fcSnapshotCreate{
		SnapshotType: kind,
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
	})
}

func (c *fcClient) loadSnapshot(ctx context.Context, snapPath, memPath string) error {
	return c.put(ctx, "/snapshot/load", fcSnapshotLoad{
		SnapshotPath:    snapPath,
		MemBackend:      fcMemBackend{BackendType: "File", BackendPath: memPath},
		ResumeVM:        true,
		TrackDirtyPages: true,
	})
}

func (c *fcClient) configure(ctx context.Context, machine fcMachineConfig, boot fcBootSource, drive fcDrive, vsock fcVsock, logger *fcLogger, nic *fcNetIface) error {
	if logger != nil {
		if err := c.put(ctx, "/logger", logger); err != nil {
			return err
		}
	}
	if err := c.put(ctx, "/machine-config", machine); err != nil {
		return err
	}
	if err := c.put(ctx, "/boot-source", boot); err != nil {
		return err
	}
	if err := c.put(ctx, "/drives/"+drive.DriveID, drive); err != nil {
		return err
	}
	if err := c.put(ctx, "/vsock", vsock); err != nil {
		return err
	}
	if nic != nil {
		if err := c.put(ctx, "/network-interfaces/"+nic.IfaceID, nic); err != nil {
			return err
		}
	}
	return nil
}

func (c *fcClient) startInstance(ctx context.Context) error {
	return c.put(ctx, "/actions", fcAction{ActionType: "InstanceStart"})
}

func (c *fcClient) sendCtrlAltDel(ctx context.Context) error {
	return c.put(ctx, "/actions", fcAction{ActionType: "SendCtrlAltDel"})
}
