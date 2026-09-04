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
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
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

type fcAction struct {
	ActionType string `json:"action_type"`
}

type fcError struct {
	FaultMessage string `json:"fault_message"`
}

func (c *fcClient) put(ctx context.Context, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("firecracker marshal %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		var fe fcError
		_ = json.Unmarshal(payload, &fe)
		if fe.FaultMessage == "" {
			fe.FaultMessage = string(payload)
		}
		return fmt.Errorf("firecracker PUT %s: %s (%d)", path, fe.FaultMessage, resp.StatusCode)
	}
	return nil
}

func (c *fcClient) configure(ctx context.Context, machine fcMachineConfig, boot fcBootSource, drive fcDrive, vsock fcVsock, logger *fcLogger) error {
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
	return nil
}

func (c *fcClient) startInstance(ctx context.Context) error {
	return c.put(ctx, "/actions", fcAction{ActionType: "InstanceStart"})
}

func (c *fcClient) sendCtrlAltDel(ctx context.Context) error {
	return c.put(ctx, "/actions", fcAction{ActionType: "SendCtrlAltDel"})
}
