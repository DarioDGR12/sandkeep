package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// dialGuestVsock performs the Firecracker host-initiated vsock handshake:
// connect to the UDS, send "CONNECT <port>\n", expect "OK <hostport>\n".
func dialGuestVsock(ctx context.Context, uds string, port uint32) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", uds)
	if err != nil {
		return nil, fmt.Errorf("vsock uds %s: %w", uds, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock CONNECT %d: %w", port, err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock handshake read: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "OK ") {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock handshake rejected: %q", line)
	}
	if _, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "OK "))); err != nil {
		// Firecracker still established the channel; host port is informational.
		_ = err
	}

	// Remaining buffered bytes belong to the guest stream. Wrap so they are not lost.
	_ = conn.SetDeadline(time.Time{})
	return &vsockConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
}

type vsockConn struct {
	net.Conn
	r io.Reader
}

func (c *vsockConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func waitForGuestAgent(ctx context.Context, uds string, port uint32) error {
	var last error
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := dialGuestVsock(ctx, uds, port)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			if last != nil {
				return fmt.Errorf("guest agent not ready: %w (%v)", ctx.Err(), last)
			}
			return fmt.Errorf("guest agent not ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
