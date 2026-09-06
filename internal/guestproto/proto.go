// Package guestproto is the host↔guest contract over vsock.
//
// One connection carries one JSON request and one JSON response
// (encoding/json, one value each). The guest agent lives in the microVM;
// the host runtime must never import an executor that runs this payload
// on the Warden process.
package guestproto

import (
	"encoding/json"
	"fmt"
	"io"
)

// DefaultPort is the AF_VSOCK port the guest agent listens on.
const DefaultPort = 52

// MaxOutputBytes caps stdout+stderr the agent will return.
const MaxOutputBytes = 1 << 20

// MaxCodeBytes matches the HTTP API cap so a compromised vsock peer
// cannot send an unbounded source payload to the guest-agent.
const MaxCodeBytes = 64 << 10

// MaxRequestBytes caps the JSON request the guest-agent will decode.
const MaxRequestBytes = MaxCodeBytes + 8<<10

// MaxResponseBytes caps the JSON response the host will decode.
// Two MaxOutputBytes buffers plus JSON framing.
const MaxResponseBytes = 2*MaxOutputBytes + 8<<10

// Request is what the host sends after the vsock CONNECT handshake.
type Request struct {
	Code        string `json:"code"`
	Runtime     string `json:"runtime"`
	TimeoutS    int    `json:"timeout_s"`
	MemoryBytes int64  `json:"memory_bytes,omitempty"`
	PIDsMax     int64  `json:"pids_max,omitempty"`
}

// Response is the guest result. TimedOut means the guest killed the job.
type Response struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
}

// WriteRequest encodes one request. json.Encoder adds a trailing newline.
func WriteRequest(w io.Writer, req Request) error {
	if err := json.NewEncoder(w).Encode(req); err != nil {
		return fmt.Errorf("guestproto write request: %w", err)
	}
	return nil
}

// ReadRequest decodes one request value (newlines inside code are fine).
func ReadRequest(r io.Reader) (Request, error) {
	return readJSON[Request](r, MaxRequestBytes)
}

// WriteResponse encodes one response.
func WriteResponse(w io.Writer, resp Response) error {
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return fmt.Errorf("guestproto write response: %w", err)
	}
	return nil
}

// ReadResponse decodes one response value with a hard size cap so a
// compromised guest cannot OOM the Warden host.
func ReadResponse(r io.Reader) (Response, error) {
	return readJSON[Response](r, MaxResponseBytes)
}

func readJSON[T any](r io.Reader, max int64) (T, error) {
	var v T
	limited := &io.LimitedReader{R: r, N: max + 1}
	if err := json.NewDecoder(limited).Decode(&v); err != nil {
		return v, fmt.Errorf("guestproto decode: %w", err)
	}
	if limited.N == 0 {
		return v, fmt.Errorf("guestproto: message exceeds %d bytes", max)
	}
	return v, nil
}
