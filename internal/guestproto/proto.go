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

// Request is what the host sends after the vsock CONNECT handshake.
type Request struct {
	Code     string `json:"code"`
	Runtime  string `json:"runtime"`
	TimeoutS int    `json:"timeout_s"`
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
	var req Request
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return Request{}, fmt.Errorf("guestproto read request: %w", err)
	}
	return req, nil
}

// WriteResponse encodes one response.
func WriteResponse(w io.Writer, resp Response) error {
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return fmt.Errorf("guestproto write response: %w", err)
	}
	return nil
}

// ReadResponse decodes one response value.
func ReadResponse(r io.Reader) (Response, error) {
	var resp Response
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("guestproto read response: %w", err)
	}
	return resp, nil
}
