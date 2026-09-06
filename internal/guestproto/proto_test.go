package guestproto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DarioDGR12/sandkeep/internal/guestproto"
)

func TestRequestRoundTripWithNewlinesInCode(t *testing.T) {
	var buf bytes.Buffer
	req := guestproto.Request{
		Code:        "print(1)\nprint(2)\n",
		Runtime:     "python",
		TimeoutS:    10,
		MemoryBytes: 256 << 20,
		PIDsMax:     64,
	}
	if err := guestproto.WriteRequest(&buf, req); err != nil {
		t.Fatal(err)
	}
	got, err := guestproto.ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != req {
		t.Fatalf("got %+v want %+v", got, req)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	resp := guestproto.Response{Stdout: "ok\n", ExitCode: 0}
	if err := guestproto.WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	got, err := guestproto.ReadResponse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != resp {
		t.Fatalf("got %+v", got)
	}
	if !strings.HasSuffix(buf.String(), "") {
		// encoder consumed the buffer on read; just ensure no panic
	}
}
