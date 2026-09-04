package api

import "testing"

func TestValidateExecute(t *testing.T) {
	t.Run("defaults timeout and normalizes python3", func(t *testing.T) {
		req := ExecuteRequest{Code: "print(1)", Runtime: "Python3"}
		if err := validateExecute(&req); err != nil {
			t.Fatal(err)
		}
		if req.Runtime != "python" {
			t.Fatalf("runtime=%q", req.Runtime)
		}
		if req.Timeout != DefaultTimeoutS {
			t.Fatalf("timeout=%d", req.Timeout)
		}
	})

	t.Run("rejects empty code", func(t *testing.T) {
		req := ExecuteRequest{Runtime: "python"}
		if err := validateExecute(&req); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects oversized code", func(t *testing.T) {
		req := ExecuteRequest{Code: string(make([]byte, MaxCodeBytes+1)), Runtime: "python"}
		if err := validateExecute(&req); err == nil {
			t.Fatal("expected error")
		}
	})
}
