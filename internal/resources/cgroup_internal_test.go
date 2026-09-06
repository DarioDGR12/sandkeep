package resources

import (
	"os/exec"
	"testing"
	"time"
)

func TestDescendantPIDsFindsChild(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 20")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(2 * time.Second)
	var kids []int
	for time.Now().Before(deadline) {
		kids = descendantPIDs(cmd.Process.Pid)
		if len(kids) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(kids) == 0 {
		t.Fatal("expected at least one child of sh -c sleep")
	}
	for _, pid := range kids {
		if pid == cmd.Process.Pid {
			t.Fatal("root pid must not appear in descendants")
		}
	}
}
