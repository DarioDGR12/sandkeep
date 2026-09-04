package runtime_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

func TestStubBootExecuteDestroy(t *testing.T) {
	rt := runtime.NewStub()
	if rt.Name() != "stub" {
		t.Fatalf("name=%s", rt.Name())
	}
	inst, err := rt.Boot(context.Background(), runtime.Spec{
		Language:  runtime.LangPython,
		SessionID: "s1",
		Limits:    resources.DefaultProfile(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := inst.Execute(context.Background(), runtime.ExecRequest{
		Code:    "print(99)",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.TimedOut {
		t.Fatalf("result=%+v", res)
	}
	if !strings.Contains(res.Stdout, "warden-stub") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	if strings.Contains(res.Stdout, "99") {
		t.Fatalf("must not evaluate code: %q", res.Stdout)
	}
	if err := inst.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := inst.Destroy(context.Background()); err == nil {
		t.Fatal("second destroy should fail")
	}
	if _, err := inst.Execute(context.Background(), runtime.ExecRequest{Code: "x"}); err == nil {
		t.Fatal("execute after destroy should fail")
	}
}

func TestStubRejectsUnknownLanguage(t *testing.T) {
	rt := runtime.NewStub()
	_, err := rt.Boot(context.Background(), runtime.Spec{
		Language: "ruby",
		Limits:   resources.DefaultProfile(),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewFactory(t *testing.T) {
	rt, err := runtime.New("stub")
	if err != nil || rt.Name() != "stub" {
		t.Fatalf("stub: rt=%v err=%v", rt, err)
	}
	rt, err = runtime.New("firecracker")
	if err != nil || rt.Name() != "firecracker" {
		t.Fatalf("fc: rt=%v err=%v", rt, err)
	}
	_, err = rt.Boot(context.Background(), runtime.Spec{Language: "python", Limits: resources.DefaultProfile()})
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Fatalf("want ErrNotImplemented, got %v", err)
	}
	if _, err := runtime.New("gvisor"); err == nil {
		t.Fatal("expected unknown runtime error")
	}
}

func TestCancelledContextTimesOut(t *testing.T) {
	rt := runtime.NewStub()
	inst, err := rt.Boot(context.Background(), runtime.Spec{
		Language: runtime.LangNode,
		Limits:   resources.DefaultProfile(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := inst.Execute(ctx, runtime.ExecRequest{Code: "x", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != -1 {
		t.Fatalf("result=%+v", res)
	}
}
