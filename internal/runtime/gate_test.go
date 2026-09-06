package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/resources"
	"github.com/DarioDGR12/sandkeep/internal/runtime"
)

type holdRuntime struct {
	entered chan struct{}
	release chan struct{}
	boots   atomic.Int32
}

func (h *holdRuntime) Name() string { return "hold" }

func (h *holdRuntime) Boot(ctx context.Context, spec runtime.Spec) (runtime.Instance, error) {
	h.boots.Add(1)
	select {
	case h.entered <- struct{}{}:
	default:
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return runtime.NewStub().Boot(ctx, spec)
}

type failOnceRuntime struct {
	calls atomic.Int32
}

func (f *failOnceRuntime) Name() string { return "fail" }

func (f *failOnceRuntime) Boot(ctx context.Context, spec runtime.Spec) (runtime.Instance, error) {
	n := f.calls.Add(1)
	if n == 1 {
		return nil, fmt.Errorf("boot exploded")
	}
	return runtime.NewStub().Boot(ctx, spec)
}

func spec() runtime.Spec {
	return runtime.Spec{Language: runtime.LangPython, Limits: resources.DefaultProfile()}
}

func TestGateSecondWaiterTimesOutBusy(t *testing.T) {
	h := &holdRuntime{entered: make(chan struct{}, 1), release: make(chan struct{})}
	g := runtime.NewGate(h, 1, 40*time.Millisecond)

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	var first runtime.Instance
	var firstErr error
	go func() {
		defer wg.Done()
		first, firstErr = g.Boot(ctx, spec())
	}()
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("first boot never entered inner runtime")
	}

	_, err := g.Boot(ctx, spec())
	if !errors.Is(err, runtime.ErrBusy) {
		t.Fatalf("second boot want ErrBusy, got %v", err)
	}

	close(h.release)
	wg.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	if err := first.Destroy(ctx); err != nil {
		t.Fatal(err)
	}

	inst, err := g.Boot(ctx, spec())
	if err != nil {
		t.Fatalf("slot must be free after Destroy: %v", err)
	}
	_ = inst.Destroy(ctx)
}

func TestGateFailedBootReleasesSlot(t *testing.T) {
	inner := &failOnceRuntime{}
	g := runtime.NewGate(inner, 1, 50*time.Millisecond)
	_, err := g.Boot(context.Background(), spec())
	if err == nil || errors.Is(err, runtime.ErrBusy) {
		t.Fatalf("first boot should fail open (not busy): %v", err)
	}
	inst, err := g.Boot(context.Background(), spec())
	if err != nil {
		t.Fatalf("slot leaked after failed Boot: %v", err)
	}
	_ = inst.Destroy(context.Background())
}

func TestGateMaxAtLeastOne(t *testing.T) {
	g := runtime.NewGate(runtime.NewStub(), 0, time.Millisecond)
	if g.Max != 1 {
		t.Fatalf("max=%d", g.Max)
	}
	inst, err := g.Boot(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGateNameDelegates(t *testing.T) {
	g := runtime.NewGate(runtime.NewStub(), 1, time.Second)
	if g.Name() != "stub" {
		t.Fatalf("name=%s", g.Name())
	}
}
