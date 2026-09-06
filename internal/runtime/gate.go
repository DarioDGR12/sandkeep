package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrBusy is returned when the VM slot queue times out.
var ErrBusy = errors.New("runtime: too many concurrent VMs")

// Gate wraps a Runtime with a bounded number of live instances. Boot waits
// up to Wait for a slot; Destroy releases it. Max < 1 is treated as 1 —
// unlimited concurrency is not an option.
type Gate struct {
	Inner Runtime
	Max   int
	Wait  time.Duration
	sem   chan struct{}
}

// NewGate returns a concurrency-limited Runtime. Inner must not be nil.
func NewGate(inner Runtime, max int, wait time.Duration) *Gate {
	if max < 1 {
		max = 1
	}
	if wait <= 0 {
		wait = 15 * time.Second
	}
	return &Gate{
		Inner: inner,
		Max:   max,
		Wait:  wait,
		sem:   make(chan struct{}, max),
	}
}

// Name implements Runtime.
func (g *Gate) Name() string {
	if g.Inner == nil {
		return "gate"
	}
	return g.Inner.Name()
}

// Ready forwards to the inner backend when it exposes Ready.
func (g *Gate) Ready() error {
	if r, ok := g.Inner.(interface{ Ready() error }); ok {
		return r.Ready()
	}
	return nil
}

// Boot waits for a VM slot, then boots the inner runtime. A failed Boot
// releases the slot; a successful Boot transfers ownership to the instance.
func (g *Gate) Boot(ctx context.Context, spec Spec) (Instance, error) {
	if g.Inner == nil {
		return nil, fmt.Errorf("runtime: gate has no inner runtime")
	}
	timer := time.NewTimer(g.Wait)
	defer timer.Stop()
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("%w (max %d)", ErrBusy, g.Max)
	}
	inst, err := g.Inner.Boot(ctx, spec)
	if err != nil {
		<-g.sem
		return nil, err
	}
	return &leasedInstance{
		Instance: inst,
		release:  sync.OnceFunc(func() { <-g.sem }),
	}, nil
}

type leasedInstance struct {
	Instance
	release func()
}

func (l *leasedInstance) Destroy(ctx context.Context) error {
	defer l.release()
	return l.Instance.Destroy(ctx)
}
