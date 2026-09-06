package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// FixedWindow caps requests per identity per Window. Limit <= 0 disables it.
type FixedWindow struct {
	Limit  int
	Window time.Duration
	Now    func() time.Time

	mu   sync.Mutex
	hits map[string]*windowCounter
}

type windowCounter struct {
	reset time.Time
	n     int
}

// NewFixedWindow returns a limiter. A non-positive limit is a no-op.
func NewFixedWindow(limit int, window time.Duration) *FixedWindow {
	if window <= 0 {
		window = time.Minute
	}
	return &FixedWindow{
		Limit:  limit,
		Window: window,
		hits:   make(map[string]*windowCounter),
	}
}

// Allow reports whether key may proceed and consumes one slot on success.
func (r *FixedWindow) Allow(key string) bool {
	if r == nil || r.Limit <= 0 {
		return true
	}
	if key == "" {
		key = "anon"
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hits == nil {
		r.hits = make(map[string]*windowCounter)
	}
	const maxKeys = 2048
	c := r.hits[key]
	if c == nil || !now.Before(c.reset) {
		r.evictExpiredLocked(now)
		if c == nil && len(r.hits) >= maxKeys {
			// Never evict an active window to make room for an attacker.
			return false
		}
		c = &windowCounter{reset: now.Add(r.Window), n: 0}
		r.hits[key] = c
	}
	if c.n >= r.Limit {
		return false
	}
	c.n++
	return true
}

func (r *FixedWindow) evictExpiredLocked(now time.Time) {
	for k, c := range r.hits {
		if !now.Before(c.reset) {
			delete(r.hits, k)
		}
	}
}

func rateKey(r *http.Request, method, cn string) string {
	if tok := tokenFromRequest(r); tok != "" {
		sum := sha256.Sum256([]byte(tok))
		return "tok:" + hex.EncodeToString(sum[:8])
	}
	if cn != "" {
		return "cn:" + cn
	}
	if method != "" && method != "none" {
		return "auth:" + method
	}
	return "ip:" + remoteHost(r)
}
