package audit

import "sync"

// MemoryLogger keeps events in process memory. It is for tests and local
// inspection, not for production durability.
type MemoryLogger struct {
	mu     sync.Mutex
	events []Event
}

// Record stores a copy of the event.
func (m *MemoryLogger) Record(event Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

// Events returns a snapshot of recorded events.
func (m *MemoryLogger) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}
