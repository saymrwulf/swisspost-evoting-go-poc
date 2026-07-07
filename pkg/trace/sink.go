package trace

import "sync"

// Short elides a long value for compact display: keeps the first and last few
// characters. Renderers that want the full value use the raw Values map.
func Short(s string) string {
	const head, tail = 8, 6
	if len(s) <= head+tail+1 {
		return s
	}
	return s[:head] + "…" + s[len(s)-tail:]
}

// ChanSink forwards events to a buffered channel, dropping if the consumer is
// too slow (tracing must never stall the ceremony). Dropped counts are tracked.
type ChanSink struct {
	C       chan Event
	dropped uint64
	mu      sync.Mutex
}

// NewChanSink creates a ChanSink with the given buffer size.
func NewChanSink(buffer int) *ChanSink {
	return &ChanSink{C: make(chan Event, buffer)}
}

func (s *ChanSink) Handle(e Event) {
	select {
	case s.C <- e:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// Dropped returns how many events were dropped due to a full buffer.
func (s *ChanSink) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// SliceSink collects events in memory (used in tests).
type SliceSink struct {
	mu     sync.Mutex
	Events []Event
}

func (s *SliceSink) Handle(e Event) {
	s.mu.Lock()
	s.Events = append(s.Events, e)
	s.mu.Unlock()
}

// Snapshot returns a copy of the collected events.
func (s *SliceSink) Snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.Events))
	copy(out, s.Events)
	return out
}
