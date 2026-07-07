package trace

import "testing"

func TestDisabledByDefaultIsCheap(t *testing.T) {
	if Enabled() {
		t.Fatal("tracing should be off with no sinks")
	}
	called := false
	EmitFunc(func() Event { called = true; return Event{} })
	if called {
		t.Fatal("EmitFunc built an event while tracing was disabled")
	}
}

func TestSubscribeReceivesEvents(t *testing.T) {
	sink := &SliceSink{}
	unsub := Subscribe(sink)
	defer unsub()

	SetContext("control-component-0", "tally")
	Emit(Event{
		Kind:    KindChallenge,
		Caption: "Fiat-Shamir challenge",
		LaTeX:   `e = \mathcal{H}(g, y, c) \bmod q`,
		Values:  map[string]string{"e": "12345678901234567890"},
	})
	Emit(Event{Party: "voter-0001", Kind: KindEncrypt, Caption: "encrypt ballot"})

	got := sink.Snapshot()
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if got[0].Seq == 0 || got[1].Seq <= got[0].Seq {
		t.Fatalf("sequence numbers not monotonic: %d, %d", got[0].Seq, got[1].Seq)
	}
	if got[0].Party != "control-component-0" || got[0].Phase != "tally" {
		t.Fatalf("context not stamped: %+v", got[0])
	}
	if got[1].Party != "voter-0001" {
		t.Fatalf("explicit party overridden: %+v", got[1])
	}

	unsub()
	if Enabled() {
		t.Fatal("unsubscribe did not clear the last sink")
	}
}

func TestShortElision(t *testing.T) {
	if Short("12345") != "12345" {
		t.Fatal("short values must pass through")
	}
	long := "1234567890123456789012345"
	e := Short(long)
	if e == long || len(e) >= len(long) {
		t.Fatalf("long value not elided: %q", e)
	}
}
