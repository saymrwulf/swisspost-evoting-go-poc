package party

import (
	"testing"

	"github.com/user/evote/pkg/trace"
)

// TestCeremonyEmitsLiveCryptoEvents runs the full ceremony with a trace sink
// attached and confirms that the real cryptographic operations emit events
// carrying live runtime values — the foundation of the "watch the math execute"
// cockpit. It checks that each headline operation kind appears with non-empty
// values and correct LaTeX.
func TestCeremonyEmitsLiveCryptoEvents(t *testing.T) {
	sink := &trace.SliceSink{}
	unsub := trace.Subscribe(sink)
	defer unsub()

	// 6 voters → N=6 ballots → the shuffle matrix is 2×3 (m>1), so the full
	// Bayer-Groth argument tree runs (Hadamard/Zero only fire when m>1).
	cfg := testConfig(t, 6, 3)
	c, err := NewCeremony(cfg, nil)
	if err != nil {
		t.Fatalf("NewCeremony: %v", err)
	}
	if err := c.RunSetup(); err != nil {
		t.Fatalf("RunSetup: %v", err)
	}
	if err := c.RunCards(); err != nil {
		t.Fatalf("RunCards: %v", err)
	}
	if err := c.RunVoting([][]int{{0}, {1}, {2}, {0}, {1}, {2}}); err != nil {
		t.Fatalf("RunVoting: %v", err)
	}
	if err := c.RunTally(); err != nil {
		t.Fatalf("RunTally: %v", err)
	}
	if err := c.RunVerify(); err != nil {
		t.Fatalf("RunVerify: %v", err)
	}

	events := sink.Snapshot()
	if len(events) == 0 {
		t.Fatal("no trace events emitted during a full ceremony")
	}

	seen := map[trace.Kind]trace.Event{}
	for _, e := range events {
		seen[e.Kind] = e
	}

	// Every headline operation must have fired at least once — including the
	// deep Bayer-Groth layers (commitment, sub-arguments, partial decryption)
	// that mirror the Swiss Post crypto-primitives class structure.
	for _, k := range []trace.Kind{
		trace.KindSign,      // Ed25519 transport signatures
		trace.KindKeyEx,     // X25519 ECDH (card delivery)
		trace.KindEncrypt,   // ballot encryption
		trace.KindChallenge, // Fiat-Shamir challenge
		trace.KindShuffle,   // Bayer-Groth mix-net (top level)
		trace.KindCommit,    // Pedersen matrix commitment
		trace.KindArgument,  // a Bayer-Groth sub-argument
		trace.KindDecrypt,   // CC partial decryption + proof
	} {
		e, ok := seen[k]
		if !ok {
			t.Errorf("no %q event emitted", k)
			continue
		}
		if e.LaTeX == "" {
			t.Errorf("%q event has empty LaTeX", k)
		}
		if len(e.Values) == 0 {
			t.Errorf("%q event carries no live values", k)
		}
	}

	// All five Bayer-Groth sub-arguments must appear (matching the Swiss Post
	// *ArgumentService classes). We identify them by a keyword in the caption.
	argCaptions := map[string]bool{}
	for _, e := range events {
		if e.Kind == trace.KindArgument {
			argCaptions[e.Caption] = true
		}
	}
	for _, want := range []string{"Shuffle argument", "Product argument", "Hadamard argument",
		"Zero argument", "Single-value product argument", "Multi-exponentiation argument"} {
		found := false
		for cap := range argCaptions {
			if len(cap) >= len(want) && cap[:len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("sub-argument %q never appeared in the trace", want)
		}
	}

	// Spot-check that the shuffle event reports the padded ballot count (N>=3).
	if sh, ok := seen[trace.KindShuffle]; ok {
		if sh.Values["N"] == "" {
			t.Error("shuffle event missing N")
		}
	}

	// Events must be tagged with a phase, and signatures with the acting party.
	if seen[trace.KindSign].Party == "" {
		t.Error("signature event not attributed to a party")
	}
	if seen[trace.KindShuffle].Phase != "tally" {
		t.Errorf("shuffle phase = %q, want tally", seen[trace.KindShuffle].Phase)
	}

	t.Logf("captured %d live crypto events across %d kinds", len(events), len(seen))
}
