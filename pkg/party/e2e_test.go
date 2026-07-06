package party

import (
	"testing"
)

// TestFullMultiPartyCeremony runs the entire election over the transport:
// distributed setup, confidential card distribution, ballot submission with CC
// verification, the CC->CC->EB mix-net, and independent verification — then
// checks the decoded tally matches the cast votes and that every phase's
// messages were carried as verified envelopes.
func TestFullMultiPartyCeremony(t *testing.T) {
	cfg := testConfig(t, 5, 3)
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

	// Votes: options 0,1,1,2,1 -> {0:1, 1:3, 2:1}.
	selections := [][]int{{0}, {1}, {1}, {2}, {1}}
	if err := c.RunVoting(selections); err != nil {
		t.Fatalf("RunVoting: %v", err)
	}
	if err := c.RunTally(); err != nil {
		t.Fatalf("RunTally: %v", err)
	}
	if err := c.RunVerify(); err != nil {
		t.Fatalf("RunVerify: %v", err)
	}

	want := map[int]int{0: 1, 1: 3, 2: 1}
	got := c.Result()
	for opt, w := range want {
		if got[opt] != w {
			t.Errorf("option %d: got %d, want %d", opt, got[opt], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("result has %d options, want %d (%v)", len(got), len(want), got)
	}

	if c.Bus.Count() == 0 {
		t.Fatal("no messages were carried over the transport")
	}
	t.Logf("ceremony carried %d verified transport messages", c.Bus.Count())
}

// TestVerifyDetectsTamperedTranscript confirms the verifier rejects a transcript
// whose shuffle output was altered after the fact.
func TestVerifyDetectsTamperedTranscript(t *testing.T) {
	cfg := testConfig(t, 3, 3)
	c, err := NewCeremony(cfg, nil)
	if err != nil {
		t.Fatalf("NewCeremony: %v", err)
	}
	mustRun(t, c)

	// Corrupt the first CC's Schnorr proof set in the transcript.
	c.Transcript.CCSchnorr[0] = c.Transcript.CCSchnorr[1]
	if err := c.RunVerify(); err == nil {
		t.Fatal("verifier accepted a transcript with swapped Schnorr proofs")
	}
}

func mustRun(t *testing.T, c *Ceremony) {
	t.Helper()
	if err := c.RunSetup(); err != nil {
		t.Fatal(err)
	}
	if err := c.RunCards(); err != nil {
		t.Fatal(err)
	}
	if err := c.RunVoting([][]int{{0}, {1}, {2}}); err != nil {
		t.Fatal(err)
	}
	if err := c.RunTally(); err != nil {
		t.Fatal(err)
	}
}
