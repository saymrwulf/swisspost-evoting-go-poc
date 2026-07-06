package party

import (
	"testing"
)

// TestRunSetupDistributedKeygen runs the distributed key generation over the
// transport and checks that: every CC's Schnorr proof verified (RunSetup would
// have errored otherwise), the combined election public key equals the product
// of the individual CC and EB keys, and the transcript captured the artifacts.
func TestRunSetupDistributedKeygen(t *testing.T) {
	cfg := testConfig(t, 5, 3)
	c, err := NewCeremony(cfg, nil)
	if err != nil {
		t.Fatalf("NewCeremony: %v", err)
	}
	if err := c.RunSetup(); err != nil {
		t.Fatalf("RunSetup: %v", err)
	}

	tr := c.Transcript
	if len(tr.CCElectionPKs) != cfg.NumCCs {
		t.Fatalf("transcript has %d CC keys, want %d", len(tr.CCElectionPKs), cfg.NumCCs)
	}
	if len(tr.Primes) != cfg.NumOptions {
		t.Fatalf("transcript has %d primes, want %d", len(tr.Primes), cfg.NumOptions)
	}

	// Recompute election PK = Π CC_j.PK * EB.PK per component and compare.
	for i := 0; i < cfg.NumOptions; i++ {
		want := cfg.Group.Identity()
		for j := 0; j < cfg.NumCCs; j++ {
			want = want.Multiply(tr.CCElectionPKs[j].Elements.Get(i))
		}
		want = want.Multiply(tr.EBPublicKey.Elements.Get(i))
		got := tr.ElectionPK.Elements.Get(i)
		if !got.Equals(want) {
			t.Fatalf("election PK component %d mismatch", i)
		}
	}

	// The setup component must actually hold private primes; a CC must hold a
	// secret key that never appeared in the transcript.
	if c.Setup.st.primes == nil {
		t.Fatal("setup component did not retain encoding primes")
	}
	if c.CCs[0].st.keyPair.SK.Elements == nil {
		t.Fatal("cc0 did not retain its private key")
	}
}
