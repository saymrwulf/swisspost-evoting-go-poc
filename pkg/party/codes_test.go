package party

import (
	"testing"
)

// TestRunCardsConfidentialDistribution runs setup + card generation and checks
// that each voter received its card over the confidential channel, the cards
// carry the right number of return codes, and the server received the mapping
// table plus public election parameters.
func TestRunCardsConfidentialDistribution(t *testing.T) {
	cfg := testConfig(t, 4, 3)
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

	for v, voter := range c.Voters {
		if voter.st.card == nil {
			t.Fatalf("voter %d never received a card", v)
		}
		if voter.st.card.VerificationCardID == "" {
			t.Fatalf("voter %d card missing vcID", v)
		}
		if len(voter.st.card.ChoiceReturnCodes) != cfg.NumOptions {
			t.Fatalf("voter %d card has %d choice codes, want %d", v, len(voter.st.card.ChoiceReturnCodes), cfg.NumOptions)
		}
	}

	if c.Server.st.mappingTable == nil {
		t.Fatal("server never received the mapping table")
	}
	// Each voter contributes NumOptions choice entries + 1 confirm entry.
	wantEntries := cfg.NumVoters * (cfg.NumOptions + 1)
	if got := c.Server.st.mappingTable.Size(); got != wantEntries {
		t.Fatalf("mapping table has %d entries, want %d", got, wantEntries)
	}
	if c.Server.st.electionPK.Elements == nil {
		t.Fatal("server did not receive the election public key")
	}
}
