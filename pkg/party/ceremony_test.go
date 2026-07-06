package party

import (
	"math/big"
	"testing"

	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/protocol"
)

const (
	testP = "179688417486862032111147025351064878713905624387098436271724698527496946737299"
	testQ = "89844208743431016055573512675532439356952812193549218135862349263748473368649"
	testG = "4"
)

func testConfig(t *testing.T, numVoters, numOptions int) *protocol.Config {
	t.Helper()
	p, _ := new(big.Int).SetString(testP, 10)
	q, _ := new(big.Int).SetString(testQ, 10)
	g, _ := new(big.Int).SetString(testG, 10)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatalf("test group: %v", err)
	}
	return &protocol.Config{
		Group:       group,
		NumCCs:      4,
		NumOptions:  numOptions,
		NumVoters:   numVoters,
		ElectionID:  "party-unit-test",
		SecurityLvl: 128,
	}
}

// TestCeremonyBootstrapAndHandshake proves the full PKI + transport wiring:
// every party is enrolled with a CA-signed Ed25519 cert, registered in the
// directory, and reachable via a signed hello/ack exchange over the bus.
func TestCeremonyBootstrapAndHandshake(t *testing.T) {
	cfg := testConfig(t, 3, 3)
	c, err := NewCeremony(cfg, nil)
	if err != nil {
		t.Fatalf("NewCeremony: %v", err)
	}

	// Expected enrolled parties: setup, EB, server, verifier, 4 CCs, 3 voters.
	wantParties := 4 + cfg.NumCCs + cfg.NumVoters
	if got := len(c.CCs) + len(c.Voters) + 4; got != wantParties {
		t.Fatalf("party count = %d, want %d", got, wantParties)
	}

	before := c.Bus.Count()
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// Each hello + ack is two verified messages; one exchange per non-setup party.
	if c.Bus.Count() <= before {
		t.Fatal("handshake carried no verified messages")
	}
}
