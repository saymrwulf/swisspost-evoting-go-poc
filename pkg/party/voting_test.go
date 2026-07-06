package party

import (
	"testing"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
)

func runToVoting(t *testing.T, voters, options int) *Ceremony {
	t.Helper()
	cfg := testConfig(t, voters, options)
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
	return c
}

// TestRunVotingBallotFlow submits ballots and confirms each is CC-verified and
// stored with its vcPK persisted.
func TestRunVotingBallotFlow(t *testing.T) {
	c := runToVoting(t, 4, 3)
	sel := [][]int{{0}, {1}, {1}, {2}}
	if err := c.RunVoting(sel); err != nil {
		t.Fatalf("RunVoting: %v", err)
	}
	if got := len(c.Server.st.ballotBox); got != 4 {
		t.Fatalf("ballot box has %d ballots, want 4", got)
	}
	for i, b := range c.Server.st.ballotBox {
		if b.VcPK.Value() == nil {
			t.Fatalf("ballot %d did not persist vcPK", i)
		}
	}
}

// TestBallotWithBadProofRejected confirms a ballot whose exponentiation proof
// does not match is rejected by the CCs (and the server does not store it),
// without any panic.
func TestBallotWithBadProofRejected(t *testing.T) {
	c := runToVoting(t, 1, 3)
	voter := c.Voters[0]

	// Build a valid ballot, then corrupt the proof before submitting.
	if _, err := voter.castBallotTampered(t); err == nil {
		t.Fatal("server accepted a ballot with a tampered proof")
	}
	if len(c.Server.st.ballotBox) != 0 {
		t.Fatal("tampered ballot was stored")
	}
}

// castBallotTampered submits a structurally valid ballot (real ciphertext,
// well-formed group elements) but with a zeroed exponentiation proof that cannot
// verify. Used only by the test above.
func (p *VoterClient) castBallotTampered(t *testing.T) (*transport.Envelope, error) {
	t.Helper()
	group := p.cer.Config.Group
	zq := emath.ZqGroupFromGqGroup(group)
	product := returncodes.EncodeVote([]int{0}, p.st.primes)
	voteElem, _ := emath.NewGqElement(product, group)
	ct := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(voteElem)), emath.RandomZqElement(zq), singlePK(p.st.electionPK))
	g := group.Generator().Value().String()
	return p.cer.send(p.id, NameServer, MsgCastBallot, wireBallot{
		VoterID:        p.st.card.VoterID,
		VcID:           p.st.card.VerificationCardID,
		Ciphertext:     encodeCiphertext(ct),
		ExponentiatedG: g,
		ExponentiatedP: g,
		VcPK:           g,
		ExpProof:       wireSchnorr{E: "0", Z: "0"},
	})
}
