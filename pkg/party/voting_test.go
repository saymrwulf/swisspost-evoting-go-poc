package party

import (
	"testing"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
	"github.com/user/evote/pkg/zkp"
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

// TestCastAsIntendedCatchesVoteSubstitution simulates malware that encrypts one
// option for the tally (E1) but a different option in the return-code channel
// (E2), so the voter would be shown the return code for the option they intended
// while a different vote is actually tallied. The plaintext-equality proof binds
// E1 and E2, so the CCs reject the ballot — the substitution is caught.
func TestCastAsIntendedCatchesVoteSubstitution(t *testing.T) {
	c := runToVoting(t, 1, 3)
	voter := c.Voters[0]
	// Tally vote = option 0; return-code channel claims option 1.
	if _, err := voter.castBallotSubstituted(t, 0, 1); err == nil {
		t.Fatal("CCs accepted a ballot whose E1 and E2 encrypt different votes")
	}
	if len(c.Server.st.ballotBox) != 0 {
		t.Fatal("substituted ballot was stored")
	}
}

// castBallotSubstituted encrypts option tallyOpt in E1 and option codeOpt in E2,
// attaching an equality proof over the mismatched pair (which cannot verify).
func (p *VoterClient) castBallotSubstituted(t *testing.T, tallyOpt, codeOpt int) (*transport.Envelope, error) {
	t.Helper()
	cfg := p.cer.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)

	tallyElem, _ := emath.NewGqElement(returncodes.EncodeVote([]int{tallyOpt}, p.st.primes), group)
	codeElem, _ := emath.NewGqElement(returncodes.EncodeVote([]int{codeOpt}, p.st.primes), group)

	msgElems := make([]emath.GqElement, cfg.NumOptions)
	msgElems[0] = tallyElem
	for i := 1; i < cfg.NumOptions; i++ {
		msgElems[i] = group.Identity()
	}
	r := emath.RandomZqElement(zq)
	ct := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(msgElems...)), r, p.st.electionPK)

	p.st.vcSK = emath.RandomZqElement(zq)
	vcPK := group.Generator().Exponentiate(p.st.vcSK)
	gammaExp := ct.Gamma.Exponentiate(p.st.vcSK)
	phi0Exp := ct.GetPhi(0).Exponentiate(p.st.vcSK)
	bases := emath.GqVectorOf(group.Generator(), ct.Gamma, ct.GetPhi(0))
	exps := emath.GqVectorOf(vcPK, gammaExp, phi0Exp)
	expProof := zkp.GenExponentiationProof(bases, p.st.vcSK, exps, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: p.st.card.VerificationCardID})

	// E2 encrypts a DIFFERENT option than E1.
	rcPK0 := elgamal.PublicKey{Elements: emath.GqVectorOf(p.st.returnCodePK.Get(0))}
	r2 := emath.RandomZqElement(zq)
	e2 := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(codeElem)), r2, rcPK0)
	c1 := elgamal.NewCiphertext(ct.Gamma, emath.GqVectorOf(ct.GetPhi(0)))
	eqProof := zkp.GenPlaintextEqualityProof(c1, e2,
		p.st.electionPK.Get(0), p.st.returnCodePK.Get(0), r, r2, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: p.st.card.VerificationCardID})

	return p.cer.send(p.id, NameServer, MsgCastBallot, wireBallot{
		VoterID:        p.st.card.VoterID,
		VcID:           p.st.card.VerificationCardID,
		Ciphertext:     encodeCiphertext(ct),
		ExponentiatedG: gammaExp.Value().String(),
		ExponentiatedP: phi0Exp.Value().String(),
		VcPK:           vcPK.Value().String(),
		ExpProof:       encodeExponentiation(expProof),
		ReturnCodeCT:   encodeCiphertext(e2),
		EqProof:        encodePlaintextEquality(eqProof),
	})
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
	msgElems := make([]emath.GqElement, p.cer.Config.NumOptions)
	msgElems[0] = voteElem
	for i := 1; i < len(msgElems); i++ {
		msgElems[i] = group.Identity()
	}
	ct := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(msgElems...)), emath.RandomZqElement(zq), p.st.electionPK)
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
