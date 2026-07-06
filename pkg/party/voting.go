package party

import (
	"fmt"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
	"github.com/user/evote/pkg/zkp"
)

// Voting-phase message types.
const (
	MsgCastBallot    = "cast-ballot"   // voter -> server
	MsgBallotStored  = "ballot-stored" // server -> voter
	MsgVerifyBallot  = "verify-ballot" // server -> CCj
	MsgBallotVerdict = "ballot-verdict"
)

// wireBallot is a submitted ballot. It carries the encrypted vote, the
// exponentiated ciphertext, the verification-card public key (persisted so a
// remote party can reconstruct the proof statement — finding F6), the
// exponentiation proof binding vcPK to the exponentiation, and the return-code
// ciphertext E2 with a plaintext-equality proof binding it to the ballot (so the
// return code is genuinely derived from the submitted vote — cast-as-intended).
type wireBallot struct {
	VoterID        string                `json:"voter_id"`
	VcID           string                `json:"vc_id"`
	Ciphertext     wireCiphertext        `json:"ciphertext"`
	ExponentiatedG string                `json:"exp_gamma"`
	ExponentiatedP string                `json:"exp_phi0"`
	VcPK           string                `json:"vc_pk"`
	ExpProof       wireSchnorr           `json:"exp_proof"`
	ReturnCodeCT   wireCiphertext        `json:"return_code_ct"` // E2: Enc(vote, returnCodesPK[0])
	EqProof        wirePlaintextEquality `json:"eq_proof"`       // proves E1[0] and E2 encrypt the same vote
}

// RunVoting has every voter encrypt its selection and submit a ballot; the
// server routes each ballot to all CCs for proof verification and stores the
// accepted ballots. Selections are provided per voter (indexed by voter).
func (c *Ceremony) RunVoting(selections [][]int) error {
	c.logf("\n--- VOTING PHASE (multi-party) ---")
	for v, voter := range c.Voters {
		sel := []int{0}
		if v < len(selections) && len(selections[v]) > 0 {
			sel = selections[v]
		}
		if _, err := voter.castBallot(sel); err != nil {
			return fmt.Errorf("voter %d cast: %w", v, err)
		}
	}
	c.logf("  voting: %d ballots submitted and accepted", len(c.Voters))
	return nil
}

// castBallot (voter) encrypts the selection, builds the exponentiation proof,
// and submits the ballot to the server.
func (p *VoterClient) castBallot(selected []int) (*transport.Envelope, error) {
	cfg := p.cer.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)
	if p.st.card == nil {
		return nil, fmt.Errorf("%s has no voting card", p.id.Name)
	}
	p.st.selected = selected

	// 1. Encode + encrypt the vote. The message has NumOptions components (vote
	//    product in slot 0, identity elsewhere) so the ciphertext width matches
	//    the CC/EB key size used to decrypt during the mix-net.
	product := returncodes.EncodeVote(selected, p.st.primes)
	voteElem, err := emath.NewGqElement(product, group)
	if err != nil {
		return nil, fmt.Errorf("vote product not in group: %w", err)
	}
	msgElems := make([]emath.GqElement, cfg.NumOptions)
	msgElems[0] = voteElem
	for i := 1; i < cfg.NumOptions; i++ {
		msgElems[i] = group.Identity()
	}
	msgRandomness := emath.RandomZqElement(zq)
	ct := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(msgElems...)), msgRandomness, p.st.electionPK)

	// 2. Verification-card key pair.
	p.st.vcSK = emath.RandomZqElement(zq)
	vcPK := group.Generator().Exponentiate(p.st.vcSK)

	// 3. Exponentiated ciphertext components (E1_tilde).
	gammaExp := ct.Gamma.Exponentiate(p.st.vcSK)
	phi0Exp := ct.GetPhi(0).Exponentiate(p.st.vcSK)

	// 4. Exponentiation proof: knowledge of vcSK s.t. (vcPK,gammaExp,phi0Exp) are
	//    (g,gamma,phi0) raised to the same vcSK. This binds the ballot to vcPK.
	bases := emath.GqVectorOf(group.Generator(), ct.Gamma, ct.GetPhi(0))
	exps := emath.GqVectorOf(vcPK, gammaExp, phi0Exp)
	expProof := zkp.GenExponentiationProof(bases, p.st.vcSK, exps, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: p.st.card.VerificationCardID},
	)

	// 5. Return-code ciphertext E2 and the plaintext-equality proof binding it
	//    to the ballot. E2 encrypts the same vote value (slot 0) under the
	//    return-codes key; the proof lets the CCs trust that the return code
	//    they compute from E2 reflects the actually-submitted vote. (Single
	//    selected option — the return-code channel is defined for one choice.)
	rcPK0 := elgamal.PublicKey{Elements: emath.GqVectorOf(p.st.returnCodePK.Get(0))}
	r2 := emath.RandomZqElement(zq)
	e2 := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(voteElem)), r2, rcPK0)

	// Single-component view of the ballot's slot 0 for the equality statement.
	c1 := elgamal.NewCiphertext(ct.Gamma, emath.GqVectorOf(ct.GetPhi(0)))
	eqProof := zkp.GenPlaintextEqualityProof(
		c1, e2,
		p.st.electionPK.Get(0), p.st.returnCodePK.Get(0),
		msgRandomness, r2, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: p.st.card.VerificationCardID},
	)

	ballot := wireBallot{
		VoterID:        p.st.card.VoterID,
		VcID:           p.st.card.VerificationCardID,
		Ciphertext:     encodeCiphertext(ct),
		ExponentiatedG: gammaExp.Value().String(),
		ExponentiatedP: phi0Exp.Value().String(),
		VcPK:           vcPK.Value().String(),
		ExpProof:       encodeExponentiation(expProof),
		ReturnCodeCT:   encodeCiphertext(e2),
		EqProof:        encodePlaintextEquality(eqProof),
	}
	return p.cer.send(p.id, NameServer, MsgCastBallot, ballot)
}

// handleCastBallot (server) validates a ballot's structure, asks every CC to
// verify its exponentiation proof, and stores it on unanimous acceptance.
func (p *VotingServer) handleCastBallot(env *transport.Envelope) (*transport.Envelope, error) {
	var b wireBallot
	if err := transport.UnmarshalPayload(env.Payload, &b); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group

	// Decode + validate all group elements (rejects malformed ballots cleanly).
	ct, err := b.Ciphertext.decode(group)
	if err != nil {
		return nil, fmt.Errorf("ballot ciphertext: %w", err)
	}
	vcPK, err := strToGq(b.VcPK, group)
	if err != nil {
		return nil, fmt.Errorf("ballot vcPK: %w", err)
	}
	if _, err := strToGq(b.ExponentiatedG, group); err != nil {
		return nil, fmt.Errorf("ballot exp gamma: %w", err)
	}
	if _, err := strToGq(b.ExponentiatedP, group); err != nil {
		return nil, fmt.Errorf("ballot exp phi0: %w", err)
	}

	// Route to every CC for proof verification; require unanimous acceptance.
	for j := 0; j < p.cer.Config.NumCCs; j++ {
		env2, err := p.cer.send(p.id, CCName(j), MsgVerifyBallot, b)
		if err != nil {
			return nil, fmt.Errorf("server->cc%d verify: %w", j, err)
		}
		var verdict ballotVerdict
		if err := transport.UnmarshalPayload(env2.Payload, &verdict); err != nil {
			return nil, err
		}
		if !verdict.Accept {
			return nil, fmt.Errorf("cc%d rejected ballot %s: %s", j, b.VcID, verdict.Reason)
		}
	}

	// Store the ballot (persisting vcPK, finding F6).
	p.st.ballotBox = append(p.st.ballotBox, encryptedBallot{
		VoterID:            b.VoterID,
		VerificationCardID: b.VcID,
		Ciphertext:         ct,
		VcPK:               vcPK,
	})
	return reply(p.id, env.From, MsgBallotStored, env.Nonce, ackPayload{Party: p.id.Name, OK: true})
}

type ballotVerdict struct {
	Accept bool   `json:"accept"`
	Reason string `json:"reason"`
}

// handleVerifyBallot (CC) re-derives the exponentiation-proof statement and
// verifies it. A malformed proof yields a clean reject, never a panic.
func (p *ControlComponent) handleVerifyBallot(env *transport.Envelope) (*transport.Envelope, error) {
	var b wireBallot
	if err := transport.UnmarshalPayload(env.Payload, &b); err != nil {
		return nil, err
	}
	cfg := p.cer.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)

	reject := func(reason string) (*transport.Envelope, error) {
		return reply(p.id, env.From, MsgBallotVerdict, env.Nonce, ballotVerdict{Accept: false, Reason: reason})
	}

	ct, err := b.Ciphertext.decode(group)
	if err != nil {
		return reject("bad ciphertext")
	}
	vcPK, err := strToGq(b.VcPK, group)
	if err != nil {
		return reject("bad vcPK")
	}
	gammaExp, err := strToGq(b.ExponentiatedG, group)
	if err != nil {
		return reject("bad exp gamma")
	}
	phi0Exp, err := strToGq(b.ExponentiatedP, group)
	if err != nil {
		return reject("bad exp phi0")
	}
	proof, err := b.ExpProof.decodeExponentiation(zq)
	if err != nil {
		return reject("bad proof encoding")
	}

	bases := emath.GqVectorOf(group.Generator(), ct.Gamma, ct.GetPhi(0))
	exps := emath.GqVectorOf(vcPK, gammaExp, phi0Exp)
	ok := zkp.VerifyExponentiationProof(bases, exps, proof, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: b.VcID},
	)
	if !ok {
		return reject("exponentiation proof INVALID")
	}

	// Verify the plaintext-equality proof binding E2 to the ballot's slot 0.
	// This is what makes the return code cast-as-intended: if E2 encrypted a
	// different vote than the ballot, this proof fails and the ballot is
	// rejected, so the code computed from E2 must reflect the tallied vote.
	e2, err := b.ReturnCodeCT.decode(group)
	if err != nil {
		return reject("bad return-code ciphertext")
	}
	eqProof, err := b.EqProof.decode(zq)
	if err != nil {
		return reject("bad equality proof encoding")
	}
	c1 := elgamal.NewCiphertext(ct.Gamma, emath.GqVectorOf(ct.GetPhi(0)))
	eqOK := zkp.VerifyPlaintextEqualityProof(
		c1, e2,
		p.cer.Transcript.ElectionPK.Get(0), p.cer.Transcript.ReturnCodePK.Get(0),
		eqProof, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: b.VcID},
	)
	if !eqOK {
		return reject("plaintext-equality proof INVALID")
	}
	return reply(p.id, env.From, MsgBallotVerdict, env.Nonce, ballotVerdict{Accept: true})
}
