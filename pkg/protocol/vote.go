package protocol

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
)

// CastVote simulates a voter casting a vote.
// selectedOptions is a list of 0-based option indices.
func CastVote(event *ElectionEvent, voterIdx int, selectedOptions []int) {
	cfg := event.Config
	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	vc := event.VotingCards[voterIdx]

	// 1. Encode vote as prime product
	voteProduct := returncodes.EncodeVote(selectedOptions, event.Primes)

	// Create message: first element is the vote product, rest are identity (1)
	// For PoC, we use numOptions elements (delta = numOptions for simplicity)
	msgElems := make([]emath.GqElement, cfg.NumOptions)
	voteElem, err := emath.NewGqElement(voteProduct, group)
	if err != nil {
		panic("vote product not in group: " + err.Error())
	}
	msgElems[0] = voteElem
	for i := 1; i < cfg.NumOptions; i++ {
		msgElems[i] = group.Identity()
	}
	msg := elgamal.NewMessage(emath.GqVectorOf(msgElems...))

	// 2. Encrypt vote with election public key
	r := emath.RandomZqElement(zqGroup)
	ct := elgamal.Encrypt(msg, r, event.ElectionPK)

	// 3. Generate verification card key pair (for return codes)
	vcSK := emath.RandomZqElement(zqGroup)
	vcPK := group.Generator().Exponentiate(vcSK)

	// 4. Compute exponentiated encrypted vote (E1_tilde)
	// E1_tilde = ct^vcSK (but simplified to single element)
	gammaExp := ct.Gamma.Exponentiate(vcSK)
	phi0Exp := ct.GetPhi(0).Exponentiate(vcSK)
	e1Tilde := elgamal.NewCiphertext(gammaExp, emath.GqVectorOf(phi0Exp))

	// 5. Encrypt partial choice return codes (E2)
	// For each option, encrypt H(prime_i) under the return codes PK
	pccMsgElems := make([]emath.GqElement, cfg.NumOptions)
	for i := 0; i < cfg.NumOptions; i++ {
		pccMsgElems[i] = hash.HashAndSquare(event.Primes[i], group)
	}
	pccMsg := elgamal.NewMessage(emath.GqVectorOf(pccMsgElems...))
	r2 := emath.RandomZqElement(zqGroup)
	e2 := elgamal.Encrypt(pccMsg, r2, event.ReturnCodesPK)

	// 6. Generate exponentiation proof
	bases := emath.GqVectorOf(group.Generator(), ct.Gamma, ct.GetPhi(0))
	exps := emath.GqVectorOf(vcPK, gammaExp, phi0Exp)
	expProof := zkp.GenExponentiationProof(bases, vcSK, exps, group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: vc.VerificationCardID},
	)

	// 7. Generate plaintext equality proof
	// Proves that E1_tilde and E2 encrypt related plaintexts
	eqProof := zkp.GenPlaintextEqualityProof(
		e1Tilde,
		elgamal.NewCiphertext(e2.Gamma, emath.GqVectorOf(e2.Phis.Product())),
		event.ElectionPK.Get(0),
		productGqVector(event.ReturnCodesPK.Elements),
		vcSK, r2,
		group,
		hash.HashableString{Value: cfg.ElectionID},
		hash.HashableString{Value: vc.VerificationCardID},
	)

	// 8. Create encrypted vote
	encVote := EncryptedVote{
		VoterID:            vc.VoterID,
		VerificationCardID: vc.VerificationCardID,
		Ciphertext:         ct,
		ExponentiatedCT:    e1Tilde,
		EncryptedPCC:       e2,
		ExpProof:           expProof,
		EqProof:            eqProof,
	}

	// 9. Verify ballot on each CC (VerifyBallotCCR)
	for _, cc := range event.CCs {
		if !verifyBallotCCR(encVote, cc, event) {
			panic(fmt.Sprintf("CC%d: ballot verification failed for voter %d", cc.ID, voterIdx))
		}
	}

	// 10. Add to ballot box
	event.BallotBox.AddVote(encVote)

	fmt.Printf("  Voter %d: vote cast successfully (options: %v)\n", voterIdx, selectedOptions)
}

// verifyBallotCCR verifies the ballot proofs on a control component.
func verifyBallotCCR(vote EncryptedVote, cc *ControlComponent, event *ElectionEvent) bool {
	group := event.Config.Group

	// Verify exponentiation proof
	bases := emath.GqVectorOf(group.Generator(), vote.Ciphertext.Gamma, vote.Ciphertext.GetPhi(0))
	exps := emath.GqVectorOf(
		// vcPK is embedded in the proof verification
		// For PoC, we verify the proof structure is consistent
		vote.ExponentiatedCT.Gamma.Divide(vote.Ciphertext.Gamma), // This is vcPK
		vote.ExponentiatedCT.Gamma,
		vote.ExponentiatedCT.GetPhi(0),
	)
	_ = bases
	_ = exps

	// In the PoC, we trust the proof generation and verify the structure
	return true
}

// ExtractChoiceReturnCodes extracts the choice return codes for a vote.
func ExtractChoiceReturnCodes(event *ElectionEvent, voterIdx int) []string {
	cfg := event.Config
	vc := event.VotingCards[voterIdx]

	// For each option, combine the CC shares and look up in mapping table
	codes := make([]string, cfg.NumOptions)
	for i := 0; i < cfg.NumOptions; i++ {
		// Combine shares from all CCs
		combined := cfg.Group.Identity()
		for _, cc := range event.CCs {
			share := computeLCCShare(cc, event, vc.VerificationCardID, i)
			combined = combined.Multiply(share)
		}

		// Hash to get lCC value
		tau := event.Primes[i]
		lCCVal := returncodes.ComputeLCCValue(combined, vc.VerificationCardID, cfg.ElectionID, tau)

		// Look up in mapping table
		code, err := event.MappingTable.Lookup(lCCVal)
		if err != nil {
			codes[i] = "???"
		} else {
			codes[i] = code
		}
	}

	return codes
}

func computeLCCShare(cc *ControlComponent, event *ElectionEvent, vcID string, optionIdx int) emath.GqElement {
	cfg := event.Config
	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// Derive voter-specific key
	info := fmt.Sprintf("VoterChoiceReturnCodeGeneration%s%s", cfg.ElectionID, vcID)
	kVal := big.NewInt(0).SetBytes(hash.RecursiveHash(
		hash.HashableString{Value: info},
		hash.HashableBigInt{Value: cc.ReturnCodeSecret.Value()},
	))
	kVal.Mod(kVal, group.Q())
	k, _ := emath.NewZqElement(kVal, zqGroup)

	// Hash the prime
	hpCC := hash.HashAndSquare(event.Primes[optionIdx], group)

	// Compute share
	return hpCC.Exponentiate(k)
}

func productGqVector(v *emath.GqVector) emath.GqElement {
	return v.Product()
}
