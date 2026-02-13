package protocol

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
)

// ConfirmVote simulates vote confirmation (voter enters BCK).
func ConfirmVote(event *ElectionEvent, voterIdx int) string {
	cfg := event.Config
	vc := event.VotingCards[voterIdx]

	// Combine LVCC shares from all CCs
	combined := cfg.Group.Identity()
	for _, cc := range event.CCs {
		share := computeLVCCShare(cc, event, vc.VerificationCardID)
		combined = combined.Multiply(share)
	}

	// Hash to get lVCC value
	lVCCVal := returncodes.ComputeLVCCValue(combined, vc.VerificationCardID, cfg.ElectionID)

	// Look up in mapping table
	code, err := event.MappingTable.Lookup(lVCCVal)
	if err != nil {
		return "???"
	}

	fmt.Printf("  Voter %d: vote confirmed (VCC: %s)\n", voterIdx, code)
	return code
}

func computeLVCCShare(cc *ControlComponent, event *ElectionEvent, vcID string) emath.GqElement {
	cfg := event.Config
	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// Derive voter-specific confirmation key
	info := fmt.Sprintf("VoterVoteCastReturnCodeGeneration%s%s", cfg.ElectionID, vcID)
	kVal := new(big.Int).SetBytes(hash.RecursiveHash(
		hash.HashableString{Value: info},
		hash.HashableBigInt{Value: cc.ReturnCodeSecret.Value()},
	))
	kVal.Mod(kVal, group.Q())
	k, _ := emath.NewZqElement(kVal, zqGroup)

	// Hash the confirmation key
	ckVal := hash.RecursiveHashToZq(group.Q(),
		hash.HashableString{Value: "ConfirmationKey"},
		hash.HashableString{Value: vcID},
	)
	ckPlusOne := new(big.Int).Add(ckVal, big.NewInt(1))
	// Square to ensure group membership
	ckSquared := new(big.Int).Exp(ckPlusOne, big.NewInt(2), group.P())
	hCK := hash.HashAndSquare(ckSquared, group)

	return hCK.Exponentiate(k)
}
