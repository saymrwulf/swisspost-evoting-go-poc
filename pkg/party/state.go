package party

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
)

// The state structs below hold each party's PRIVATE state. Nothing here may be
// read by another party except through an explicit signed message.

// setupState is the setup component's working store while assembling cards.
type setupState struct {
	primes       []*big.Int
	votingCards  []*votingCard
	mappingTable *returncodes.MappingTable
	electionPK   elgamal.PublicKey
	returnCodePK elgamal.PublicKey
}

// ccState is a control component's private key material and mix state.
type ccState struct {
	keyPair          elgamal.KeyPair
	returnCodeSecret emath.ZqElement
	schnorrProofs    []zkp.SchnorrProof

	// Tally working state.
	shuffle    mixnet.VerifiableShuffle
	decProofs  []zkp.DecryptionProof
	shuffleIn  *elgamal.CiphertextVector
	shuffleOut *elgamal.CiphertextVector
}

// ebState is the electoral board's private key material.
type ebState struct {
	passwords []string
	keyPair   elgamal.KeyPair
}

// serverState is the voting server / ballot box.
type serverState struct {
	mappingTable *returncodes.MappingTable
	ballotBox    []encryptedBallot
	electionPK   elgamal.PublicKey
	returnCodePK elgamal.PublicKey
	primes       []*big.Int
}

// voterState is a voter client's private card and ballot secrets.
type voterState struct {
	card     *votingCard
	vcSK     emath.ZqElement
	selected []int
}

// votingCard is a voter's credential bundle (private to the voter, produced by
// the setup component and delivered over a confidential channel).
type votingCard struct {
	VoterID            string   `json:"voter_id"`
	VerificationCardID string   `json:"vc_id"`
	StartVotingKey     string   `json:"svk"`
	ChoiceReturnCodes  []string `json:"choice_return_codes"`
	VoteConfirmCode    string   `json:"vote_confirm_code"`
	BallotCastingKey   string   `json:"bck"`
}

// encryptedBallot is a ballot as stored in the ballot box.
type encryptedBallot struct {
	VoterID            string
	VerificationCardID string
	Ciphertext         elgamal.Ciphertext
	VcPK               emath.GqElement
}
