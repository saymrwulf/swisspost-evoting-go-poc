package protocol

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
)

// ControlComponent represents one of the 4 control components.
type ControlComponent struct {
	ID               int
	ElectionKeyPair  elgamal.KeyPair
	ReturnCodeSecret emath.ZqElement
	SchnorrProofs    []zkp.SchnorrProof
}

// ElectoralBoard holds the electoral board's key material.
type ElectoralBoard struct {
	Passwords []string
	SK        elgamal.PrivateKey
	PK        elgamal.PublicKey
}

// VotingCard holds a voter's credentials.
type VotingCard struct {
	VoterID            string
	VerificationCardID string
	StartVotingKey     string   // SVK for authentication
	ChoiceReturnCodes  []string // Expected choice return codes
	VoteConfirmCode    string   // Expected vote cast return code
	BallotCastingKey   string   // BCK for confirmation
}

// EncryptedVote holds a voter's encrypted ballot and proofs.
type EncryptedVote struct {
	VoterID            string
	VerificationCardID string
	Ciphertext         elgamal.Ciphertext
	ExponentiatedCT    elgamal.Ciphertext // E1_tilde (size 1)
	EncryptedPCC       elgamal.Ciphertext // E2 (encrypted partial choice return codes)
	ExpProof           zkp.ExponentiationProof
	EqProof            zkp.PlaintextEqualityProof
}

// BallotBox holds all confirmed encrypted votes.
type BallotBox struct {
	Votes []EncryptedVote
}

// ElectionEvent holds the entire election state.
type ElectionEvent struct {
	Config        *Config
	CCs           []*ControlComponent
	EB            *ElectoralBoard
	ElectionPK    elgamal.PublicKey // Combined election public key
	ReturnCodesPK elgamal.PublicKey // Combined return codes public key
	Primes        []*big.Int        // Small primes for vote encoding
	VotingCards   []*VotingCard
	BallotBox     *BallotBox
	MappingTable  *returncodes.MappingTable
	// Tally results
	MixInput           *elgamal.CiphertextVector // Padded ballot ciphertexts fed to shuffle 0 (persisted so the verifier uses the SAME padding)
	ShuffleResults     []mixnet.VerifiableShuffle
	PartiallyDecrypted []*elgamal.CiphertextVector // Partially decrypted ciphertexts after each CC
	DecryptionProofs   [][]zkp.DecryptionProof     // Per-CC decryption proofs (one slice per shuffle stage)
	DecryptedVotes     []*emath.GqVector
	FinalResult        map[int]int // option index → vote count
}

// NewBallotBox creates an empty ballot box.
func NewBallotBox() *BallotBox {
	return &BallotBox{Votes: []EncryptedVote{}}
}

// AddVote adds a vote to the ballot box.
func (bb *BallotBox) AddVote(vote EncryptedVote) {
	bb.Votes = append(bb.Votes, vote)
}

// Size returns the number of votes.
func (bb *BallotBox) Size() int {
	return len(bb.Votes)
}

// GetCiphertexts returns all vote ciphertexts as a CiphertextVector.
func (bb *BallotBox) GetCiphertexts() *elgamal.CiphertextVector {
	cts := make([]elgamal.Ciphertext, len(bb.Votes))
	for i, v := range bb.Votes {
		cts[i] = v.Ciphertext
	}
	return elgamal.NewCiphertextVector(cts)
}
