package party

import (
	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/zkp"
)

// PublicTranscript is the append-only bulletin board: everything a remote
// verifier needs to re-check the election, and nothing secret. It is populated
// by the parties as the ceremony proceeds and consumed by the verifier.
type PublicTranscript struct {
	ElectionID string

	// Setup artifacts.
	CCElectionPKs []elgamal.PublicKey  // per-CC election public keys
	CCSchnorr     [][]zkp.SchnorrProof // per-CC Schnorr proofs of key knowledge
	EBPublicKey   elgamal.PublicKey    // electoral board public key
	ElectionPK    elgamal.PublicKey    // combined election public key
	ReturnCodePK  elgamal.PublicKey    // combined return-codes public key (CCs only, no EB)
	Primes        []string             // decimal encodings of the encoding primes

	// Tally artifacts.
	MixInput        *elgamal.CiphertextVector   // padded ballot ciphertexts fed to shuffle 0
	Shuffles        []mixnet.VerifiableShuffle  // one per CC + EB
	PartialDecrypts []*elgamal.CiphertextVector // partial decryption after each CC
	DecryptProofs   [][]zkp.DecryptionProof     // per-stage decryption proofs
	FinalPlaintexts []*emath.GqVector           // EB's decrypted messages
	Result          map[int]int                 // option index → count
}
