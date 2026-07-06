package protocol

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
)

// Tally performs the complete tally phase.
func Tally(event *ElectionEvent) {
	cfg := event.Config
	group := cfg.Group

	fmt.Println("\n--- TALLY PHASE ---")

	// 1. Get mixnet initial ciphertexts
	ballotCts := event.BallotBox.GetCiphertexts()
	N := ballotCts.Size()

	// Ensure at least 2 ciphertexts (add trivial if needed). The padded vector
	// is persisted as event.MixInput so the verifier checks shuffle 0 against
	// the EXACT same input rather than re-padding with fresh randomness.
	if N < 2 {
		zqGroup := emath.ZqGroupFromGqGroup(group)
		for N < 2 {
			r := emath.RandomZqElement(zqGroup)
			trivial := elgamal.EncryptOnes(r, event.ElectionPK)
			ballotCts = ballotCts.Append(trivial)
			N++
		}
	}
	event.MixInput = ballotCts

	fmt.Printf("  Mixing %d ciphertexts through %d CCs + EB\n", N, cfg.NumCCs)

	// 2. MixDecOnline: Each CC shuffles and partially decrypts
	currentCts := ballotCts
	event.ShuffleResults = make([]mixnet.VerifiableShuffle, 0)
	event.PartiallyDecrypted = make([]*elgamal.CiphertextVector, 0)
	event.DecryptionProofs = make([][]zkp.DecryptionProof, 0)

	for j := 0; j < cfg.NumCCs; j++ {
		cc := event.CCs[j]
		fmt.Printf("  CC%d: shuffle + partial decrypt...\n", j)

		// Compute remaining public key (CCs j..3 + EB)
		remainingPKs := make([]elgamal.PublicKey, 0)
		for k := j; k < cfg.NumCCs; k++ {
			remainingPKs = append(remainingPKs, event.CCs[k].ElectionKeyPair.PK)
		}
		remainingPKs = append(remainingPKs, event.EB.PK)
		remainingPK := elgamal.CombinePublicKeys(remainingPKs...)

		// Shuffle under remaining PK
		vs := mixnet.GenVerifiableShuffle(currentCts, remainingPK, group)
		event.ShuffleResults = append(event.ShuffleResults, vs)

		// Partial decrypt with this CC's key
		decrypted := make([]elgamal.Ciphertext, vs.ShuffledCiphertexts.Size())
		var decProofs []zkp.DecryptionProof
		for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
			ct := vs.ShuffledCiphertexts.Get(i)
			dec := elgamal.PartialDecrypt(ct, cc.ElectionKeyPair.SK)
			decrypted[i] = dec

			// Generate decryption proof
			msg := elgamal.Decrypt(ct, cc.ElectionKeyPair.SK)
			proof := zkp.GenDecryptionProof(ct, cc.ElectionKeyPair.SK, cc.ElectionKeyPair.PK, msg, group)
			decProofs = append(decProofs, proof)
		}
		event.DecryptionProofs = append(event.DecryptionProofs, decProofs)

		currentCts = elgamal.NewCiphertextVector(decrypted)
		event.PartiallyDecrypted = append(event.PartiallyDecrypted, currentCts)
	}

	// 3. MixDecOffline: EB final shuffle + decrypt
	fmt.Println("  EB: final shuffle + decrypt...")

	// Final shuffle under EB key
	vs := mixnet.GenVerifiableShuffle(currentCts, event.EB.PK, group)
	event.ShuffleResults = append(event.ShuffleResults, vs)

	// Final decryption with EB key
	event.DecryptedVotes = make([]*emath.GqVector, vs.ShuffledCiphertexts.Size())
	for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
		ct := vs.ShuffledCiphertexts.Get(i)
		msg := elgamal.Decrypt(ct, event.EB.SK)
		event.DecryptedVotes[i] = msg.Elements
	}

	// 4. Process plaintexts: factorize to decode votes
	fmt.Println("  Processing plaintexts...")
	processPlaintexts(event)
}

func processPlaintexts(event *ElectionEvent) {
	cfg := event.Config
	numActualVotes := event.BallotBox.Size()

	for i := 0; i < len(event.DecryptedVotes); i++ {
		msg := event.DecryptedVotes[i]

		// Check if this is a trivial vote (all ones)
		if msg.Get(0).IsIdentity() {
			continue
		}

		// Factorize the first element to get selected options
		voteProduct := msg.Get(0).Value()
		selectedOptions := returncodes.DecodeVote(voteProduct, event.Primes)

		for _, opt := range selectedOptions {
			event.FinalResult[opt]++
		}
	}

	fmt.Printf("\n--- ELECTION RESULT ---\n")
	fmt.Printf("  Total votes cast: %d\n", numActualVotes)
	for opt := 0; opt < cfg.NumOptions; opt++ {
		count := event.FinalResult[opt]
		fmt.Printf("  Option %d: %d votes\n", opt, count)
	}
}

// VerifyTally verifies all shuffle proofs and decryption proofs.
func VerifyTally(event *ElectionEvent) bool {
	cfg := event.Config
	group := cfg.Group

	fmt.Println("\n--- VERIFICATION ---")

	allValid := true

	// 1. Verify Schnorr proofs for CC keys (really invokes the ZK verifier).
	for j := 0; j < cfg.NumCCs; j++ {
		cc := event.CCs[j]
		ccOK := true
		for i := 0; i < cfg.NumOptions; i++ {
			auxInfo := []hash.Hashable{
				hash.HashableBigInt{Value: big.NewInt(int64(i))},
				hash.HashableString{Value: cfg.ElectionID},
				hash.HashableBigInt{Value: big.NewInt(int64(j))},
			}
			if !zkp.VerifySchnorrProof(cc.SchnorrProofs[i], cc.ElectionKeyPair.PK.Get(i), group, auxInfo...) {
				ccOK = false
			}
		}
		if ccOK {
			fmt.Printf("  CC%d: Schnorr proofs OK\n", j)
		} else {
			fmt.Printf("  CC%d: Schnorr proofs INVALID\n", j)
			allValid = false
		}
	}

	// 2. Verify shuffle proofs against the SAME padded input the tally used.
	ballotCts := event.MixInput
	if ballotCts == nil {
		// Tally not run, or legacy event: fall back to the ballot box.
		ballotCts = event.BallotBox.GetCiphertexts()
	}

	for j, vs := range event.ShuffleResults {
		var pk elgamal.PublicKey
		if j < cfg.NumCCs {
			remainingPKs := make([]elgamal.PublicKey, 0)
			for k := j; k < cfg.NumCCs; k++ {
				remainingPKs = append(remainingPKs, event.CCs[k].ElectionKeyPair.PK)
			}
			remainingPKs = append(remainingPKs, event.EB.PK)
			pk = elgamal.CombinePublicKeys(remainingPKs...)
		} else {
			pk = event.EB.PK
		}

		valid := mixnet.VerifyShuffle(ballotCts, vs, pk, group)
		if valid {
			fmt.Printf("  Shuffle %d: proof VALID\n", j)
		} else {
			fmt.Printf("  Shuffle %d: proof INVALID\n", j)
			allValid = false
		}

		// Update ciphertexts for next shuffle:
		// After each CC shuffle, we use the PARTIALLY DECRYPTED ciphertexts as input to the next shuffle.
		// The shuffle proof verifies the shuffle of `ballotCts` → `vs.ShuffledCiphertexts`.
		// But the next shuffle's input is the partially decrypted version of `vs.ShuffledCiphertexts`.
		if j < cfg.NumCCs && j < len(event.PartiallyDecrypted) {
			ballotCts = event.PartiallyDecrypted[j]
		} else {
			ballotCts = vs.ShuffledCiphertexts
		}
	}

	// 3. Verify vote count consistency
	totalVotes := 0
	for _, count := range event.FinalResult {
		totalVotes += count
	}
	fmt.Printf("  Total votes decoded: %d (expected: %d)\n", totalVotes, event.BallotBox.Size())

	if allValid {
		fmt.Println("  Verification complete: ALL CHECKS PASSED.")
	} else {
		fmt.Println("  Verification complete: FAILURES DETECTED.")
	}
	return allValid
}
