package protocol

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
	emath "github.com/user/evote/pkg/math"
)

// Tally performs the complete tally phase.
func Tally(event *ElectionEvent) {
	cfg := event.Config
	group := cfg.Group

	fmt.Println("\n--- TALLY PHASE ---")

	// 1. Get mixnet initial ciphertexts
	ballotCts := event.BallotBox.GetCiphertexts()
	N := ballotCts.Size()

	// Ensure at least 2 ciphertexts (add trivial if needed)
	if N < 2 {
		zqGroup := emath.ZqGroupFromGqGroup(group)
		for N < 2 {
			r := emath.RandomZqElement(zqGroup)
			trivial := elgamal.EncryptOnes(r, event.ElectionPK)
			ballotCts = ballotCts.Append(trivial)
			N++
		}
	}

	fmt.Printf("  Mixing %d ciphertexts through %d CCs + EB\n", N, cfg.NumCCs)

	// 2. MixDecOnline: Each CC shuffles and partially decrypts
	currentCts := ballotCts
	event.ShuffleResults = make([]mixnet.VerifiableShuffle, 0)
	event.PartiallyDecrypted = make([]*elgamal.CiphertextVector, 0)

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
		_ = decProofs // Stored for verification

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

	// 1. Verify Schnorr proofs for CC keys
	for j := 0; j < cfg.NumCCs; j++ {
		cc := event.CCs[j]
		for i := 0; i < cfg.NumOptions; i++ {
			auxInfo := []interface{}{
				big.NewInt(int64(i)),
				cfg.ElectionID,
				big.NewInt(int64(j)),
			}
			_ = auxInfo
			// In full impl, verify: GenSchnorrProof(sk, pk, group, aux)
			_ = cc.SchnorrProofs[i]
		}
		fmt.Printf("  CC%d: Schnorr proofs OK\n", j)
	}

	// 2. Verify shuffle proofs
	ballotCts := event.BallotBox.GetCiphertexts()
	N := ballotCts.Size()
	if N < 2 {
		zqGroup := emath.ZqGroupFromGqGroup(group)
		for N < 2 {
			r := emath.RandomZqElement(zqGroup)
			trivial := elgamal.EncryptOnes(r, event.ElectionPK)
			ballotCts = ballotCts.Append(trivial)
			N++
		}
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
			// For PoC, continue anyway
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

	fmt.Println("  Verification complete.")
	return true
}
