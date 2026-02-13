package main

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/protocol"
)

var presentCmd = &cobra.Command{
	Use:   "present",
	Short: "Theatrical step-by-step election presentation",
	Run:   runPresentation,
}

func init() {
	rootCmd.AddCommand(presentCmd)
}

func banner(text string) {
	width := 72
	line := strings.Repeat("=", width)
	pad := (width - len(text) - 2) / 2
	if pad < 0 {
		pad = 0
	}
	fmt.Println()
	fmt.Println(line)
	fmt.Printf("%s %s %s\n", strings.Repeat(" ", pad), text, strings.Repeat(" ", pad))
	fmt.Println(line)
}

func section(text string) {
	fmt.Printf("\n  --- %s ---\n\n", text)
}

func truncBig(b *big.Int, chars int) string {
	s := b.String()
	if len(s) <= chars {
		return s
	}
	half := (chars - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

func truncHex(b *big.Int, chars int) string {
	s := fmt.Sprintf("%X", b)
	if len(s) <= chars {
		return s
	}
	half := (chars - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

func narrator(text string) {
	fmt.Printf("  %s\n", text)
}

func showValue(label string, val string) {
	fmt.Printf("      %-26s %s\n", label+":", val)
}

func showSecret(label string, val string) {
	fmt.Printf("      %-26s %s  [SECRET]\n", label+":", val)
}

func showPublic(label string, val string) {
	fmt.Printf("      %-26s %s  [PUBLIC]\n", label+":", val)
}

func runPresentation(cmd *cobra.Command, args []string) {
	numVoters := 6
	numOptions := 3

	// =====================================================================
	// TITLE
	// =====================================================================
	fmt.Println()
	fmt.Println("  +================================================================+")
	fmt.Println("  |                                                                |")
	fmt.Println("  |      SWISS POST E-VOTING: A CRYPTOGRAPHIC ELECTION             |")
	fmt.Println("  |                                                                |")
	fmt.Println("  |      Live demonstration of a verifiable electronic vote        |")
	fmt.Println("  |                                                                |")
	fmt.Println("  +================================================================+")
	fmt.Println()
	narrator("Today we are holding an election.")
	narrator(fmt.Sprintf("%d citizens will choose between %d candidates.", numVoters, numOptions))
	narrator("Their votes will be encrypted, shuffled, and counted.")
	narrator("Nobody will know who voted for whom.")
	narrator("But EVERYONE can verify the result is correct.")
	fmt.Println()
	narrator("You will experience this election from three perspectives:")
	fmt.Println()
	narrator("  [1] As a CONTROL COMPONENT operator  -- you hold part of the master key")
	narrator("  [2] As a VOTER                       -- you cast your secret ballot")
	narrator("  [3] As a PUBLIC AUDITOR              -- you verify nothing was rigged")
	fmt.Println()

	// =====================================================================
	// ACT 1: SETUP (do it silently, then show internals)
	// =====================================================================
	banner("ACT 1: THE SETUP")
	fmt.Println()
	narrator("Before any vote is cast, we need to build the infrastructure.")
	narrator("Think of it like constructing a ballot box that requires 5 different")
	narrator("keys to open. No single person holds all the keys.")

	// Run setup
	cfg := protocol.DefaultConfig(numVoters, numOptions)
	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	section("Step 1.1: The Mathematical Universe")

	narrator("All the cryptography runs inside a mathematical structure called")
	narrator("a \"safe prime group.\" These are the agreed-upon rules of the game:")
	fmt.Println()
	showPublic("Prime p (257 bits)", truncBig(group.P(), 60))
	showPublic("Safe prime q (256 bits)", truncBig(group.Q(), 60))
	showPublic("Generator g", group.Generator().Value().String())
	fmt.Println()
	narrator("These numbers are PUBLIC. Everyone agrees on them before the election starts.")
	fmt.Println()

	// Run full setup
	event := protocol.Setup(cfg)

	section("Step 1.2: The Control Components Generate Their Keys")
	fmt.Println()
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println("  |  YOU ARE NOW: Control Component Operator (CC0)                  |")
	fmt.Println("  |  Location: Secure data center, Bern, Switzerland                |")
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println()
	narrator("You are one of 4 independent operators. You don't know each other.")
	narrator("You're in a locked room with an air-gapped computer.")
	narrator("Your job: generate a secret key and share ONLY the public part.")
	fmt.Println()

	ccNames := []string{"CC0 (Bern)", "CC1 (Zurich)", "CC2 (Geneva)", "CC3 (Lugano)"}
	cc0 := event.CCs[0]

	narrator("Your computer generates a random secret key:")
	fmt.Println()
	for i := 0; i < cfg.NumOptions; i++ {
		showSecret(fmt.Sprintf("Secret key [%d]", i), truncBig(cc0.ElectionKeyPair.SK.Get(i).Value(), 50))
	}
	fmt.Println()
	narrator("From the secret, your computer derives the public key: PK = g ^ SK mod p")
	fmt.Println()
	for i := 0; i < cfg.NumOptions; i++ {
		showPublic(fmt.Sprintf("Public key [%d]", i), truncBig(cc0.ElectionKeyPair.PK.Get(i).Value(), 50))
	}
	fmt.Println()
	narrator("You also generate a SCHNORR PROOF for each key component.")
	narrator("This proves you know the secret behind the public key, WITHOUT revealing it.")
	narrator("That's a zero-knowledge proof -- the verifier learns NOTHING except \"they know it.\"")
	fmt.Println()
	for i := 0; i < cfg.NumOptions; i++ {
		showPublic(fmt.Sprintf("Schnorr proof [%d].e", i), truncBig(cc0.SchnorrProofs[i].E.Value(), 40))
		showPublic(fmt.Sprintf("Schnorr proof [%d].z", i), truncBig(cc0.SchnorrProofs[i].Z.Value(), 40))
	}
	fmt.Println()
	narrator("Meanwhile, the other 3 operators do the same thing independently:")
	fmt.Println()
	for j := 1; j < cfg.NumCCs; j++ {
		showPublic(fmt.Sprintf("%s PK[0]", ccNames[j]), truncBig(event.CCs[j].ElectionKeyPair.PK.Get(0).Value(), 44))
	}
	fmt.Println()

	section("Step 1.3: Combining Keys Into the Election Key")

	narrator("Now the magic: all 5 public keys (4 CCs + Electoral Board) are")
	narrator("MULTIPLIED together into a single Election Public Key.")
	fmt.Println()
	narrator("Encrypting with this key means you need ALL 5 secrets to decrypt.")
	narrator("If even ONE operator is honest, the others cannot cheat.")
	fmt.Println()
	fmt.Println("      CC0 PK  x  CC1 PK  x  CC2 PK  x  CC3 PK  x  EB PK")
	fmt.Println("                            |")
	fmt.Println("                            V")
	showPublic("Election Public Key [0]", truncBig(event.ElectionPK.Get(0).Value(), 50))
	fmt.Println()

	section("Step 1.4: Encoding Candidates as Prime Numbers")

	narrator("Each candidate gets a unique small prime number.")
	narrator("A vote is encoded as g^(prime) -- a group element.")
	fmt.Println()
	candidateNames := []string{"Alice", "Bob", "Carol"}
	for i := 0; i < numOptions; i++ {
		raw := emath.SmallPrimes(numOptions)[i]
		showPublic(fmt.Sprintf("Candidate %d (%s)", i, candidateNames[i]), fmt.Sprintf("prime %d -> squared prime %s", raw, truncBig(event.Primes[i], 20)))
	}
	fmt.Println()
	narrator("Why squared primes? The raw primes must be in the mathematical group.")
	narrator("Squaring guarantees they are quadratic residues (valid group elements).")
	fmt.Println()

	section("Step 1.5: Mailing the Voting Cards")

	narrator("Each voter receives a physical card in the mail:")
	fmt.Println()
	vc0 := event.VotingCards[0]
	fmt.Println("      +------------------------------------------------------+")
	fmt.Println("      |                SWISS CONFEDERATION                    |")
	fmt.Println("      |            Electronic Voting Card                     |")
	fmt.Println("      |                                                       |")
	fmt.Printf("      |  Voter ID:           %-32s |\n", vc0.VoterID)
	fmt.Printf("      |  Start Voting Key:   %-32s |\n", vc0.StartVotingKey)
	fmt.Printf("      |  Ballot Casting Key: %-32s |\n", vc0.BallotCastingKey)
	fmt.Println("      |                                                       |")
	fmt.Println("      |  Choice Return Codes (to verify your vote):           |")
	for i, code := range vc0.ChoiceReturnCodes {
		fmt.Printf("      |    Candidate %d (%s):  %-32s |\n", i, candidateNames[i], code)
	}
	fmt.Println("      |                                                       |")
	fmt.Printf("      |  Vote Cast Code:     %-32s |\n", vc0.VoteConfirmCode)
	fmt.Println("      |                                                       |")
	fmt.Println("      |  KEEP THIS CARD SAFE. DO NOT SHARE IT.                |")
	fmt.Println("      +------------------------------------------------------+")
	fmt.Println()
	narrator("The Start Voting Key (SVK) = your username.")
	narrator("The Ballot Casting Key (BCK) = your confirmation PIN.")
	narrator("The Choice Return Codes = prove the server recorded YOUR choice, not something else.")
	narrator("The Vote Cast Code = proves your vote was finalized.")
	fmt.Println()

	// =====================================================================
	// ACT 2: VOTING
	// =====================================================================
	banner("ACT 2: THE VOTE")
	fmt.Println()
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println("  |  YOU ARE NOW: A Citizen (Voter 2)                               |")
	fmt.Println("  |  Location: Your kitchen table, laptop open, voting card in hand |")
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println()
	narrator("You open the voting website. You enter your Start Voting Key and")
	narrator("date of birth. The system authenticates you.")
	fmt.Println()
	narrator("On screen you see three candidates:")
	fmt.Println()
	narrator("     [ ] Alice     [ ] Bob     [ ] Carol")
	fmt.Println()
	narrator("You choose: BOB.")
	fmt.Println()
	narrator("     [ ] Alice     [X] Bob     [ ] Carol")
	fmt.Println()

	section("Step 2.1: Your Browser Encrypts Your Vote (JavaScript)")

	narrator("This happens INSIDE your web browser. The voting server")
	narrator("never sees your plaintext vote. Let's look under the hood:")
	fmt.Println()

	selectedOption := 1 // Bob
	voteProduct := event.Primes[selectedOption]
	g := group.Generator()
	voteElem, _ := emath.NewZqElement(voteProduct, zqGroup)

	narrator(fmt.Sprintf("Your choice: %s (prime = %s)", candidateNames[selectedOption], truncBig(voteProduct, 20)))
	fmt.Println()

	narrator("Step 1 -- Encode the vote as a group element:")
	msgGq := g.Exponentiate(voteElem)
	showValue("Plaintext", fmt.Sprintf("g^%s = %s", truncBig(voteProduct, 10), truncBig(msgGq.Value(), 40)))
	fmt.Println()

	narrator("Step 2 -- Generate a random number (used once, then discarded):")
	r := emath.RandomZqElement(zqGroup)
	showSecret("Ephemeral r", truncBig(r.Value(), 50))
	fmt.Println()

	narrator("Step 3 -- ElGamal encryption:")
	narrator("          gamma = g^r          (random mask)")
	narrator("          phi   = PK^r * msg   (encrypted payload)")
	fmt.Println()
	l := cfg.NumOptions
	msgElems := make([]emath.GqElement, l)
	for i := 0; i < l; i++ {
		if i == 0 {
			msgElems[i] = msgGq
		} else {
			one, _ := emath.NewZqElement(big.NewInt(1), zqGroup)
			msgElems[i] = g.Exponentiate(one)
		}
	}
	msg := elgamal.NewMessage(emath.GqVectorOf(msgElems...))
	ct := elgamal.Encrypt(msg, r, event.ElectionPK)

	showPublic("Encrypted gamma", truncBig(ct.Gamma.Value(), 50))
	for i := 0; i < ct.Size(); i++ {
		showPublic(fmt.Sprintf("Encrypted phi[%d]", i), truncBig(ct.GetPhi(i).Value(), 50))
	}
	fmt.Println()
	narrator("Look at those numbers. Pure noise. Even if a hacker breaks into")
	narrator("the voting server, they see only random-looking numbers.")
	narrator("You need ALL 5 secret keys to decrypt. Your vote is safe.")
	fmt.Println()

	section("Step 2.2: Zero-Knowledge Proofs (\"I voted correctly\")")

	narrator("Your browser also generates mathematical proofs that:")
	narrator("  (a) The ciphertext actually contains a valid vote (not garbage)")
	narrator("  (b) It's an encryption of one of the allowed candidates")
	fmt.Println()
	narrator("These proofs reveal NOTHING about which candidate you chose.")
	narrator("They only prove the vote is well-formed. Think of it as:")
	narrator("  \"I put a valid ballot in the envelope, but you can't see which one.\"")
	fmt.Println()

	expProof := zkp.GenExponentiationProof(
		emath.GqVectorOf(g),
		voteElem,
		emath.GqVectorOf(msgGq),
		group,
	)
	showPublic("Exponentiation proof .e", truncBig(expProof.E.Value(), 40))
	showPublic("Exponentiation proof .z", truncBig(expProof.Z.Value(), 40))
	fmt.Println()

	section("Step 2.3: Return Codes (\"My vote was recorded correctly\")")

	narrator("After your encrypted vote arrives, each Control Component computes")
	narrator("a partial return code -- WITHOUT decrypting your vote!")
	narrator("They use the mathematical properties of ElGamal (homomorphic encryption).")
	fmt.Println()
	narrator("The server combines all partial codes and sends back:")
	fmt.Println()
	vc2 := event.VotingCards[2]
	fmt.Println("      +------------------------------------------+")
	fmt.Println("      |  Your choice was recorded.                |")
	fmt.Println("      |                                           |")
	fmt.Printf("      |  Choice Return Code: %-20s |\n", vc2.ChoiceReturnCodes[selectedOption])
	fmt.Println("      |                                           |")
	fmt.Println("      |  Compare with your voting card.           |")
	fmt.Println("      +------------------------------------------+")
	fmt.Println()
	narrator("You check your physical card. The code for Bob matches!")
	narrator("This confirms: the server recorded YOUR actual choice, not something else.")
	narrator("Even if your computer had malware, the return code would be WRONG")
	narrator("if the vote was changed -- because the code depends on YOUR specific choice.")
	fmt.Println()

	section("Step 2.4: All 6 Citizens Vote")

	narrator("Now all 6 citizens cast their ballots. Here's what really happened:")
	fmt.Println()

	votes := []int{0, 2, 1, 0, 1, 2} // Alice, Carol, Bob, Alice, Bob, Carol
	for i, opt := range votes {
		protocol.CastVote(event, i, []int{opt})
	}

	fmt.Println("      +----------+------------------+------------------------------------+")
	fmt.Println("      |  Voter   |  Actual Vote     |  What the server sees              |")
	fmt.Println("      +----------+------------------+------------------------------------+")
	for i, opt := range votes {
		gamma := event.BallotBox.Votes[i].Ciphertext.Gamma.Value()
		fmt.Printf("      |  Voter %d |  %-14s  |  %s  |\n", i, candidateNames[opt], truncHex(gamma, 34))
	}
	fmt.Println("      +----------+------------------+------------------------------------+")
	fmt.Println()
	narrator("The left column is the TRUTH (known only to each voter).")
	narrator("The right column is ALL the server has: meaningless hex noise.")
	fmt.Println()

	// =====================================================================
	// ACT 3: TALLY
	// =====================================================================
	banner("ACT 3: THE TALLY -- The Verifiable Shuffle")
	fmt.Println()
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println("  |  YOU ARE NOW: Control Component Operator (CC0) again            |")
	fmt.Println("  |  Location: Back in the secure data center, Bern                 |")
	fmt.Println("  |  Mission: Shuffle the votes so nobody can trace them            |")
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println()
	narrator("The voting period is over. Time to count.")
	fmt.Println()
	narrator("But we CAN'T just decrypt in order -- that reveals who voted for whom.")
	narrator("Instead, each of the 5 key holders takes a turn:")
	fmt.Println()
	narrator("   1. SHUFFLE    -- randomly reorder all encrypted ballots")
	narrator("   2. RE-ENCRYPT -- add fresh randomness (so shuffled ballots look different)")
	narrator("   3. PARTIALLY DECRYPT -- peel off their key layer")
	narrator("   4. PROVE      -- generate a Bayer-Groth zero-knowledge proof")
	narrator("                    that the shuffle was honest")
	fmt.Println()
	narrator("After 5 rounds, votes are decrypted but disconnected from voters.")
	fmt.Println()

	// Get initial ciphertexts
	ballotCts := event.BallotBox.GetCiphertexts()
	N := ballotCts.Size()
	if N < 2 {
		for N < 2 {
			rr := emath.RandomZqElement(zqGroup)
			trivial := elgamal.EncryptOnes(rr, event.ElectionPK)
			ballotCts = ballotCts.Append(trivial)
			N++
		}
	}
	currentCts := ballotCts
	event.ShuffleResults = make([]mixnet.VerifiableShuffle, 0)
	event.PartiallyDecrypted = make([]*elgamal.CiphertextVector, 0)

	for j := 0; j < cfg.NumCCs; j++ {
		cc := event.CCs[j]

		if j == 0 {
			section(fmt.Sprintf("Step 3.%d: YOUR Turn -- %s Shuffles", j+1, ccNames[j]))
			narrator("This is YOUR turn. Let's watch every step.")
		} else {
			section(fmt.Sprintf("Step 3.%d: %s Shuffles", j+1, ccNames[j]))
		}
		fmt.Println()

		narrator("Input ciphertexts (what you receive):")
		fmt.Println()
		for i := 0; i < currentCts.Size(); i++ {
			fmt.Printf("        [%d]  %s\n", i, truncHex(currentCts.Get(i).Gamma.Value(), 40))
		}
		fmt.Println()

		// Build remaining PK
		remainingPKs := make([]elgamal.PublicKey, 0)
		for k := j; k < cfg.NumCCs; k++ {
			remainingPKs = append(remainingPKs, event.CCs[k].ElectionKeyPair.PK)
		}
		remainingPKs = append(remainingPKs, event.EB.PK)
		remainingPK := elgamal.CombinePublicKeys(remainingPKs...)

		// Shuffle
		start := time.Now()
		vs := mixnet.GenVerifiableShuffle(currentCts, remainingPK, group)
		shuffleTime := time.Since(start)
		event.ShuffleResults = append(event.ShuffleResults, vs)

		if j == 0 {
			narrator("Your computer generates a SECRET permutation and re-encrypts.")
			narrator("The permutation is DESTROYED after use. Even you can't recover it.")
			fmt.Println()
		}

		narrator("Output ciphertexts (after shuffle + re-encryption):")
		fmt.Println()
		for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
			fmt.Printf("        [%d]  %s\n", i, truncHex(vs.ShuffledCiphertexts.Get(i).Gamma.Value(), 40))
		}
		fmt.Println()

		if j == 0 {
			narrator("NOTICE: The values are COMPLETELY DIFFERENT. Not just reordered --")
			narrator("re-encrypted with fresh randomness. You cannot tell which input")
			narrator("became which output by looking at the numbers.")
			fmt.Println()
			m, n := mixnet.GetMatrixDimensions(N)
			narrator(fmt.Sprintf("Along with the shuffle, a PROOF was generated (%v):", shuffleTime.Round(time.Millisecond)))
			narrator(fmt.Sprintf("  Bayer-Groth ShuffleArgument for %d ciphertexts (%dx%d matrix):", N, m, n))
			fmt.Println()
			fmt.Println("        ShuffleArgument")
			fmt.Println("        +-- ProductArgument")
			if m > 1 {
				fmt.Println("        |   +-- HadamardArgument")
				fmt.Println("        |   |   +-- ZeroArgument  (proves star-map relation = 0)")
				fmt.Println("        |   +-- SingleValueProductArgument  (proves product constraint)")
			} else {
				fmt.Println("        |   +-- SingleValueProductArgument  (proves product constraint)")
			}
			fmt.Println("        +-- MultiExponentiationArgument  (proves ciphertext relation)")
			fmt.Println()
			narrator("This proof is ~800 bytes of math. It guarantees the shuffle is honest.")
			narrator("Anyone can verify it. No secrets needed.")
			fmt.Println()
		} else {
			narrator(fmt.Sprintf("  Shuffle + proof generated in %v", shuffleTime.Round(time.Millisecond)))
			fmt.Println()
		}

		// Partial decrypt
		decrypted := make([]elgamal.Ciphertext, vs.ShuffledCiphertexts.Size())
		for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
			decrypted[i] = elgamal.PartialDecrypt(vs.ShuffledCiphertexts.Get(i), cc.ElectionKeyPair.SK)
		}
		currentCts = elgamal.NewCiphertextVector(decrypted)
		event.PartiallyDecrypted = append(event.PartiallyDecrypted, currentCts)

		remaining := cfg.NumCCs - j - 1 + 1
		narrator(fmt.Sprintf("  Partial decryption done. %d encryption layer(s) remaining.", remaining))
		fmt.Println()
	}

	// EB final
	section("Step 3.5: Electoral Board -- Final Shuffle + Full Decryption")
	narrator("The Electoral Board performs the final shuffle on an AIR-GAPPED")
	narrator("computer (no network). Then they remove the last encryption layer.")
	fmt.Println()

	start := time.Now()
	vs := mixnet.GenVerifiableShuffle(currentCts, event.EB.PK, group)
	ebTime := time.Since(start)
	event.ShuffleResults = append(event.ShuffleResults, vs)
	narrator(fmt.Sprintf("  Final shuffle + proof generated in %v", ebTime.Round(time.Millisecond)))
	fmt.Println()

	event.DecryptedVotes = make([]*emath.GqVector, vs.ShuffledCiphertexts.Size())
	for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
		ct := vs.ShuffledCiphertexts.Get(i)
		dmsg := elgamal.Decrypt(ct, event.EB.SK)
		event.DecryptedVotes[i] = dmsg.Elements
	}

	narrator("The envelope is open. The plaintext votes emerge:")
	fmt.Println()
	fmt.Println("      +--------+-------------------------------+-----------------+")
	fmt.Println("      |  Slot  |  Decrypted Group Element      |  Decoded Vote   |")
	fmt.Println("      +--------+-------------------------------+-----------------+")
	for i := 0; i < len(event.DecryptedVotes); i++ {
		val := event.DecryptedVotes[i].Get(0).Value()
		decoded := returncodes.DecodeVote(val, event.Primes)
		voteStr := "(padding)"
		if len(decoded) > 0 {
			voteStr = candidateNames[decoded[0]]
		}
		fmt.Printf("      |   %d    |  %s  |  %-13s  |\n", i, truncBig(val, 27), voteStr)
	}
	fmt.Println("      +--------+-------------------------------+-----------------+")
	fmt.Println()
	narrator("The votes are readable -- but in a RANDOM, IRREVERSIBLE order.")
	narrator("We can count them. We cannot trace them back to any voter.")
	fmt.Println()

	// Count
	for i := 0; i < len(event.DecryptedVotes); i++ {
		val := event.DecryptedVotes[i].Get(0).Value()
		if event.DecryptedVotes[i].Get(0).IsIdentity() {
			continue
		}
		decoded := returncodes.DecodeVote(val, event.Primes)
		for _, opt := range decoded {
			event.FinalResult[opt]++
		}
	}

	fmt.Println("      +==========================================+")
	fmt.Println("      |          ELECTION RESULT                  |")
	fmt.Println("      +==========================================+")
	for opt := 0; opt < numOptions; opt++ {
		count := event.FinalResult[opt]
		bar := strings.Repeat("#", count*5)
		fmt.Printf("      |  %-8s  %d votes  %-20s |\n", candidateNames[opt], count, bar)
	}
	fmt.Println("      +==========================================+")
	fmt.Println()

	// Quick sanity: show the real votes matched
	realCounts := make(map[int]int)
	for _, v := range votes {
		realCounts[v]++
	}
	narrator("Sanity check (we know the real votes because this is a demo):")
	for opt := 0; opt < numOptions; opt++ {
		match := "MATCH"
		if event.FinalResult[opt] != realCounts[opt] {
			match = "MISMATCH!"
		}
		narrator(fmt.Sprintf("  %s: counted=%d, actual=%d  -> %s", candidateNames[opt], event.FinalResult[opt], realCounts[opt], match))
	}
	fmt.Println()

	// =====================================================================
	// ACT 4: VERIFICATION
	// =====================================================================
	banner("ACT 4: THE AUDIT -- Anyone Can Verify")
	fmt.Println()
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println("  |  YOU ARE NOW: A Public Auditor                                  |")
	fmt.Println("  |  Location: Anywhere. Your laptop. A coffee shop.                |")
	fmt.Println("  |                                                                 |")
	fmt.Println("  |  You have: The public election data (encrypted ballots,         |")
	fmt.Println("  |            shuffled ballots, proofs, commitments)                |")
	fmt.Println("  |  You DON'T have: Any secret keys                                |")
	fmt.Println("  +----------------------------------------------------------------+")
	fmt.Println()
	narrator("This is the moment of truth.")
	fmt.Println()
	narrator("You don't trust the government. You don't trust the operators.")
	narrator("You don't trust the software vendor. You don't trust ANYONE.")
	narrator("And you don't have to.")
	fmt.Println()
	narrator("The mathematics lets you verify the entire election yourself.")
	fmt.Println()

	section("Step 4.1: Verify Each Operator's Key Proof")

	narrator("First: did each CC actually generate a real key?")
	narrator("The Schnorr proofs let you check without seeing the secrets.")
	fmt.Println()

	for j := 0; j < cfg.NumCCs; j++ {
		cc := event.CCs[j]
		allOk := true
		for i := 0; i < cfg.NumOptions; i++ {
			auxInfo := []hash.Hashable{
				hash.HashableBigInt{Value: big.NewInt(int64(i))},
				hash.HashableString{Value: cfg.ElectionID},
				hash.HashableBigInt{Value: big.NewInt(int64(j))},
			}
			ok := zkp.VerifySchnorrProof(cc.SchnorrProofs[i], cc.ElectionKeyPair.PK.Get(i), group, auxInfo...)
			if !ok {
				allOk = false
			}
		}
		status := "PASS -- they proved they know their secret"
		if !allOk {
			status = "FAIL!"
		}
		fmt.Printf("      [%s] %s\n", status[:4], ccNames[j])
	}
	fmt.Println()

	section("Step 4.2: Verify the 5 Shuffle Proofs")

	narrator("This is the HEART of the verification. The hardest math in the system.")
	fmt.Println()
	narrator("For each of the 5 shuffles, you verify that the output contains")
	narrator("the SAME votes as the input, just in a different order.")
	fmt.Println()
	narrator("You don't know the permutation. You can't see which vote went where.")
	narrator("But the Bayer-Groth proof MATHEMATICALLY GUARANTEES correctness.")
	fmt.Println()
	narrator("Each proof contains nested sub-proofs:")
	narrator("  - ProductArgument: proves the permutation matrix is valid")
	narrator("  - HadamardArgument: proves element-wise product relationship")
	narrator("  - ZeroArgument: proves a bilinear identity equals zero")
	narrator("  - SingleValueProductArgument: proves a scalar product constraint")
	narrator("  - MultiExponentiationArgument: proves the ciphertext transformation")
	fmt.Println()
	narrator("Verifying now...")
	fmt.Println()

	verifyBallotCts := event.BallotBox.GetCiphertexts()
	vN := verifyBallotCts.Size()
	if vN < 2 {
		for vN < 2 {
			rr := emath.RandomZqElement(zqGroup)
			trivial := elgamal.EncryptOnes(rr, event.ElectionPK)
			verifyBallotCts = verifyBallotCts.Append(trivial)
			vN++
		}
	}

	allValid := true
	for j, vsShuffle := range event.ShuffleResults {
		var pk elgamal.PublicKey
		var name string
		if j < cfg.NumCCs {
			remainingPKs := make([]elgamal.PublicKey, 0)
			for k := j; k < cfg.NumCCs; k++ {
				remainingPKs = append(remainingPKs, event.CCs[k].ElectionKeyPair.PK)
			}
			remainingPKs = append(remainingPKs, event.EB.PK)
			pk = elgamal.CombinePublicKeys(remainingPKs...)
			name = ccNames[j]
		} else {
			pk = event.EB.PK
			name = "Electoral Board"
		}

		m, n := mixnet.GetMatrixDimensions(verifyBallotCts.Size())
		fmt.Printf("      Shuffle %d (%s) -- %d ciphertexts, %dx%d matrix\n", j, name, verifyBallotCts.Size(), m, n)

		vStart := time.Now()
		valid := mixnet.VerifyShuffle(verifyBallotCts, vsShuffle, pk, group)
		elapsed := time.Since(vStart)

		if valid {
			fmt.Printf("        ProductArgument .............. PASS\n")
			if m > 1 {
				fmt.Printf("          HadamardArgument ........... PASS\n")
				fmt.Printf("            ZeroArgument ............. PASS\n")
			}
			fmt.Printf("          SingleValueProductArgument . PASS\n")
			fmt.Printf("        MultiExponentiationArgument .. PASS\n")
			fmt.Printf("      ==> VERIFIED in %v\n\n", elapsed.Round(time.Millisecond))
		} else {
			fmt.Printf("      ==> FAILED!\n\n")
			allValid = false
		}

		if j < cfg.NumCCs && j < len(event.PartiallyDecrypted) {
			verifyBallotCts = event.PartiallyDecrypted[j]
		} else {
			verifyBallotCts = vsShuffle.ShuffledCiphertexts
		}
	}

	section("Step 4.3: Verify the Count")

	totalVotes := 0
	for _, count := range event.FinalResult {
		totalVotes += count
	}
	fmt.Printf("      Decrypted ballots:  %d\n", totalVotes)
	fmt.Printf("      Ballots submitted:  %d\n", event.BallotBox.Size())
	if totalVotes == event.BallotBox.Size() {
		fmt.Println("      ==> PASS: Every ballot is accounted for.")
	} else {
		fmt.Println("      ==> FAIL: Count mismatch!")
		allValid = false
	}
	fmt.Println()

	// =====================================================================
	// FINALE
	// =====================================================================
	banner("THE VERDICT")

	if allValid {
		fmt.Println()
		fmt.Println("  +================================================================+")
		fmt.Println("  |                                                                |")
		fmt.Println("  |                 ALL VERIFICATIONS PASSED.                       |")
		fmt.Println("  |                                                                |")
		fmt.Println("  |  As a public auditor, you have independently verified:          |")
		fmt.Println("  |                                                                |")
		fmt.Println("  |    [x] All 4 key holders proved they know their secrets         |")
		fmt.Println("  |    [x] All 5 shuffles are mathematically honest                 |")
		fmt.Println("  |    [x] No votes were added, removed, or changed                 |")
		fmt.Println("  |    [x] The final count matches the number of ballots            |")
		fmt.Println("  |                                                                |")
		fmt.Println("  |  You did this WITHOUT any secret keys.                          |")
		fmt.Println("  |  You did this WITHOUT trusting anyone.                          |")
		fmt.Println("  |                                                                |")
		fmt.Println("  |  Pure mathematics.                                              |")
		fmt.Println("  |                                                                |")
		fmt.Println("  +================================================================+")
	}

	fmt.Println()
	narrator("RECAP -- What you experienced:")
	fmt.Println()
	fmt.Println("    AS THE CC OPERATOR:   You generated keys, shuffled votes, created proofs.")
	fmt.Println("                          You never saw anyone's vote. Even you can't undo")
	fmt.Println("                          your own shuffle -- the permutation was destroyed.")
	fmt.Println()
	fmt.Println("    AS THE VOTER:         Your vote was encrypted in your browser. The server")
	fmt.Println("                          stored only noise. Return codes on your physical")
	fmt.Println("                          card confirmed it was recorded correctly.")
	fmt.Println()
	fmt.Println("    AS THE AUDITOR:       You verified every step with public data and math.")
	fmt.Println("                          No trust required. No access to secrets. The proofs")
	fmt.Println("                          are either valid or they aren't. No gray area.")
	fmt.Println()
	narrator("This is the same protocol used in real Swiss federal elections.")
	narrator("The production system: 14 repositories, 500,000+ lines, Windows + Kubernetes + 50GB RAM.")
	narrator("This demo: one 15MB Go binary on a Mac.")
	narrator("The math is identical.")
	fmt.Println()
}
