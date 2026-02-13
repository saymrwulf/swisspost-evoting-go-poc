package protocol

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	"github.com/user/evote/pkg/kdf"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/zkp"
	emath "github.com/user/evote/pkg/math"
)

// Setup performs the complete setup phase of the election.
func Setup(cfg *Config) *ElectionEvent {
	event := &ElectionEvent{
		Config:       cfg,
		BallotBox:    NewBallotBox(),
		MappingTable: returncodes.NewMappingTable(),
		FinalResult:  make(map[int]int),
	}

	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// 1. Generate small primes for vote encoding
	// Square the raw primes to ensure they are quadratic residues (group members)
	rawPrimes := emath.SmallPrimes(cfg.NumOptions)
	event.Primes = make([]*big.Int, cfg.NumOptions)
	for i, rp := range rawPrimes {
		squared := new(big.Int).Exp(rp, big.NewInt(2), group.P())
		if !group.IsGroupMember(squared) {
			panic(fmt.Sprintf("squared prime %v is not a group member", squared))
		}
		event.Primes[i] = squared
	}

	// 2. GenKeysCCR: Each CC generates election keys and return code secrets
	event.CCs = make([]*ControlComponent, cfg.NumCCs)
	for j := 0; j < cfg.NumCCs; j++ {
		kp := elgamal.GenKeyPair(group, cfg.NumOptions)

		// Generate Schnorr proofs for each key element
		proofs := make([]zkp.SchnorrProof, cfg.NumOptions)
		for i := 0; i < cfg.NumOptions; i++ {
			auxInfo := []hash.Hashable{
				hash.HashableBigInt{Value: big.NewInt(int64(i))},
				hash.HashableString{Value: cfg.ElectionID},
				hash.HashableBigInt{Value: big.NewInt(int64(j))},
			}
			proofs[i] = zkp.GenSchnorrProof(kp.SK.Get(i), kp.PK.Get(i), group, auxInfo...)
		}

		// Return codes generation secret
		rcSecret := emath.RandomZqElement(zqGroup)

		event.CCs[j] = &ControlComponent{
			ID:               j,
			ElectionKeyPair:  kp,
			ReturnCodeSecret: rcSecret,
			SchnorrProofs:    proofs,
		}
	}

	// 3. Combine election public keys
	ccPKs := make([]elgamal.PublicKey, cfg.NumCCs)
	for j := 0; j < cfg.NumCCs; j++ {
		ccPKs[j] = event.CCs[j].ElectionKeyPair.PK
	}
	event.ReturnCodesPK = elgamal.CombinePublicKeys(ccPKs...)

	// 4. Generate Electoral Board key from passwords
	event.EB = generateElectoralBoard(cfg, group, zqGroup)

	// 5. Combine all keys into election PK: ccPKs × ebPK
	allPKs := append(ccPKs, event.EB.PK)
	event.ElectionPK = elgamal.CombinePublicKeys(allPKs...)

	// 6. Generate voting cards with return codes
	event.VotingCards = make([]*VotingCard, cfg.NumVoters)
	for v := 0; v < cfg.NumVoters; v++ {
		event.VotingCards[v] = generateVotingCard(v, event)
	}

	return event
}

func generateElectoralBoard(cfg *Config, group *emath.GqGroup, zqGroup *emath.ZqGroup) *ElectoralBoard {
	passwords := []string{"password1", "password2"} // PoC: fixed passwords

	// Derive EB secret key from passwords
	skElems := make([]emath.ZqElement, cfg.NumOptions)
	g := group.Generator()
	pkElems := make([]emath.GqElement, cfg.NumOptions)

	for i := 0; i < cfg.NumOptions; i++ {
		// EB_sk_i = RecursiveHashToZq(q, "ElectoralBoardSecretKey", eeID, i, pw1, pw2)
		hashArgs := []hash.Hashable{
			hash.HashableString{Value: "ElectoralBoardSecretKey"},
			hash.HashableString{Value: cfg.ElectionID},
			hash.HashableBigInt{Value: big.NewInt(int64(i))},
		}
		for _, pw := range passwords {
			hashArgs = append(hashArgs, hash.HashableString{Value: pw})
		}
		skVal := hash.RecursiveHashToZq(group.Q(), hashArgs...)
		skElems[i], _ = emath.NewZqElement(skVal, zqGroup)
		pkElems[i] = g.Exponentiate(skElems[i])
	}

	return &ElectoralBoard{
		Passwords: passwords,
		SK:        elgamal.PrivateKey{Elements: emath.ZqVectorOf(skElems...)},
		PK:        elgamal.PublicKey{Elements: emath.GqVectorOf(pkElems...)},
	}
}

func generateVotingCard(voterIdx int, event *ElectionEvent) *VotingCard {
	cfg := event.Config
	group := cfg.Group
	zqGroup := emath.ZqGroupFromGqGroup(group)

	vcID := fmt.Sprintf("vc-%04d", voterIdx)

	// Generate choice return codes for each option
	choiceCodes := make([]string, cfg.NumOptions)
	for i := 0; i < cfg.NumOptions; i++ {
		// Compute the long CC share from each CC and combine
		combined := group.Identity()
		for _, cc := range event.CCs {
			// Derive voter-specific key
			kInfo := kdf.BuildKDFInfo("VoterChoiceReturnCodeGeneration", cfg.ElectionID, vcID)
			kVal := kdf.KDFToZq(hash.IntegerToByteArray(cc.ReturnCodeSecret.Value()), kInfo, group.Q())
			k, _ := emath.NewZqElement(kVal, zqGroup)

			// HashAndSquare the prime (simulating the pCC path)
			hpCC := hash.HashAndSquare(event.Primes[i], group)

			// Compute share: hpCC^k
			share := hpCC.Exponentiate(k)
			combined = combined.Multiply(share)
		}

		// Hash combined to get lCC value, then derive short code
		tau := event.Primes[i]
		lCCVal := returncodes.ComputeLCCValue(combined, vcID, cfg.ElectionID, tau)

		// Generate short code
		shortCode := fmt.Sprintf("CC%02d", i)
		choiceCodes[i] = shortCode

		// Add to mapping table
		event.MappingTable.Add(lCCVal, shortCode)
	}

	// Generate vote confirmation code similarly
	combined := group.Identity()
	for _, cc := range event.CCs {
		kInfo := kdf.BuildKDFInfo("VoterVoteCastReturnCodeGeneration", cfg.ElectionID, vcID)
		kVal := kdf.KDFToZq(hash.IntegerToByteArray(cc.ReturnCodeSecret.Value()), kInfo, group.Q())
		k, _ := emath.NewZqElement(kVal, zqGroup)

		// Use a confirmation key (hash of voter identity)
		// Create CK as a group element by hashing and squaring
		ckSeed := hash.RecursiveHashToZq(group.Q(),
			hash.HashableString{Value: "ConfirmationKey"},
			hash.HashableString{Value: vcID},
		)
		// Add 1 to avoid zero, then square to get a guaranteed group member
		ckPlusOne := new(big.Int).Add(ckSeed, big.NewInt(1))
		ckElem, err := emath.GqElementFromSquareRoot(ckPlusOne, group)
		if err != nil {
			panic("failed to create CK element: " + err.Error())
		}

		hCK := hash.HashAndSquare(ckElem.Value(), group)
		share := hCK.Exponentiate(k)
		combined = combined.Multiply(share)
	}

	lVCCVal := returncodes.ComputeLVCCValue(combined, vcID, cfg.ElectionID)
	vccShortCode := fmt.Sprintf("VCC%02d", voterIdx)
	event.MappingTable.Add(lVCCVal, vccShortCode)

	return &VotingCard{
		VoterID:            fmt.Sprintf("voter-%04d", voterIdx),
		VerificationCardID: vcID,
		StartVotingKey:     fmt.Sprintf("SVK-%04d", voterIdx),
		ChoiceReturnCodes:  choiceCodes,
		VoteConfirmCode:    vccShortCode,
		BallotCastingKey:   fmt.Sprintf("BCK-%04d", voterIdx),
	}
}
