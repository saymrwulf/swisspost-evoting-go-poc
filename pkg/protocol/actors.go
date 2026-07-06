package protocol

import (
	"fmt"
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

func bigIntN(n int) *big.Int { return big.NewInt(int64(n)) }

// RunDemoElection runs a complete election ceremony with the given parameters.
func RunDemoElection(numVoters, numOptions int) {
	fmt.Println("========================================")
	fmt.Println(" Swiss Post E-Voting Protocol PoC (Go)")
	fmt.Println("========================================")
	fmt.Printf(" Voters: %d, Options: %d, CCs: 4\n", numVoters, numOptions)
	fmt.Println()

	// Phase 1: Setup
	fmt.Println("--- SETUP PHASE ---")
	cfg := DefaultConfig(numVoters, numOptions)
	fmt.Printf("  Group: %d-bit safe prime\n", cfg.Group.Q().BitLen())
	event := Setup(cfg)
	fmt.Printf("  Generated %d voting cards\n", numVoters)
	fmt.Printf("  Mapping table: %d entries\n", event.MappingTable.Size())
	fmt.Println("  Setup complete.")

	// Phase 2: Voting
	fmt.Println("\n--- VOTING PHASE ---")
	for v := 0; v < numVoters; v++ {
		// Randomly select 1 option for each voter (CSPRNG; simulation only).
		selected := []int{int(emath.RandomBigInt(bigIntN(numOptions)).Int64())}
		CastVote(event, v, selected)
	}
	fmt.Printf("  All %d votes cast.\n", numVoters)

	// Phase 3: Tally
	Tally(event)

	// Phase 4: Verify
	VerifyTally(event)
}
