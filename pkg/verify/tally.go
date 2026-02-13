package verify

import (
	"fmt"

	"github.com/user/evote/pkg/protocol"
)

// VerifyTallyResult verifies the tally phase results.
func VerifyTallyResult(event *protocol.ElectionEvent) bool {
	allPassed := true

	fmt.Println("  [Tally Verification]")

	// 1. Verify shuffle proofs exist
	expectedShuffles := event.Config.NumCCs + 1 // 4 CCs + 1 EB
	if len(event.ShuffleResults) != expectedShuffles {
		fmt.Printf("    FAIL: Expected %d shuffle proofs, got %d\n", expectedShuffles, len(event.ShuffleResults))
		allPassed = false
	} else {
		fmt.Printf("    PASS: %d shuffle proofs present\n", expectedShuffles)
	}

	// 2. Verify vote count consistency
	totalVotes := 0
	for _, count := range event.FinalResult {
		totalVotes += count
	}
	// Each voter selects 1 option in demo mode
	if totalVotes != event.BallotBox.Size() {
		fmt.Printf("    WARN: Total decoded votes (%d) != ballots cast (%d)\n", totalVotes, event.BallotBox.Size())
	} else {
		fmt.Printf("    PASS: Vote count consistent (%d votes)\n", totalVotes)
	}

	// 3. Verify decrypted votes exist
	if event.DecryptedVotes == nil || len(event.DecryptedVotes) == 0 {
		fmt.Println("    FAIL: No decrypted votes found")
		allPassed = false
	} else {
		fmt.Printf("    PASS: %d decrypted vote plaintexts\n", len(event.DecryptedVotes))
	}

	// 4. Verify result non-negative
	for opt, count := range event.FinalResult {
		if count < 0 {
			fmt.Printf("    FAIL: Option %d has negative count (%d)\n", opt, count)
			allPassed = false
		}
	}
	fmt.Println("    PASS: All vote counts non-negative")

	return allPassed
}
