package protocol

import (
	"math/big"
	"testing"

	emath "github.com/user/evote/pkg/math"
)

const (
	testP = "179688417486862032111147025351064878713905624387098436271724698527496946737299"
	testQ = "89844208743431016055573512675532439356952812193549218135862349263748473368649"
	testG = "4"
)

func testConfig(t *testing.T, numVoters, numOptions int) *Config {
	t.Helper()
	p, _ := new(big.Int).SetString(testP, 10)
	q, _ := new(big.Int).SetString(testQ, 10)
	g, _ := new(big.Int).SetString(testG, 10)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatalf("test group: %v", err)
	}
	return &Config{
		Group:       group,
		NumCCs:      4,
		NumOptions:  numOptions,
		NumVoters:   numVoters,
		ElectionID:  "unit-test",
		SecurityLvl: 128,
	}
}

// TestEndToEndTallyAndVerify runs the full ceremony deterministically (fixed
// group, fixed votes) and asserts both the decoded result and that the honest
// verifier returns true — this is the regression guard for the F2/F7 fixes
// (VerifyTally must now return the real outcome, and small-N padding must match).
func TestEndToEndTallyAndVerify(t *testing.T) {
	for _, tc := range []struct {
		voters  int
		options int
		votes   []int // one selection per voter
		want    map[int]int
	}{
		{voters: 3, options: 3, votes: []int{0, 1, 1}, want: map[int]int{0: 1, 1: 2}},
		{voters: 1, options: 2, votes: []int{0}, want: map[int]int{0: 1}}, // exercises N<2 padding
		{voters: 4, options: 2, votes: []int{0, 0, 1, 1}, want: map[int]int{0: 2, 1: 2}},
	} {
		cfg := testConfig(t, tc.voters, tc.options)
		event := Setup(cfg)
		for v := 0; v < tc.voters; v++ {
			CastVote(event, v, []int{tc.votes[v]})
		}
		Tally(event)

		for opt, want := range tc.want {
			if event.FinalResult[opt] != want {
				t.Errorf("voters=%d: option %d got %d, want %d", tc.voters, opt, event.FinalResult[opt], want)
			}
		}
		if !VerifyTally(event) {
			t.Errorf("voters=%d: honest ceremony failed verification", tc.voters)
		}
	}
}
