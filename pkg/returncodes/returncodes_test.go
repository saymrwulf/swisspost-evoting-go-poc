package returncodes

import (
	"math/big"
	"reflect"
	"sort"
	"testing"

	emath "github.com/user/evote/pkg/math"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	primes := emath.SmallPrimes(5)

	cases := [][]int{
		{},
		{0},
		{4},
		{0, 2, 4},
		{1, 3},
	}
	for _, sel := range cases {
		product := EncodeVote(sel, primes)
		got := DecodeVote(product, primes)
		sort.Ints(got)
		want := append([]int(nil), sel...)
		sort.Ints(want)
		if len(want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round-trip mismatch: selected %v, decoded %v", want, got)
		}
	}
}

// TestDecodeVoteRepeatedPrime confirms a squared prime decodes to the option
// selected twice (the encoding is multiplicative, so multiplicity matters).
func TestDecodeVoteRepeatedPrime(t *testing.T) {
	primes := emath.SmallPrimes(3)
	product := new(big.Int).Mul(primes[1], primes[1])
	got := DecodeVote(product, primes)
	if len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Fatalf("expected [1 1], got %v", got)
	}
}
