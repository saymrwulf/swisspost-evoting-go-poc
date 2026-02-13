package returncodes

import (
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// EncodeVote encodes a set of selected option indices as a product of small primes.
// Each option index maps to a small prime; the vote is the product of selected primes.
func EncodeVote(selectedIndices []int, primes []*big.Int) *big.Int {
	result := big.NewInt(1)
	for _, idx := range selectedIndices {
		result.Mul(result, primes[idx])
	}
	return result
}

// EncodeVoteAsGqElement encodes a vote and returns it as a GqElement.
func EncodeVoteAsGqElement(selectedIndices []int, primes []*big.Int, group *emath.GqGroup) emath.GqElement {
	product := EncodeVote(selectedIndices, primes)
	elem, err := emath.NewGqElement(product, group)
	if err != nil {
		panic("encoded vote is not a group member: " + err.Error())
	}
	return elem
}
