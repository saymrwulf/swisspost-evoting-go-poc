package returncodes

import (
	"math/big"
)

// DecodeVote factorizes a vote product back into the indices of selected options.
func DecodeVote(product *big.Int, primes []*big.Int) []int {
	remaining := new(big.Int).Set(product)
	var selected []int

	for idx, p := range primes {
		for {
			quo, rem := new(big.Int).DivMod(remaining, p, new(big.Int))
			if rem.Sign() == 0 {
				selected = append(selected, idx)
				remaining = quo
			} else {
				break
			}
		}
	}

	if remaining.Cmp(big.NewInt(1)) != 0 {
		panic("factorization failed: remaining = " + remaining.String())
	}
	return selected
}
