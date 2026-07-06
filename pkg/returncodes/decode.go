package returncodes

import (
	"fmt"
	"math/big"
)

// DecodeVote factorizes a vote product back into the indices of selected
// options. It panics if the product is not a smooth product of the encoding
// primes; use DecodeVoteChecked when the input may be untrusted.
func DecodeVote(product *big.Int, primes []*big.Int) []int {
	selected, err := DecodeVoteChecked(product, primes)
	if err != nil {
		panic(err.Error())
	}
	return selected
}

// DecodeVoteChecked is like DecodeVote but returns an error instead of panicking
// when the product does not fully factor over the encoding primes (which can
// happen for a corrupted or malicious ciphertext once inputs are remote).
func DecodeVoteChecked(product *big.Int, primes []*big.Int) ([]int, error) {
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
		return nil, fmt.Errorf("vote does not factor over encoding primes (remaining %s)", remaining.String())
	}
	return selected, nil
}
