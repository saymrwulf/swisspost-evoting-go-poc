package math

import (
	"math/big"
)

// SmallPrimes returns the first n small primes starting from 2.
func SmallPrimes(n int) []*big.Int {
	primes := make([]*big.Int, 0, n)
	candidate := big.NewInt(2)
	for len(primes) < n {
		if candidate.ProbablyPrime(20) {
			primes = append(primes, new(big.Int).Set(candidate))
		}
		candidate = new(big.Int).Add(candidate, big.NewInt(1))
	}
	return primes
}

// Factorize attempts to factorize value as a product of elements from allowedPrimes.
// Returns the prime factors. Panics if factorization fails.
func Factorize(value *big.Int, allowedPrimes []*big.Int) []*big.Int {
	remaining := new(big.Int).Set(value)
	factors := make([]*big.Int, 0)
	for _, p := range allowedPrimes {
		for {
			quo, rem := new(big.Int).DivMod(remaining, p, new(big.Int))
			if rem.Sign() == 0 {
				factors = append(factors, new(big.Int).Set(p))
				remaining = quo
			} else {
				break
			}
		}
	}
	if remaining.Cmp(big.NewInt(1)) != 0 {
		panic("factorization failed: remaining = " + remaining.String())
	}
	return factors
}
