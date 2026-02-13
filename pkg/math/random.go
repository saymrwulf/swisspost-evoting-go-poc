package math

import (
	"crypto/rand"
	"math/big"
)

// RandomZqElement generates a random element in Z_q.
func RandomZqElement(group *ZqGroup) ZqElement {
	for {
		r, err := rand.Int(rand.Reader, group.q)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		return ZqElement{value: r, group: group}
	}
}

// RandomZqVector generates a vector of n random elements in Z_q.
func RandomZqVector(n int, group *ZqGroup) *ZqVector {
	elements := make([]ZqElement, n)
	for i := range elements {
		elements[i] = RandomZqElement(group)
	}
	return &ZqVector{elements: elements, group: group}
}

// RandomGqElement generates a random element in G_q by squaring a random value.
func RandomGqElement(group *GqGroup) GqElement {
	for {
		// Generate random value in [1, q)
		r, err := rand.Int(rand.Reader, new(big.Int).Sub(group.q, big.NewInt(1)))
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		r.Add(r, big.NewInt(1)) // Shift to [1, q)
		// Square to get quadratic residue
		squared := new(big.Int).Exp(r, big.NewInt(2), group.p)
		return GqElement{value: squared, group: group}
	}
}

// RandomBigInt generates a random big.Int in [0, max).
func RandomBigInt(max *big.Int) *big.Int {
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return r
}

// RandomNonZeroZqElement generates a random non-zero element in Z_q.
func RandomNonZeroZqElement(group *ZqGroup) ZqElement {
	for {
		e := RandomZqElement(group)
		if !e.IsZero() {
			return e
		}
	}
}
