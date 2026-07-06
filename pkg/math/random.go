package math

import (
	"crypto/rand"
	"math/big"
)

// RandomZqElement generates a uniform random element in Z_q = [0, q).
func RandomZqElement(group *ZqGroup) ZqElement {
	r, err := rand.Int(rand.Reader, group.q)
	if err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return ZqElement{value: r, group: group}
}

// RandomZqVector generates a vector of n random elements in Z_q.
func RandomZqVector(n int, group *ZqGroup) *ZqVector {
	elements := make([]ZqElement, n)
	for i := range elements {
		elements[i] = RandomZqElement(group)
	}
	return &ZqVector{elements: elements, group: group}
}

// RandomGqElement generates a uniform random element in G_q by squaring a
// random square root drawn from the canonical half [1, q].
func RandomGqElement(group *GqGroup) GqElement {
	// rand.Int yields [0, q); shift to the canonical root range [1, q].
	r, err := rand.Int(rand.Reader, group.q)
	if err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	r.Add(r, big.NewInt(1))
	squared := new(big.Int).Exp(r, big.NewInt(2), group.p)
	return GqElement{value: squared, group: group}
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
