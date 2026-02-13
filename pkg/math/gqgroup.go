package math

import (
	"fmt"
	"math/big"
)

// GqGroup represents the quadratic residue group of integers modulo p,
// where p is a safe prime (p = 2q + 1) and q is the group order.
type GqGroup struct {
	p         *big.Int
	q         *big.Int
	generator GqElement
	identity  GqElement
}

// NewGqGroup creates a new GqGroup with the given parameters.
// Validates that p and q are prime, p = 2q + 1, and g is a group member.
func NewGqGroup(p, q, g *big.Int) (*GqGroup, error) {
	if p == nil || q == nil || g == nil {
		return nil, fmt.Errorf("parameters must not be nil")
	}

	// Validate p is prime
	if !p.ProbablyPrime(64) {
		return nil, fmt.Errorf("p is not prime")
	}

	// Validate q is prime
	if !q.ProbablyPrime(64) {
		return nil, fmt.Errorf("q is not prime")
	}

	// Validate p = 2q + 1
	twoQPlusOne := new(big.Int).Mul(big.NewInt(2), q)
	twoQPlusOne.Add(twoQPlusOne, big.NewInt(1))
	if p.Cmp(twoQPlusOne) != 0 {
		return nil, fmt.Errorf("p != 2q + 1")
	}

	// Validate g is in range [2, p)
	if g.Cmp(big.NewInt(2)) < 0 || g.Cmp(p) >= 0 {
		return nil, fmt.Errorf("g must be in range [2, p)")
	}

	// Validate g is a quadratic residue (Jacobi symbol == 1)
	if big.Jacobi(g, p) != 1 {
		return nil, fmt.Errorf("g is not a quadratic residue mod p")
	}

	group := &GqGroup{
		p: new(big.Int).Set(p),
		q: new(big.Int).Set(q),
	}
	group.generator = GqElement{value: new(big.Int).Set(g), group: group}
	group.identity = GqElement{value: big.NewInt(1), group: group}

	return group, nil
}

// P returns the modulus p.
func (g *GqGroup) P() *big.Int {
	return new(big.Int).Set(g.p)
}

// Q returns the group order q.
func (g *GqGroup) Q() *big.Int {
	return new(big.Int).Set(g.q)
}

// Generator returns the generator of this group.
func (g *GqGroup) Generator() GqElement {
	return g.generator
}

// Identity returns the identity element (1).
func (g *GqGroup) Identity() GqElement {
	return g.identity
}

// IsGroupMember checks if value is in G_q: value > 0 AND value < p AND Jacobi(value, p) == 1.
func (g *GqGroup) IsGroupMember(value *big.Int) bool {
	if value == nil {
		return false
	}
	if value.Sign() <= 0 || value.Cmp(g.p) >= 0 {
		return false
	}
	return big.Jacobi(value, g.p) == 1
}

// BitLength returns the bit length of q.
func (g *GqGroup) BitLength() int {
	return g.q.BitLen()
}

// Equals checks if two groups are the same.
func (g *GqGroup) Equals(other *GqGroup) bool {
	if other == nil {
		return false
	}
	return g.p.Cmp(other.p) == 0 && g.q.Cmp(other.q) == 0 && g.generator.value.Cmp(other.generator.value) == 0
}
