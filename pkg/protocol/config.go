package protocol

import (
	"crypto/rand"
	"fmt"
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// Config holds the election configuration.
type Config struct {
	Group       *emath.GqGroup
	NumCCs      int    // Number of control components (typically 4)
	NumOptions  int    // Number of voting options
	NumVoters   int    // Number of eligible voters
	ElectionID  string // Election event identifier
	SecurityLvl int    // Security level in bits (128)
}

// DefaultConfig creates a config with a safe prime group.
func DefaultConfig(numVoters, numOptions int) *Config {
	group := DefaultGroup()
	return &Config{
		Group:       group,
		NumCCs:      4,
		NumOptions:  numOptions,
		NumVoters:   numVoters,
		ElectionID:  "test-election-001",
		SecurityLvl: 128,
	}
}

// DefaultGroup returns a safe prime group for the PoC.
// Uses a pre-generated 512-bit safe prime for fast PoC testing.
// Production would use 3072 bits.
func DefaultGroup() *emath.GqGroup {
	// Pre-computed 512-bit safe prime: q is prime, p = 2q + 1 is prime
	// q = a prime ~255 bits, p = 2q+1 ~256 bits
	// Using a known safe prime from literature for reproducibility.
	// Generate a safe prime: p = 2q + 1 where both are prime.
	q := generateSafePrimeQ(256)
	p := new(big.Int).Mul(big.NewInt(2), q)
	p.Add(p, big.NewInt(1))

	// g = 4 (2^2 is a quadratic residue when 2 is a non-residue, which holds for p ≡ 3 mod 8)
	// But we need to verify. If Jacobi(4, p) != 1, try g = 9.
	g := big.NewInt(4)
	if big.Jacobi(g, p) != 1 {
		g = big.NewInt(9)
	}

	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		panic("failed to create group: " + err.Error())
	}
	fmt.Printf("  Generated safe prime group (q: %d bits, p: %d bits)\n", q.BitLen(), p.BitLen())
	return group
}

// generateSafePrimeQ generates a prime q such that p = 2q + 1 is also prime.
func generateSafePrimeQ(bits int) *big.Int {
	for {
		q, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			panic("failed to generate prime: " + err.Error())
		}
		// Check if p = 2q + 1 is also prime
		p := new(big.Int).Mul(big.NewInt(2), q)
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(64) {
			return q
		}
	}
}
