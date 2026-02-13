package mixnet

import (
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// Permutation represents a random permutation of [0, N).
type Permutation struct {
	table []int
}

// GenPermutation generates a random permutation of size N using Fisher-Yates.
func GenPermutation(n int) Permutation {
	table := make([]int, n)
	for i := range table {
		table[i] = i
	}
	for i := 0; i < n; i++ {
		// offset = random integer in [0, n-i)
		max := big.NewInt(int64(n - i))
		offset := emath.RandomBigInt(max).Int64()
		// Swap table[i] with table[i+offset]
		j := i + int(offset)
		table[i], table[j] = table[j], table[i]
	}
	return Permutation{table: table}
}

// Apply returns π[i].
func (p Permutation) Apply(i int) int {
	return p.table[i]
}

// Size returns N.
func (p Permutation) Size() int {
	return len(p.table)
}

// Table returns a copy of the permutation table.
func (p Permutation) Table() []int {
	t := make([]int, len(p.table))
	copy(t, p.table)
	return t
}

// GetMatrixDimensions computes size-optimal m×n dimensions for a vector of size N.
// Returns (m, n) where m <= n, m*n = N, and m is the largest factor ≤ √N.
func GetMatrixDimensions(vectorSize int) (int, int) {
	if vectorSize < 2 {
		panic("size must be >= 2")
	}
	m := 1
	n := vectorSize
	sqrtN := isqrt(vectorSize)
	for i := sqrtN; i > 1; i-- {
		if vectorSize%i == 0 {
			m = i
			n = vectorSize / i
			break
		}
	}
	return m, n
}

func isqrt(n int) int {
	x := int64(n)
	s := new(big.Int).Sqrt(big.NewInt(x))
	return int(s.Int64())
}
