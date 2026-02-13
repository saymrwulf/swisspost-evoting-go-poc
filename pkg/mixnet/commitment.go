package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

var oneBI = big.NewInt(1)

// CommitmentKey represents a Pedersen commitment key (h, g_1, ..., g_v).
type CommitmentKey struct {
	H emath.GqElement // First element h
	G *emath.GqVector // Elements g_1, ..., g_v
}

// Size returns v (the number of g elements, not counting h).
func (ck CommitmentKey) Size() int {
	return ck.G.Size()
}

// Group returns the group of this commitment key.
func (ck CommitmentKey) Group() *emath.GqGroup {
	return ck.H.Group()
}

// GenCommitmentKey generates a verifiable Pedersen commitment key.
// Uses hash-based generation: w = (hash(q, "commitmentKey", i, count) + 1)^2 mod p
func GenCommitmentKey(numElements int, group *emath.GqGroup) CommitmentKey {
	q := group.Q()
	p := group.P()
	g := group.Generator()

	var values []emath.GqElement
	count := 0
	i := 0

	for count <= numElements {
		// u = RecursiveHashToZq(q, "commitmentKey", q, i, count) + 1
		u := hash.RecursiveHashToZq(q,
			hash.HashableString{Value: "commitmentKey"},
			hash.HashableBigInt{Value: q},
			hash.HashableBigInt{Value: big.NewInt(int64(i))},
			hash.HashableBigInt{Value: big.NewInt(int64(count))},
		)
		uPlusOne := new(big.Int).Add(u, oneBI)

		// w = uPlusOne^2 mod p
		w := new(big.Int).Exp(uPlusOne, big.NewInt(2), p)

		// Check w != 1 AND w != g AND w not already in values
		wIsOne := w.Cmp(oneBI) == 0
		wIsG := w.Cmp(g.Value()) == 0
		wInValues := false
		for _, v := range values {
			if v.Value().Cmp(w) == 0 {
				wInValues = true
				break
			}
		}

		if !wIsOne && !wIsG && !wInValues {
			elem, _ := emath.NewGqElement(w, group)
			values = append(values, elem)
			count++
		}
		i++
	}

	// h = values[0], g = values[1..numElements]
	gElems := make([]emath.GqElement, numElements)
	copy(gElems, values[1:numElements+1])

	return CommitmentKey{
		H: values[0],
		G: emath.GqVectorOf(gElems...),
	}
}

// Commit computes a Pedersen commitment: C = h^r * Π(g_i^a_i)
func (ck CommitmentKey) Commit(a *emath.ZqVector, r emath.ZqElement) emath.GqElement {
	if a.Size() > ck.Size() {
		panic("vector size must not exceed commitment key size")
	}
	// h^r
	result := ck.H.Exponentiate(r)
	// Π(g_i^a_i)
	for i := 0; i < a.Size(); i++ {
		result = result.Multiply(ck.G.Get(i).Exponentiate(a.Get(i)))
	}
	return result
}

// CommitMatrix computes commitments to each column of a matrix.
func (ck CommitmentKey) CommitMatrix(A *emath.ZqMatrix, r *emath.ZqVector) *emath.GqVector {
	if A.NumCols() != r.Size() {
		panic("number of columns must match randomness vector size")
	}
	commitments := make([]emath.GqElement, A.NumCols())
	for j := 0; j < A.NumCols(); j++ {
		commitments[j] = ck.Commit(A.GetColumn(j), r.Get(j))
	}
	return emath.GqVectorOf(commitments...)
}
