package mixnet

import (
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// StarMap computes the bilinear star map: ★(a, b, y) = Σ_j (a_j * b_j * y^(j+1))
func StarMap(a, b *emath.ZqVector, y emath.ZqElement) emath.ZqElement {
	if a.Size() != b.Size() {
		panic("vectors must have same size")
	}
	group := y.Group()
	result, _ := emath.NewZqElement(big.NewInt(0), group)

	yPow := y // y^1
	for j := 0; j < a.Size(); j++ {
		// a_j * b_j * y^(j+1)
		term := a.Get(j).Multiply(b.Get(j)).Multiply(yPow)
		result = result.Add(term)
		yPow = yPow.Multiply(y)
	}
	return result
}
