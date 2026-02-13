package hash

import (
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// HashAndSquare hashes a value x to a GqElement by:
// 1. Computing h = RecursiveHashToZq(q, "HashAndSquare", x)
// 2. Adding 1: h_plus_one = h + 1
// 3. Squaring: result = (h+1)^2 mod p (guaranteed to be in G_q)
func HashAndSquare(x *big.Int, group *emath.GqGroup) emath.GqElement {
	q := group.Q()
	// Hash to Z_q with "HashAndSquare" label
	h := RecursiveHashToZq(q, HashableString{Value: "HashAndSquare"}, HashableBigInt{Value: x})
	// Add 1
	hPlusOne := new(big.Int).Add(h, big.NewInt(1))
	// Square mod p to get element of G_q
	elem, err := emath.GqElementFromSquareRoot(hPlusOne, group)
	if err != nil {
		panic("HashAndSquare: failed to create GqElement: " + err.Error())
	}
	return elem
}
