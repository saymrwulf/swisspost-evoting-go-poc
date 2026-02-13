package mixnet

import (
	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
)

// Shuffle holds the result of a re-encrypting shuffle.
type Shuffle struct {
	Shuffled *elgamal.CiphertextVector // C' shuffled ciphertexts
	Perm     Permutation               // π permutation used
	Rho      *emath.ZqVector           // ρ re-encryption exponents
}

// GenShuffle performs a re-encrypting shuffle on ciphertexts.
// C'_i = Enc(1; rho_i, pk) * C_{pi(i)}
func GenShuffle(cts *elgamal.CiphertextVector, pk elgamal.PublicKey) Shuffle {
	n := cts.Size()
	zqGroup := emath.ZqGroupFromGqGroup(pk.Group())

	perm := GenPermutation(n)
	rhoElems := make([]emath.ZqElement, n)
	shuffled := make([]elgamal.Ciphertext, n)

	for i := 0; i < n; i++ {
		rhoElems[i] = emath.RandomZqElement(zqGroup)
		// Enc(1; rho_i, pk)
		enc := elgamal.EncryptOnes(rhoElems[i], pk)
		// C'_i = enc * C_{pi(i)}
		shuffled[i] = enc.Multiply(cts.Get(perm.Apply(i)))
	}

	return Shuffle{
		Shuffled: elgamal.NewCiphertextVector(shuffled),
		Perm:     perm,
		Rho:      emath.ZqVectorOf(rhoElems...),
	}
}
