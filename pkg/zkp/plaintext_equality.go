package zkp

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// GenPlaintextEqualityProof generates a proof that two ciphertexts encrypt
// the same plaintext under different keys.
// C1 = Enc(m, r0, h), C2 = Enc(m, r1, h')
func GenPlaintextEqualityProof(
	c1, c2 elgamal.Ciphertext,
	h, hPrime emath.GqElement,
	r0, r1 emath.ZqElement,
	group *emath.GqGroup,
	auxInfo ...hash.Hashable,
) PlaintextEqualityProof {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	// 1. Sample random b0, b1
	b0 := emath.RandomZqElement(zqGroup)
	b1 := emath.RandomZqElement(zqGroup)

	// 2. Compute phi(b, h, h') = (g^b0, g^b1, h^b0 / h'^b1)
	commit0 := g.Exponentiate(b0)
	commit1 := g.Exponentiate(b1)
	commit2 := h.Exponentiate(b0).Divide(hPrime.Exponentiate(b1))

	commitments := emath.GqVectorOf(commit0, commit1, commit2)

	// 3. Statement: y = (gamma1, gamma2, phi1/phi2')
	phi1 := c1.GetPhi(0)
	phi2 := c2.GetPhi(0)
	y := emath.GqVectorOf(c1.Gamma, c2.Gamma, phi1.Divide(phi2))

	// 4. Compute challenge
	e := plaintextEqualityChallenge(group, h, hPrime, y, commitments, phi1, phi2, zqGroup, auxInfo)

	// 5. Response: z0 = b0 + e*r0, z1 = b1 + e*r1
	z0 := b0.Add(e.Multiply(r0))
	z1 := b1.Add(e.Multiply(r1))

	return PlaintextEqualityProof{
		E: e,
		Z: emath.ZqVectorOf(z0, z1),
	}
}

// VerifyPlaintextEqualityProof verifies a plaintext equality proof.
func VerifyPlaintextEqualityProof(
	c1, c2 elgamal.Ciphertext,
	h, hPrime emath.GqElement,
	proof PlaintextEqualityProof,
	group *emath.GqGroup,
	auxInfo ...hash.Hashable,
) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	z0 := proof.Z.Get(0)
	z1 := proof.Z.Get(1)

	// Compute phi(z, h, h') = (g^z0, g^z1, h^z0 / h'^z1)
	x0 := g.Exponentiate(z0)
	x1 := g.Exponentiate(z1)
	x2 := h.Exponentiate(z0).Divide(hPrime.Exponentiate(z1))

	// Statement: y = (gamma1, gamma2, phi1/phi2')
	phi1 := c1.GetPhi(0)
	phi2 := c2.GetPhi(0)
	y := emath.GqVectorOf(c1.Gamma, c2.Gamma, phi1.Divide(phi2))

	// Reconstruct commitments: c'_i = x_i * y_i^(-e)
	negE := proof.E.Negate()
	c0 := x0.Multiply(y.Get(0).Exponentiate(negE))
	c1Prime := x1.Multiply(y.Get(1).Exponentiate(negE))
	c2Prime := x2.Multiply(y.Get(2).Exponentiate(negE))

	commitments := emath.GqVectorOf(c0, c1Prime, c2Prime)

	// Recompute challenge
	ePrime := plaintextEqualityChallenge(group, h, hPrime, y, commitments, phi1, phi2, zqGroup, auxInfo)

	return proof.E.Equals(ePrime)
}

func plaintextEqualityChallenge(group *emath.GqGroup, h, hPrime emath.GqElement, y, commitments *emath.GqVector, phi1, phi2 emath.GqElement, zqGroup *emath.ZqGroup, auxInfo []hash.Hashable) emath.ZqElement {
	// f = (p, q, g, h, h')
	f := hash.HashableList{Elements: []hash.Hashable{
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		hash.HashableBigInt{Value: group.Generator().Value()},
		hash.HashableBigInt{Value: h.Value()},
		hash.HashableBigInt{Value: hPrime.Value()},
	}}

	yHash := gqVectorToHashableList(y)
	cHash := gqVectorToHashableList(commitments)

	// h_aux: ["PlaintextEqualityProof", phi1, phi2] or ["PlaintextEqualityProof", phi1, phi2, i_aux]
	auxElements := []hash.Hashable{
		hash.HashableString{Value: "PlaintextEqualityProof"},
		hash.HashableBigInt{Value: phi1.Value()},
		hash.HashableBigInt{Value: phi2.Value()},
	}
	if len(auxInfo) > 0 {
		auxElements = append(auxElements, auxInfo...)
	}
	hAux := hash.HashableList{Elements: auxElements}

	hashBytes := hash.RecursiveHash(f, yHash, cHash, hAux)
	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, zqGroup.Q())
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
