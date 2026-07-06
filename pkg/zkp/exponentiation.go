package zkp

import (
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// GenExponentiationProof generates a proof that all exponentiations
// share the same exponent: y_i = bases_i^x for all i.
func GenExponentiationProof(bases *emath.GqVector, x emath.ZqElement, exponentiations *emath.GqVector, group *emath.GqGroup, auxInfo ...hash.Hashable) ExponentiationProof {
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// 1. Sample random b
	b := emath.RandomZqElement(zqGroup)

	// 2. Commitment: c_i = bases_i^b
	c := bases.ExpScalar(b)

	// 3. Compute challenge
	e := exponentiationChallenge(group, bases, exponentiations, c, zqGroup, auxInfo)

	// 4. Response: z = b + e*x
	z := b.Add(e.Multiply(x))

	return ExponentiationProof{E: e, Z: z}
}

// VerifyExponentiationProof verifies an exponentiation proof.
func VerifyExponentiationProof(bases *emath.GqVector, exponentiations *emath.GqVector, proof ExponentiationProof, group *emath.GqGroup, auxInfo ...hash.Hashable) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// Reconstruct commitments: c'_i = bases_i^z * y_i^(-e)
	basesZ := bases.ExpScalar(proof.Z)
	yNegE := exponentiations.ExpScalar(proof.E.Negate())
	cPrime := basesZ.Multiply(yNegE)

	// Recompute challenge
	ePrime := exponentiationChallenge(group, bases, exponentiations, cPrime, zqGroup, auxInfo)

	return proof.E.Equals(ePrime)
}

// exponentiationChallenge computes the Fiat-Shamir challenge for exponentiation proofs.
// Hash order: (p, q, [bases]), [exponentiations], [commitments], h_aux
func exponentiationChallenge(group *emath.GqGroup, bases, exponentiations, commitments *emath.GqVector, zqGroup *emath.ZqGroup, auxInfo []hash.Hashable) emath.ZqElement {
	// f = (p, q, [bases])
	fElems := []hash.Hashable{
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
	}
	basesHashable := gqVectorToHashableList(bases)
	fElems = append(fElems, basesHashable)
	f := hash.HashableList{Elements: fElems}

	// y = [exponentiations]
	y := gqVectorToHashableList(exponentiations)

	// c = [commitments]
	c := gqVectorToHashableList(commitments)

	// h_aux
	hAux := buildAuxHash("ExponentiationProof", auxInfo)

	// Uniform Z_q challenge via oversample-then-reduce (Swiss Post spec).
	eVal := hash.RecursiveHashToZq(zqGroup.Q(), f, y, c, hAux)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}

// gqVectorToHashableList converts a GqVector to a HashableList of BigInts.
func gqVectorToHashableList(v *emath.GqVector) hash.HashableList {
	elements := make([]hash.Hashable, v.Size())
	for i := 0; i < v.Size(); i++ {
		elements[i] = hash.HashableBigInt{Value: v.Get(i).Value()}
	}
	return hash.HashableList{Elements: elements}
}
