package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// HadamardArgument proves that b = ∏_j a_j (entrywise Hadamard product).
type HadamardArgument struct {
	CB   *emath.GqVector // Intermediate commitments (size m)
	Zero ZeroArgument    // Nested ZeroArgument
}

// GenHadamardArgument generates a Hadamard argument.
func GenHadamardArgument(
	cA *emath.GqVector,  // Commitments to A columns (size m)
	cb emath.GqElement,  // Commitment to b (Hadamard product)
	A *emath.ZqMatrix,   // n×m matrix
	b *emath.ZqVector,   // Hadamard product (size n)
	r *emath.ZqVector,   // Randomness for A columns (size m)
	s emath.ZqElement,   // Randomness for cb
	pk elgamal.PublicKey, // Public key (needed for Fiat-Shamir hash)
	ck CommitmentKey,
	group *emath.GqGroup,
) HadamardArgument {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	n := A.NumRows()
	m := A.NumCols()

	// 1. Compute intermediate products b_j = ∏_{i=0}^j A[:,i] (entrywise)
	bIntermediate := make([]*emath.ZqVector, m)
	bIntermediate[0] = A.GetColumn(0)
	for j := 1; j < m; j++ {
		bIntermediate[j] = bIntermediate[j-1].MultiplyElementWise(A.GetColumn(j))
	}

	// 2. Build c_B and s_vector
	cbVec := make([]emath.GqElement, m)
	sVec := make([]emath.ZqElement, m)
	cbVec[0] = cA.Get(0)
	sVec[0] = r.Get(0)
	for j := 1; j < m-1; j++ {
		sVec[j] = emath.RandomZqElement(zqGroup)
		cbVec[j] = ck.Commit(bIntermediate[j], sVec[j])
	}
	cbVec[m-1] = cb
	sVec[m-1] = s
	cB := emath.GqVectorOf(cbVec...)

	// 3. Fiat-Shamir for x
	// Java hash order: (p, q, pk, ck, c_A, c_b, c_B)
	x := hadamardChallengeX(group, pk, &ck, cA, cb, cB)

	// 4. Compute x^i powers
	xPowers := computeXPowers(x, m+1, zqGroup)

	// 5. Fiat-Shamir for y (with "1" prefix)
	// Java hash order: ("1", p, q, pk, ck, c_A, c_b, c_B)
	y := hadamardChallengeY(group, pk, &ck, cA, cb, cB)

	// 6. Prepare ZeroArgument matrices
	one, _ := emath.NewZqElement(big.NewInt(1), zqGroup)
	negOnes := make([]emath.ZqElement, n)
	for i := range negOnes {
		negOnes[i] = one.Negate()
	}

	aZeroCols := make([]*emath.ZqVector, m)
	for j := 0; j < m-1; j++ {
		aZeroCols[j] = A.GetColumn(j + 1)
	}
	aZeroCols[m-1] = emath.ZqVectorOf(negOnes...)

	// Java: d_matrix[i] = x^(i+1) * b_vectors[i] for i=0..m-2
	dZeroCols := make([]*emath.ZqVector, m)
	for i := 0; i < m-1; i++ {
		dZeroCols[i] = bIntermediate[i].ScalarMultiply(xPowers[i+1])
	}
	// Java: d[j] = Σ(i=1..m-1) x^i * b_vectors[i][j]
	dFinal := emath.ZqVectorOfZeros(n, zqGroup)
	for i := 1; i < m; i++ {
		dFinal = dFinal.Add(bIntermediate[i].ScalarMultiply(xPowers[i]))
	}
	dZeroCols[m-1] = dFinal

	// Build c_A_zero and c_D_zero
	// Java: r_zero = [r[1:], 0] — last randomness is 0, not random
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)
	cAZero := make([]emath.GqElement, m)
	rZero := make([]emath.ZqElement, m)
	for j := 0; j < m-1; j++ {
		cAZero[j] = cA.Get(j + 1)
		rZero[j] = r.Get(j + 1)
	}
	// Java: c_minus_one = commit((-1,...,-1), 0)
	cAZero[m-1] = ck.Commit(emath.ZqVectorOf(negOnes...), zero)
	rZero[m-1] = zero

	// Java: c_D_vector[i] = c_B[i]^(x^(i+1)) for i=0..m-2
	cDZero := make([]emath.GqElement, m)
	sDZero := make([]emath.ZqElement, m)
	for i := 0; i < m-1; i++ {
		sDZero[i] = sVec[i].Multiply(xPowers[i+1])
		cDZero[i] = cB.Get(i).Exponentiate(xPowers[i+1])
	}
	// Java: t = Σ(i=1..m-1) x^i * s_vector[i]
	sDFinal := zqGroup.Identity()
	for i := 1; i < m; i++ {
		sDFinal = sDFinal.Add(sVec[i].Multiply(xPowers[i]))
	}
	sDZero[m-1] = sDFinal
	// Java: c_D = Π(i=1..m-1) c_B[i]^(x^i)
	cDFinal := group.Identity()
	for i := 1; i < m; i++ {
		cDFinal = cDFinal.Multiply(cB.Get(i).Exponentiate(xPowers[i]))
	}
	cDZero[m-1] = cDFinal

	// Build matrices
	aZeroMatrix := emath.ZqMatrixFromColumns(aZeroCols)
	dZeroMatrix := emath.ZqMatrixFromColumns(dZeroCols)

	cAZeroVec := emath.GqVectorOf(cAZero...)
	cDZeroVec := emath.GqVectorOf(cDZero...)
	rZeroVec := emath.ZqVectorOf(rZero...)
	sDZeroVec := emath.ZqVectorOf(sDZero...)

	// 7. Generate ZeroArgument (now with pk)
	zeroArg := GenZeroArgument(cAZeroVec, cDZeroVec, aZeroMatrix, dZeroMatrix, rZeroVec, sDZeroVec, y, pk, ck, group)

	return HadamardArgument{
		CB:   cB,
		Zero: zeroArg,
	}
}

// VerifyHadamardArgument verifies a Hadamard argument.
func VerifyHadamardArgument(
	arg HadamardArgument,
	cA *emath.GqVector,
	cb emath.GqElement,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	m := cA.Size()

	// Check c_B[0] = c_A[0]
	if !arg.CB.Get(0).Equals(cA.Get(0)) {
		return false
	}

	// Check c_B[m-1] = c_b
	if !arg.CB.Get(m - 1).Equals(cb) {
		return false
	}

	// Reconstruct x and y
	x := hadamardChallengeX(group, pk, &ck, cA, cb, arg.CB)
	y := hadamardChallengeY(group, pk, &ck, cA, cb, arg.CB)

	zqGroup := emath.ZqGroupFromGqGroup(group)
	xPowers := computeXPowers(x, m+1, zqGroup)

	// Reconstruct c_A_zero and c_D_zero for verification
	n := arg.Zero.APrime.Size()
	one, _ := emath.NewZqElement(big.NewInt(1), zqGroup)
	negOnes := make([]emath.ZqElement, n)
	for i := range negOnes {
		negOnes[i] = one.Negate()
	}

	cAZero := make([]emath.GqElement, m)
	for j := 0; j < m-1; j++ {
		cAZero[j] = cA.Get(j + 1)
	}
	// For the c_A_zero, the last element (commitment to -1s) needs to be
	// derived from the ZeroArgument itself. Since VerifyZeroArgument handles
	// all commitment checks internally, we pass through.
	cNegOnes := ck.Commit(emath.ZqVectorOf(negOnes...), zqGroup.Identity())
	cAZero[m-1] = cNegOnes

	// Build c_D_zero
	// Java: c_D_vector[i] = c_B[i]^(x^(i+1)) for i=0..m-2
	cDZero := make([]emath.GqElement, m)
	for i := 0; i < m-1; i++ {
		cDZero[i] = arg.CB.Get(i).Exponentiate(xPowers[i+1])
	}
	// Java: c_D = Π(i=1..m-1) c_B[i]^(x^i)
	cDFinal := group.Identity()
	for i := 1; i < m; i++ {
		cDFinal = cDFinal.Multiply(arg.CB.Get(i).Exponentiate(xPowers[i]))
	}
	cDZero[m-1] = cDFinal

	cAZeroVec := emath.GqVectorOf(cAZero...)
	cDZeroVec := emath.GqVectorOf(cDZero...)

	// Verify the ZeroArgument
	return VerifyZeroArgument(arg.Zero, cAZeroVec, cDZeroVec, y, pk, ck, group)
}

// hadamardChallengeX computes the X challenge for HadamardArgument.
// Java hash order: (p, q, pk, ck, c_A, c_b, c_B)
func hadamardChallengeX(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, cA *emath.GqVector, cb emath.GqElement, cB *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		gqVectorToHashable(cA),
		hash.HashableBigInt{Value: cb.Value()},
		gqVectorToHashable(cB),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}

// hadamardChallengeY computes the Y challenge for HadamardArgument.
// Java hash order: ("1", p, q, pk, ck, c_A, c_b, c_B)
func hadamardChallengeY(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, cA *emath.GqVector, cb emath.GqElement, cB *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableString{Value: "1"},
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		gqVectorToHashable(cA),
		hash.HashableBigInt{Value: cb.Value()},
		gqVectorToHashable(cB),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
