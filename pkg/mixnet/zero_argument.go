package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// ZeroArgument is a proof that Σ_i a_i ★ b_{i-1} = 0 for committed matrices A, B.
type ZeroArgument struct {
	CA0    emath.GqElement // Commitment to a_0 (prepended column)
	CBm    emath.GqElement // Commitment to b_m (appended column)
	CD     *emath.GqVector // Commitments to diagonal d vector (size 2m+1)
	APrime *emath.ZqVector // Aggregated a' vector
	BPrime *emath.ZqVector // Aggregated b' vector
	RPrime emath.ZqElement // Aggregated randomness for A
	SPrime emath.ZqElement // Aggregated randomness for B
	TPrime emath.ZqElement // Aggregated randomness for D
}

// GenZeroArgument generates a ZeroArgument proof.
func GenZeroArgument(
	cA *emath.GqVector, // Commitments to A columns (size m)
	cB *emath.GqVector, // Commitments to B columns (size m)
	A *emath.ZqMatrix, // n×m matrix
	B *emath.ZqMatrix, // n×m matrix
	r *emath.ZqVector, // Randomness for A (size m)
	s *emath.ZqVector, // Randomness for B (size m)
	y emath.ZqElement, // Star map parameter
	pk elgamal.PublicKey, // Public key (needed for Fiat-Shamir hash)
	ck CommitmentKey,
	group *emath.GqGroup,
) ZeroArgument {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	n := A.NumRows()
	m := A.NumCols()

	// 1. Prepend random a_0 to A, append random b_m to B
	a0 := emath.RandomZqVector(n, zqGroup)
	r0 := emath.RandomZqElement(zqGroup)
	cA0 := ck.Commit(a0, r0)

	bm := emath.RandomZqVector(n, zqGroup)
	sm := emath.RandomZqElement(zqGroup)
	cBm := ck.Commit(bm, sm)

	// A' = [a_0 | A] (m+1 columns, n rows)
	aPrimeCols := make([]*emath.ZqVector, m+1)
	aPrimeCols[0] = a0
	for j := 0; j < m; j++ {
		aPrimeCols[j+1] = A.GetColumn(j)
	}

	// B' = [B | b_m] (m+1 columns, n rows)
	bPrimeCols := make([]*emath.ZqVector, m+1)
	for j := 0; j < m; j++ {
		bPrimeCols[j] = B.GetColumn(j)
	}
	bPrimeCols[m] = bm

	// r' = [r_0 | r] and s' = [s | s_m]
	rPrepended := r.Prepend(r0)
	sAppended := s.Append(sm)

	// 2. Compute d vector (diagonal star map products)
	// Java formula: d[k] = Σ StarMap(A'[i], B'[j]) where j = (m - k) + i
	// Bounds: i = max(0, k-m) to m, break when j > m
	dSize := 2*m + 1
	dVec := make([]emath.ZqElement, dSize)
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)
	for k := 0; k < dSize; k++ {
		dVec[k] = zero
		for i := max(0, k-m); i <= m; i++ {
			j := (m - k) + i
			if j > m {
				break
			}
			if j >= 0 {
				sm := StarMap(aPrimeCols[i], bPrimeCols[j], y)
				dVec[k] = dVec[k].Add(sm)
			}
		}
	}

	// 3. Generate randomness for d (Java: t[m+1] = 0)
	tVec := make([]emath.ZqElement, dSize)
	for k := 0; k < dSize; k++ {
		if k == m+1 {
			tVec[k] = zero
		} else {
			tVec[k] = emath.RandomZqElement(zqGroup)
		}
	}

	// 4. Compute commitments to d
	cdElems := make([]emath.GqElement, dSize)
	for k := 0; k < dSize; k++ {
		cdElems[k] = ck.H.Exponentiate(tVec[k]).Multiply(ck.G.Get(0).Exponentiate(dVec[k]))
	}
	cD := emath.GqVectorOf(cdElems...)

	// 5. Fiat-Shamir challenge x
	// Java hash order: (p, q, pk, ck, c_A_0, c_B_m, c_d, c_B, c_A)
	x := zeroArgumentChallenge(group, pk, &ck, cA0, cBm, cD, cB, cA)

	// 6. Compute x^i powers
	xPowers := computeXPowers(x, 2*m+1, zqGroup)

	// 7. Compute proof elements
	aPrimeVec := emath.ZqVectorOfZeros(n, zqGroup)
	for i := 0; i <= m; i++ {
		scaled := aPrimeCols[i].ScalarMultiply(xPowers[i])
		aPrimeVec = aPrimeVec.Add(scaled)
	}

	bPrimeVec := emath.ZqVectorOfZeros(n, zqGroup)
	for i := 0; i <= m; i++ {
		scaled := bPrimeCols[i].ScalarMultiply(xPowers[m-i])
		bPrimeVec = bPrimeVec.Add(scaled)
	}

	rPrimeVal := zero
	for i := 0; i <= m; i++ {
		rPrimeVal = rPrimeVal.Add(xPowers[i].Multiply(rPrepended.Get(i)))
	}

	sPrimeVal := zero
	for i := 0; i <= m; i++ {
		sPrimeVal = sPrimeVal.Add(xPowers[m-i].Multiply(sAppended.Get(i)))
	}

	tPrimeVal := zero
	for k := 0; k < dSize; k++ {
		tPrimeVal = tPrimeVal.Add(xPowers[k].Multiply(tVec[k]))
	}

	return ZeroArgument{
		CA0:    cA0,
		CBm:    cBm,
		CD:     cD,
		APrime: aPrimeVec,
		BPrime: bPrimeVec,
		RPrime: rPrimeVal,
		SPrime: sPrimeVal,
		TPrime: tPrimeVal,
	}
}

// VerifyZeroArgument verifies a ZeroArgument proof.
func VerifyZeroArgument(
	arg ZeroArgument,
	cA *emath.GqVector,
	cB *emath.GqVector,
	y emath.ZqElement,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	m := cA.Size()

	// 1. Reconstruct x
	x := zeroArgumentChallenge(group, pk, &ck, arg.CA0, arg.CBm, arg.CD, cB, cA)
	xPowers := computeXPowers(x, 2*m+1, zqGroup)

	// 2. Check c_D[m+1] commits to 0 (Java: c_d.get(m+1) == 1)
	if !arg.CD.Get(m + 1).IsIdentity() {
		return false
	}

	// 3. Check Π(c_A[:,i]^{x^(i+1)}) * c_A_0^{x^0} = commit(a', r')
	lhs1 := arg.CA0.Exponentiate(xPowers[0])
	for i := 0; i < m; i++ {
		lhs1 = lhs1.Multiply(cA.Get(i).Exponentiate(xPowers[i+1]))
	}
	rhs1 := ck.Commit(arg.APrime, arg.RPrime)
	if !lhs1.Equals(rhs1) {
		return false
	}

	// 4. Check Π(c_B[:,i]^{x^(m-i)}) * c_B_m^{x^0} = commit(b', s')
	lhs2 := arg.CBm.Exponentiate(xPowers[0])
	for i := 0; i < m; i++ {
		lhs2 = lhs2.Multiply(cB.Get(i).Exponentiate(xPowers[m-i]))
	}
	rhs2 := ck.Commit(arg.BPrime, arg.SPrime)
	if !lhs2.Equals(rhs2) {
		return false
	}

	// 5. Check Π(c_D[k]^{x^k}) = commit(starMap(a', b', y), t')
	lhs3 := group.Identity()
	for k := 0; k < arg.CD.Size(); k++ {
		lhs3 = lhs3.Multiply(arg.CD.Get(k).Exponentiate(xPowers[k]))
	}
	starMapVal := StarMap(arg.APrime, arg.BPrime, y)
	rhs3 := ck.H.Exponentiate(arg.TPrime).Multiply(ck.G.Get(0).Exponentiate(starMapVal))
	return lhs3.Equals(rhs3)
}

// zeroArgumentChallenge computes the Fiat-Shamir challenge for ZeroArgument.
// Java hash order: (p, q, pk, ck, c_A_0, c_B_m, c_d, c_B, c_A)
func zeroArgumentChallenge(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, cA0, cBm emath.GqElement, cD, cB, cA *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		hash.HashableBigInt{Value: cA0.Value()},
		hash.HashableBigInt{Value: cBm.Value()},
		gqVectorToHashable(cD),
		gqVectorToHashable(cB),
		gqVectorToHashable(cA),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}

func computeXPowers(x emath.ZqElement, count int, group *emath.ZqGroup) []emath.ZqElement {
	powers := make([]emath.ZqElement, count)
	one, _ := emath.NewZqElement(big.NewInt(1), group)
	powers[0] = one
	if count > 1 {
		powers[1] = x
		for i := 2; i < count; i++ {
			powers[i] = powers[i-1].Multiply(x)
		}
	}
	return powers
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
