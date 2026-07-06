package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// MultiExponentiationArgument proves a multi-exponentiation relationship.
type MultiExponentiationArgument struct {
	CA0 emath.GqElement           // Commitment to a_0
	CB  *emath.GqVector           // Commitments to b vector (size 2m)
	E   *elgamal.CiphertextVector // Ciphertexts E (size 2m)
	A   *emath.ZqVector           // Aggregated a vector
	R   emath.ZqElement           // Aggregated randomness for commitments
	B   emath.ZqElement           // Aggregated b value
	S   emath.ZqElement           // Aggregated randomness for b commitments
	Tau emath.ZqElement           // Aggregated re-encryption randomness
}

// GenMultiExponentiationArgument generates a multi-exponentiation argument.
func GenMultiExponentiationArgument(
	cMatrix []*elgamal.CiphertextVector, // m ciphertext rows, each of size n
	cTarget elgamal.Ciphertext, // Target ciphertext
	cA *emath.GqVector, // Commitments to A columns (size m)
	A *emath.ZqMatrix, // n×m matrix (exponents)
	r *emath.ZqVector, // Randomness for A commitments
	rho emath.ZqElement, // Re-encryption randomness
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) MultiExponentiationArgument {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	n := A.NumRows()
	m := A.NumCols()
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)

	// 1. Random values
	a0 := emath.RandomZqVector(n, zqGroup)
	r0 := emath.RandomZqElement(zqGroup)

	bVec := make([]emath.ZqElement, 2*m)
	sVec := make([]emath.ZqElement, 2*m)
	tauVec := make([]emath.ZqElement, 2*m)

	for k := 0; k < 2*m; k++ {
		if k == m {
			bVec[k] = zero
			sVec[k] = zero
			tauVec[k] = rho
		} else {
			bVec[k] = emath.RandomZqElement(zqGroup)
			sVec[k] = emath.RandomZqElement(zqGroup)
			tauVec[k] = emath.RandomZqElement(zqGroup)
		}
	}

	// 2. Prepend a_0 to A → A' with m+1 columns
	aPrimeCols := make([]*emath.ZqVector, m+1)
	aPrimeCols[0] = a0
	for j := 0; j < m; j++ {
		aPrimeCols[j+1] = A.GetColumn(j)
	}

	// 3. Compute diagonal products D[k]
	// Java: D[k] = Π_{i in range} multiExp(C[i], A'[:,j]) where j = (k - m) + i + 1
	diagCts := make([]elgamal.Ciphertext, 2*m)
	for k := 0; k < 2*m; k++ {
		var lowerBound, upperBound int
		if k < m {
			lowerBound = m - k - 1
			upperBound = m
		} else {
			lowerBound = 0
			upperBound = 2*m - k
		}

		diagCt := identityCiphertext(pk.Size(), group)
		for i := lowerBound; i < upperBound; i++ {
			j := (k - m) + i + 1 // column index into A_prepended
			if j >= 0 && j <= m {
				exp := aPrimeCols[j]
				ct := multiExpCiphertextRow(cMatrix[i], exp)
				diagCt = diagCt.Multiply(ct)
			}
		}
		diagCts[k] = diagCt
	}

	// 4. Compute commitments
	cA0 := ck.Commit(a0, r0)

	cbElems := make([]emath.GqElement, 2*m)
	for k := 0; k < 2*m; k++ {
		bSingle := emath.ZqVectorOf(bVec[k])
		ck1 := CommitmentKey{H: ck.H, G: ck.G.SubVector(0, 1)}
		cbElems[k] = ck1.Commit(bSingle, sVec[k])
	}
	cB := emath.GqVectorOf(cbElems...)

	// E[k] = Enc(g^{b[k]}; tau[k], pk) * D[k]
	// Java: constantMessage(g_b_k, l) — ALL l phi elements are g^{b[k]}
	eVec := make([]elgamal.Ciphertext, 2*m)
	g := group.Generator()
	for k := 0; k < 2*m; k++ {
		gB := g.Exponentiate(bVec[k])
		msgElems := make([]emath.GqElement, pk.Size())
		for i := 0; i < pk.Size(); i++ {
			msgElems[i] = gB
		}
		msg := elgamal.NewMessage(emath.GqVectorOf(msgElems...))
		enc := elgamal.Encrypt(msg, tauVec[k], pk)
		eVec[k] = enc.Multiply(diagCts[k])
	}
	eCiphertexts := elgamal.NewCiphertextVector(eVec)

	// 5. Fiat-Shamir challenge x
	// Java hash order: (p, q, pk, ck, C_matrix, C, c_A, c_A_0, c_B, E)
	x := multiExpChallenge(group, pk, &ck, cMatrix, cTarget, cA, cA0, cB, eCiphertexts)
	xPowers := computeXPowers(x, 2*m+1, zqGroup)

	// 6. Compute proof elements
	aAgg := emath.ZqVectorOfZeros(n, zqGroup)
	for i := 0; i <= m; i++ {
		aAgg = aAgg.Add(aPrimeCols[i].ScalarMultiply(xPowers[i]))
	}

	rPrepended := r.Prepend(r0)
	rAgg := zero
	for i := 0; i <= m; i++ {
		rAgg = rAgg.Add(xPowers[i].Multiply(rPrepended.Get(i)))
	}

	bAgg := zero
	for k := 0; k < 2*m; k++ {
		bAgg = bAgg.Add(xPowers[k].Multiply(bVec[k]))
	}

	sAgg := zero
	for k := 0; k < 2*m; k++ {
		sAgg = sAgg.Add(xPowers[k].Multiply(sVec[k]))
	}

	tauAgg := zero
	for k := 0; k < 2*m; k++ {
		tauAgg = tauAgg.Add(xPowers[k].Multiply(tauVec[k]))
	}

	return MultiExponentiationArgument{
		CA0: cA0,
		CB:  cB,
		E:   eCiphertexts,
		A:   aAgg,
		R:   rAgg,
		B:   bAgg,
		S:   sAgg,
		Tau: tauAgg,
	}
}

// VerifyMultiExponentiationArgument verifies a multi-exponentiation argument.
func VerifyMultiExponentiationArgument(
	arg MultiExponentiationArgument,
	cMatrix []*elgamal.CiphertextVector,
	cTarget elgamal.Ciphertext,
	cA *emath.GqVector,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	m := cA.Size()

	// Reconstruct x
	x := multiExpChallenge(group, pk, &ck, cMatrix, cTarget, cA, arg.CA0, arg.CB, arg.E)
	xPowers := computeXPowers(x, 2*m+1, zqGroup)

	// Check 1: c_B[m] must be the identity, i.e. commit(0; 0). This pins
	// b_m = 0 so the extracted relation has no Enc(g^{b_m}) slack; without
	// it a malicious prover can shift the target ciphertext arbitrarily.
	if !arg.CB.Get(m).IsIdentity() {
		return false
	}

	// Check 2: Π c_A[:,i]^{x^i} * c_A_0 = commit(a, r)
	lhs := arg.CA0
	for i := 0; i < m; i++ {
		lhs = lhs.Multiply(cA.Get(i).Exponentiate(xPowers[i+1]))
	}
	rhs := ck.Commit(arg.A, arg.R)
	if !lhs.Equals(rhs) {
		return false
	}

	// Check 3: Π c_B[k]^{x^k} = commit([b], s)
	lhs2 := group.Identity()
	for k := 0; k < 2*m; k++ {
		lhs2 = lhs2.Multiply(arg.CB.Get(k).Exponentiate(xPowers[k]))
	}
	bSingle := emath.ZqVectorOf(arg.B)
	ck1 := CommitmentKey{H: ck.H, G: ck.G.SubVector(0, 1)}
	rhs2 := ck1.Commit(bSingle, arg.S)
	if !lhs2.Equals(rhs2) {
		return false
	}

	// Check 4: Π E[k]^{x^k} = Enc(g^b; tau, pk) * Π C_matrix[i]^{x^{m-i-1}*a}
	// Java: constantMessage(g_b, l) — ALL l phi elements are g^b
	g := group.Generator()
	gB := g.Exponentiate(arg.B)
	msgElems := make([]emath.GqElement, pk.Size())
	for i := 0; i < pk.Size(); i++ {
		msgElems[i] = gB
	}
	msg := elgamal.NewMessage(emath.GqVectorOf(msgElems...))
	enc := elgamal.Encrypt(msg, arg.Tau, pk)

	cMultiExp := identityCiphertext(pk.Size(), group)
	for i := 0; i < m; i++ {
		row := cMatrix[i]
		for j := 0; j < row.Size(); j++ {
			exp := arg.A.Get(j).Multiply(xPowers[m-i-1])
			ct := row.Get(j).Exponentiate(exp)
			cMultiExp = cMultiExp.Multiply(ct)
		}
	}
	rhs3 := enc.Multiply(cMultiExp)

	lhs3 := identityCiphertext(pk.Size(), group)
	for k := 0; k < 2*m; k++ {
		ct := arg.E.Get(k).Exponentiate(xPowers[k])
		lhs3 = lhs3.Multiply(ct)
	}

	return ciphertextEquals(lhs3, rhs3)
}

func identityCiphertext(size int, group *emath.GqGroup) elgamal.Ciphertext {
	phis := make([]emath.GqElement, size)
	for i := range phis {
		phis[i] = group.Identity()
	}
	return elgamal.NewCiphertext(group.Identity(), emath.GqVectorOf(phis...))
}

func ciphertextEquals(a, b elgamal.Ciphertext) bool {
	if !a.Gamma.Equals(b.Gamma) {
		return false
	}
	if a.Size() != b.Size() {
		return false
	}
	for i := 0; i < a.Size(); i++ {
		if !a.GetPhi(i).Equals(b.GetPhi(i)) {
			return false
		}
	}
	return true
}

func multiExpCiphertextRow(row *elgamal.CiphertextVector, exps *emath.ZqVector) elgamal.Ciphertext {
	if row.Size() != exps.Size() {
		panic("row and exponents must have same size")
	}
	result := identityCiphertext(row.PhiSize(), row.Group())
	for j := 0; j < row.Size(); j++ {
		ct := row.Get(j).Exponentiate(exps.Get(j))
		result = result.Multiply(ct)
	}
	return result
}

// multiExpChallenge computes the Fiat-Shamir challenge for MultiExponentiationArgument.
// Java hash order: (p, q, pk, ck, C_matrix, C, c_A, c_A_0, c_B, E)
func multiExpChallenge(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, cMatrix []*elgamal.CiphertextVector, cTarget elgamal.Ciphertext, cA *emath.GqVector, cA0 emath.GqElement, cB *emath.GqVector, eCts *elgamal.CiphertextVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		ciphertextMatrixToHashable(cMatrix),
		ciphertextToHashable(cTarget),
		gqVectorToHashable(cA),
		hash.HashableBigInt{Value: cA0.Value()},
		gqVectorToHashable(cB),
		ciphertextVectorToHashable(eCts),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
