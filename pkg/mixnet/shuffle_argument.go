package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// ShuffleArgument is the top-level proof combining ProductArgument and MultiExponentiationArgument.
type ShuffleArgument struct {
	CA       *emath.GqVector             // Commitments to permutation matrix columns
	CB       *emath.GqVector             // Commitments to B = x^π columns
	Product  ProductArgument             // Product argument
	MultiExp MultiExponentiationArgument // Multi-exponentiation argument
}

// GenShuffleArgument generates a shuffle argument proving C' is a valid shuffle of C.
func GenShuffleArgument(
	C *elgamal.CiphertextVector, // Original ciphertexts
	CPrime *elgamal.CiphertextVector, // Shuffled ciphertexts
	perm Permutation, // Permutation used
	rho *emath.ZqVector, // Re-encryption exponents
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) ShuffleArgument {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	N := C.Size()
	m, n := GetMatrixDimensions(N)

	emitArgument("shuffle",
		"Shuffle argument: prove C' is a permutation + re-encryption of C, without revealing π",
		`\text{ShuffleArgument}:\ \prod_i C_i^{\,x^{i}} \;\sim\; \prod_i C'^{\,x^{\pi(i)}}_i`,
		"ShuffleArgument: Π_i C_i^{x^i} ~ Π_i C'_i^{x^π(i)}   (bound via c_A, c_B; challenges x,y,z)",
		dims(m, n))

	// 1. Convert permutation to m×n matrix A
	aCols := make([]*emath.ZqVector, m)
	rA := emath.RandomZqVector(m, zqGroup)
	for j := 0; j < m; j++ {
		col := make([]emath.ZqElement, n)
		for i := 0; i < n; i++ {
			val := big.NewInt(int64(perm.Apply(n*j + i)))
			col[i], _ = emath.NewZqElement(val, zqGroup)
		}
		aCols[j] = emath.ZqVectorOf(col...)
	}
	A := emath.ZqMatrixFromColumns(aCols)

	// Commit to A columns
	cA := ck.CommitMatrix(A, rA)

	// 2. Fiat-Shamir for x
	x := shuffleArgumentChallengeX(group, pk, &ck, C, CPrime, cA)

	// 3. Compute B matrix: b[i] = x^(π[i])
	xPowers := computeXPowers(x, N, zqGroup)
	bCols := make([]*emath.ZqVector, m)
	rB := emath.RandomZqVector(m, zqGroup)
	for j := 0; j < m; j++ {
		col := make([]emath.ZqElement, n)
		for i := 0; i < n; i++ {
			piVal := perm.Apply(n*j + i)
			col[i] = xPowers[piVal]
		}
		bCols[j] = emath.ZqVectorOf(col...)
	}
	B := emath.ZqMatrixFromColumns(bCols)
	cB := ck.CommitMatrix(B, rB)

	// 4. Fiat-Shamir for y and z
	y := shuffleArgumentChallengeY(group, pk, &ck, C, CPrime, cA, cB)
	z := shuffleArgumentChallengeZ(group, pk, &ck, C, CPrime, cA, cB)

	// 5. Compute D = y*A + B (element-wise)
	one, _ := emath.NewZqElement(big.NewInt(1), zqGroup)
	dCols := make([]*emath.ZqVector, m)
	for j := 0; j < m; j++ {
		dCols[j] = aCols[j].ScalarMultiply(y).Add(bCols[j])
	}

	// 6. Compute D - z for product argument
	dzCols := make([]*emath.ZqVector, m)
	for j := 0; j < m; j++ {
		dzCol := make([]emath.ZqElement, n)
		for i := 0; i < n; i++ {
			dzCol[i] = dCols[j].Get(i).Subtract(z)
		}
		dzCols[j] = emath.ZqVectorOf(dzCol...)
	}
	DZ := emath.ZqMatrixFromColumns(dzCols)

	// Compute b_product = Π_{i=0}^{N-1} (y*i + x^i - z)
	bProduct := one
	for i := 0; i < N; i++ {
		iBI := big.NewInt(int64(i))
		iElem, _ := emath.NewZqElement(iBI, zqGroup)
		term := y.Multiply(iElem).Add(xPowers[i]).Subtract(z)
		bProduct = bProduct.Multiply(term)
	}

	// Commitment to D-z
	rDZ := make([]emath.ZqElement, m)
	cDZ := make([]emath.GqElement, m)
	for j := 0; j < m; j++ {
		rDZ[j] = y.Multiply(rA.Get(j)).Add(rB.Get(j))
		cNegZ := ck.Commit(emath.ZqVectorOf(func() []emath.ZqElement {
			v := make([]emath.ZqElement, n)
			for i := range v {
				v[i] = z.Negate()
			}
			return v
		}()...), zqGroup.Identity())
		cDZ[j] = cA.Get(j).Exponentiate(y).Multiply(cB.Get(j)).Multiply(cNegZ)
	}
	cDZVec := emath.GqVectorOf(cDZ...)
	rDZVec := emath.ZqVectorOf(rDZ...)

	// 7. Product argument
	prodArg := GenProductArgument(cDZVec, bProduct, DZ, rDZVec, pk, ck, group)

	// 8. Multi-exponentiation argument
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)
	rhoAgg := zero
	for i := 0; i < N; i++ {
		piVal := perm.Apply(i)
		rhoAgg = rhoAgg.Add(rho.Get(i).Multiply(xPowers[piVal]))
	}
	rhoAgg = rhoAgg.Negate()

	// Build C' as m ciphertext rows of n
	cPrimeRows := make([]*elgamal.CiphertextVector, m)
	for j := 0; j < m; j++ {
		rowCts := make([]elgamal.Ciphertext, n)
		for i := 0; i < n; i++ {
			rowCts[i] = CPrime.Get(n*j + i)
		}
		cPrimeRows[j] = elgamal.NewCiphertextVector(rowCts)
	}

	// Compute C_agg = Π C[i]^{x^i}
	cAgg := identityCiphertext(C.PhiSize(), group)
	for i := 0; i < N; i++ {
		ct := C.Get(i).Exponentiate(xPowers[i])
		cAgg = cAgg.Multiply(ct)
	}

	multiExpArg := GenMultiExponentiationArgument(cPrimeRows, cAgg, cB, B, rB, rhoAgg, pk, ck, group)

	return ShuffleArgument{
		CA:       cA,
		CB:       cB,
		Product:  prodArg,
		MultiExp: multiExpArg,
	}
}

// VerifyShuffleArgument verifies a shuffle argument.
func VerifyShuffleArgument(
	arg ShuffleArgument,
	C *elgamal.CiphertextVector,
	CPrime *elgamal.CiphertextVector,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	N := C.Size()
	m, n := GetMatrixDimensions(N)

	// Reconstruct challenges
	x := shuffleArgumentChallengeX(group, pk, &ck, C, CPrime, arg.CA)
	y := shuffleArgumentChallengeY(group, pk, &ck, C, CPrime, arg.CA, arg.CB)
	z := shuffleArgumentChallengeZ(group, pk, &ck, C, CPrime, arg.CA, arg.CB)

	xPowers := computeXPowers(x, N, zqGroup)
	one, _ := emath.NewZqElement(big.NewInt(1), zqGroup)

	// Compute b_product
	bProduct := one
	for i := 0; i < N; i++ {
		iBI := big.NewInt(int64(i))
		iElem, _ := emath.NewZqElement(iBI, zqGroup)
		term := y.Multiply(iElem).Add(xPowers[i]).Subtract(z)
		bProduct = bProduct.Multiply(term)
	}

	// Reconstruct c_{D-z}
	cDZ := make([]emath.GqElement, m)
	for j := 0; j < m; j++ {
		cNegZ := ck.Commit(emath.ZqVectorOf(func() []emath.ZqElement {
			v := make([]emath.ZqElement, n)
			for i := range v {
				v[i] = z.Negate()
			}
			return v
		}()...), zqGroup.Identity())
		cDZ[j] = arg.CA.Get(j).Exponentiate(y).Multiply(arg.CB.Get(j)).Multiply(cNegZ)
	}
	cDZVec := emath.GqVectorOf(cDZ...)

	// Verify product argument
	if !VerifyProductArgument(arg.Product, cDZVec, bProduct, pk, ck, group) {
		return false
	}

	// Reconstruct cMatrix and cAgg for multi-exponentiation
	cPrimeRows := make([]*elgamal.CiphertextVector, m)
	for j := 0; j < m; j++ {
		rowCts := make([]elgamal.Ciphertext, n)
		for i := 0; i < n; i++ {
			rowCts[i] = CPrime.Get(n*j + i)
		}
		cPrimeRows[j] = elgamal.NewCiphertextVector(rowCts)
	}

	cAgg := identityCiphertext(C.PhiSize(), group)
	for i := 0; i < N; i++ {
		ct := C.Get(i).Exponentiate(xPowers[i])
		cAgg = cAgg.Multiply(ct)
	}

	// Verify multi-exponentiation argument
	return VerifyMultiExponentiationArgument(arg.MultiExp, cPrimeRows, cAgg, arg.CB, pk, ck, group)
}

// shuffleArgumentChallengeX computes the X challenge.
// Java hash order: (p, q, pk, ck, C_vector, C_prime, c_A)
func shuffleArgumentChallengeX(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, C, CPrime *elgamal.CiphertextVector, cA *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		ciphertextVectorToHashable(C),
		ciphertextVectorToHashable(CPrime),
		gqVectorToHashable(cA),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}

// shuffleArgumentChallengeY computes the Y challenge.
// Java hash order: (c_B, p, q, pk, ck, C_vector, C_prime, c_A)
func shuffleArgumentChallengeY(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, C, CPrime *elgamal.CiphertextVector, cA, cB *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		gqVectorToHashable(cB),
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		ciphertextVectorToHashable(C),
		ciphertextVectorToHashable(CPrime),
		gqVectorToHashable(cA),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}

// shuffleArgumentChallengeZ computes the Z challenge.
// Java hash order: ("1", c_B, p, q, pk, ck, C_vector, C_prime, c_A)
func shuffleArgumentChallengeZ(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, C, CPrime *elgamal.CiphertextVector, cA, cB *emath.GqVector) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableString{Value: "1"},
		gqVectorToHashable(cB),
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		ciphertextVectorToHashable(C),
		ciphertextVectorToHashable(CPrime),
		gqVectorToHashable(cA),
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
