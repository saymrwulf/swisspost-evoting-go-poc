package mixnet

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
)

func TestMultiExponentiationArgument(t *testing.T) {
	q := testSafePrimeQ(256)
	p := new(big.Int).Mul(big.NewInt(2), q)
	p.Add(p, big.NewInt(1))
	g := big.NewInt(4)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatal(err)
	}
	zqGroup := emath.ZqGroupFromGqGroup(group)

	l := 2
	pk := elgamal.GenKeyPair(group, l).PK
	n := 3
	m := 1

	ck := GenCommitmentKey(n, group)

	cMatrix := make([]*elgamal.CiphertextVector, m)
	for i := 0; i < m; i++ {
		cts := make([]elgamal.Ciphertext, n)
		for j := 0; j < n; j++ {
			r := emath.RandomZqElement(zqGroup)
			cts[j] = elgamal.EncryptOnes(r, pk)
		}
		cMatrix[i] = elgamal.NewCiphertextVector(cts)
	}

	aCols := make([]*emath.ZqVector, m)
	for j := 0; j < m; j++ {
		aCols[j] = emath.RandomZqVector(n, zqGroup)
	}
	A := emath.ZqMatrixFromColumns(aCols)
	r := emath.RandomZqVector(m, zqGroup)
	cA := ck.CommitMatrix(A, r)

	// Target = Enc(1; rho) * Π multiExp(cMatrix[i], A[:,i])
	rhoVal := emath.RandomZqElement(zqGroup)
	cTarget := identityCiphertext(l, group)
	for i := 0; i < m; i++ {
		ct := multiExpCiphertextRow(cMatrix[i], A.GetColumn(i))
		cTarget = cTarget.Multiply(ct)
	}
	encRho := elgamal.EncryptOnes(rhoVal, pk)
	cTarget = cTarget.Multiply(encRho)

	arg := GenMultiExponentiationArgument(cMatrix, cTarget, cA, A, r, rhoVal, pk, ck, group)

	ok := VerifyMultiExponentiationArgument(arg, cMatrix, cTarget, cA, pk, ck, group)
	if !ok {
		t.Fatal("MultiExponentiationArgument verification failed")
	}
	t.Log("MultiExponentiationArgument verification PASSED!")
}

func TestMultiExpLargerMatrix(t *testing.T) {
	q := testSafePrimeQ(256)
	p := new(big.Int).Mul(big.NewInt(2), q)
	p.Add(p, big.NewInt(1))
	g := big.NewInt(4)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatal(err)
	}
	zqGroup := emath.ZqGroupFromGqGroup(group)

	l := 2
	pk := elgamal.GenKeyPair(group, l).PK
	n := 2
	m := 2

	ck := GenCommitmentKey(n, group)

	cMatrix := make([]*elgamal.CiphertextVector, m)
	for i := 0; i < m; i++ {
		cts := make([]elgamal.Ciphertext, n)
		for j := 0; j < n; j++ {
			r := emath.RandomZqElement(zqGroup)
			cts[j] = elgamal.EncryptOnes(r, pk)
		}
		cMatrix[i] = elgamal.NewCiphertextVector(cts)
	}

	aCols := make([]*emath.ZqVector, m)
	for j := 0; j < m; j++ {
		aCols[j] = emath.RandomZqVector(n, zqGroup)
	}
	A := emath.ZqMatrixFromColumns(aCols)
	r := emath.RandomZqVector(m, zqGroup)
	cA := ck.CommitMatrix(A, r)

	rhoVal := emath.RandomZqElement(zqGroup)
	cTarget := identityCiphertext(l, group)
	for i := 0; i < m; i++ {
		ct := multiExpCiphertextRow(cMatrix[i], A.GetColumn(i))
		cTarget = cTarget.Multiply(ct)
	}
	encRho := elgamal.EncryptOnes(rhoVal, pk)
	cTarget = cTarget.Multiply(encRho)

	arg := GenMultiExponentiationArgument(cMatrix, cTarget, cA, A, r, rhoVal, pk, ck, group)

	ok := VerifyMultiExponentiationArgument(arg, cMatrix, cTarget, cA, pk, ck, group)
	if !ok {
		t.Fatal("MultiExponentiationArgument (2x2) verification failed")
	}
	t.Log("MultiExponentiationArgument (2x2) verification PASSED!")
}

func testSafePrimeQ(bits int) *big.Int {
	for {
		q, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		p := new(big.Int).Mul(big.NewInt(2), q)
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(64) {
			return q
		}
	}
}
