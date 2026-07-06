package mixnet

import (
	"math/big"
	"testing"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
)

const (
	testP = "179688417486862032111147025351064878713905624387098436271724698527496946737299"
	testQ = "89844208743431016055573512675532439356952812193549218135862349263748473368649"
	testG = "4"
)

func testGroup(t *testing.T) *emath.GqGroup {
	t.Helper()
	p, _ := new(big.Int).SetString(testP, 10)
	q, _ := new(big.Int).SetString(testQ, 10)
	g, _ := new(big.Int).SetString(testG, 10)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatalf("test group: %v", err)
	}
	return group
}

func randomCiphertexts(t *testing.T, group *emath.GqGroup, pk elgamal.PublicKey, n, width int) *elgamal.CiphertextVector {
	t.Helper()
	zq := emath.ZqGroupFromGqGroup(group)
	cts := make([]elgamal.Ciphertext, n)
	for i := 0; i < n; i++ {
		elems := make([]emath.GqElement, width)
		for w := 0; w < width; w++ {
			elems[w] = emath.RandomGqElement(group)
		}
		msg := elgamal.NewMessage(emath.GqVectorOf(elems...))
		cts[i] = elgamal.Encrypt(msg, emath.RandomZqElement(zq), pk)
	}
	return elgamal.NewCiphertextVector(cts)
}

// TestShuffleRoundTrip verifies an honest Bayer-Groth shuffle at several sizes,
// including the dimensions that exercise the m=1 SVP path and rectangular N.
func TestShuffleRoundTrip(t *testing.T) {
	group := testGroup(t)
	pk := elgamal.GenKeyPair(group, 1).PK

	for _, N := range []int{2, 3, 4, 6, 9} {
		C := randomCiphertexts(t, group, pk, N, 1)
		vs := GenVerifiableShuffle(C, pk, group)
		if !VerifyShuffle(C, vs, pk, group) {
			t.Fatalf("honest shuffle of N=%d rejected", N)
		}
	}
}

// TestShuffleTamperedOutputRejected confirms the verifier rejects a shuffle
// whose claimed output was altered (soundness smoke test).
func TestShuffleTamperedOutputRejected(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	pk := elgamal.GenKeyPair(group, 1).PK

	C := randomCiphertexts(t, group, pk, 4, 1)
	vs := GenVerifiableShuffle(C, pk, group)

	// Replace one output ciphertext with a fresh encryption not in the input.
	extra := elgamal.Encrypt(
		elgamal.NewMessage(emath.GqVectorOf(emath.RandomGqElement(group))),
		emath.RandomZqElement(zq), pk)
	orig := vs.ShuffledCiphertexts
	tampered := make([]elgamal.Ciphertext, orig.Size())
	for i := 0; i < orig.Size(); i++ {
		tampered[i] = orig.Get(i)
	}
	tampered[0] = extra
	vs.ShuffledCiphertexts = elgamal.NewCiphertextVector(tampered)

	if VerifyShuffle(C, vs, pk, group) {
		t.Fatal("verifier accepted a tampered shuffle output")
	}
}
