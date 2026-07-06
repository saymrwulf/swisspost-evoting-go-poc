package zkp

import (
	"math/big"
	"testing"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
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

func TestSchnorrRoundTrip(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	x := emath.RandomZqElement(zq)
	y := g.Exponentiate(x)

	proof := GenSchnorrProof(x, y, group)
	if !VerifySchnorrProof(proof, y, group) {
		t.Fatal("honest Schnorr proof rejected")
	}
	// Wrong statement must be rejected.
	yBad := y.Multiply(g)
	if VerifySchnorrProof(proof, yBad, group) {
		t.Fatal("Schnorr proof accepted against wrong statement")
	}
	// Aux-info mismatch must be rejected (domain separation).
	proofAux := GenSchnorrProof(x, y, group, hash.HashableString{Value: "ctx-A"})
	if VerifySchnorrProof(proofAux, y, group, hash.HashableString{Value: "ctx-B"}) {
		t.Fatal("Schnorr proof accepted with mismatched aux info")
	}
	if !VerifySchnorrProof(proofAux, y, group, hash.HashableString{Value: "ctx-A"}) {
		t.Fatal("Schnorr proof with matching aux info rejected")
	}
}

// TestSchnorrChallengeInRange locks in the M1 fix: the Fiat-Shamir challenge is
// a uniform Z_q element via RecursiveHashToZq, so it must be < q.
func TestSchnorrChallengeInRange(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()
	for i := 0; i < 50; i++ {
		x := emath.RandomZqElement(zq)
		proof := GenSchnorrProof(x, g.Exponentiate(x), group)
		if proof.E.Value().Cmp(group.Q()) >= 0 {
			t.Fatalf("challenge not reduced mod q: %v", proof.E.Value())
		}
	}
}

func TestExponentiationRoundTrip(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)

	basesElems := []emath.GqElement{group.Generator(), emath.RandomGqElement(group), emath.RandomGqElement(group)}
	bases := emath.GqVectorOf(basesElems...)
	x := emath.RandomZqElement(zq)
	expElems := make([]emath.GqElement, len(basesElems))
	for i, b := range basesElems {
		expElems[i] = b.Exponentiate(x)
	}
	exps := emath.GqVectorOf(expElems...)

	proof := GenExponentiationProof(bases, x, exps, group)
	if !VerifyExponentiationProof(bases, exps, proof, group) {
		t.Fatal("honest exponentiation proof rejected")
	}
	// Tamper one exponentiation.
	expElems[0] = expElems[0].Multiply(group.Generator())
	if VerifyExponentiationProof(bases, emath.GqVectorOf(expElems...), proof, group) {
		t.Fatal("exponentiation proof accepted against tampered statement")
	}
}

func TestDecryptionProofRoundTrip(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)

	kp := elgamal.GenKeyPair(group, 2)
	msg := elgamal.NewMessage(emath.GqVectorOf(emath.RandomGqElement(group), emath.RandomGqElement(group)))
	r := emath.RandomZqElement(zq)
	ct := elgamal.Encrypt(msg, r, kp.PK)
	decrypted := elgamal.Decrypt(ct, kp.SK)

	proof := GenDecryptionProof(ct, kp.SK, kp.PK, decrypted, group)
	if !VerifyDecryptionProof(ct, kp.PK, decrypted, proof, group) {
		t.Fatal("honest decryption proof rejected")
	}
	// Claim a wrong plaintext.
	wrong := elgamal.NewMessage(emath.GqVectorOf(decrypted.Get(0).Multiply(group.Generator()), decrypted.Get(1)))
	if VerifyDecryptionProof(ct, kp.PK, wrong, proof, group) {
		t.Fatal("decryption proof accepted for wrong plaintext")
	}
}
