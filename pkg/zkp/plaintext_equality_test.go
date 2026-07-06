package zkp

import (
	"testing"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

func hashStr(s string) hash.HashableString { return hash.HashableString{Value: s} }

// TestPlaintextEqualityProofSound confirms the proof primitive is sound when
// used correctly: it accepts two single-component ciphertexts that encrypt the
// SAME plaintext under different public keys, and rejects when the plaintexts
// differ. (Finding F5 was a caller error in the old vote path, not a defect in
// this primitive — this test pins the correct contract.)
func TestPlaintextEqualityProofSound(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	// Two independent public keys h = g^x1, h' = g^x2.
	h := g.Exponentiate(emath.RandomZqElement(zq))
	hPrime := g.Exponentiate(emath.RandomZqElement(zq))
	pk1 := elgamal.PublicKey{Elements: emath.GqVectorOf(h)}
	pk2 := elgamal.PublicKey{Elements: emath.GqVectorOf(hPrime)}

	m := emath.RandomGqElement(group)
	r0 := emath.RandomZqElement(zq)
	r1 := emath.RandomZqElement(zq)
	c1 := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(m)), r0, pk1)
	c2 := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(m)), r1, pk2)

	proof := GenPlaintextEqualityProof(c1, c2, h, hPrime, r0, r1, group)
	if !VerifyPlaintextEqualityProof(c1, c2, h, hPrime, proof, group) {
		t.Fatal("honest same-plaintext proof rejected")
	}

	// Different plaintext in c2 must fail.
	m2 := m.Multiply(g)
	c2bad := elgamal.Encrypt(elgamal.NewMessage(emath.GqVectorOf(m2)), r1, pk2)
	if VerifyPlaintextEqualityProof(c1, c2bad, h, hPrime, proof, group) {
		t.Fatal("proof verified against a different plaintext")
	}

	// Aux-info binding: mismatched aux must fail.
	p2 := GenPlaintextEqualityProof(c1, c2, h, hPrime, r0, r1, group, hashStr("ctx-A"))
	if VerifyPlaintextEqualityProof(c1, c2, h, hPrime, p2, group, hashStr("ctx-B")) {
		t.Fatal("proof verified under mismatched aux info")
	}
}
