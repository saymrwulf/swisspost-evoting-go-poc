package elgamal

import (
	emath "github.com/user/evote/pkg/math"
)

// Encrypt computes the ElGamal encryption of a message.
// gamma = g^r
// phi_i = pk_i^r * m_i
func Encrypt(msg Message, r emath.ZqElement, pk PublicKey) Ciphertext {
	if msg.Size() != pk.Size() {
		panic("message size must match public key size")
	}

	group := pk.Group()
	g := group.Generator()

	// gamma = g^r
	gamma := g.Exponentiate(r)

	// phi_i = pk_i^r * m_i
	phis := make([]emath.GqElement, msg.Size())
	for i := 0; i < msg.Size(); i++ {
		pkR := pk.Get(i).Exponentiate(r)
		phis[i] = pkR.Multiply(msg.Get(i))
	}

	return Ciphertext{
		Gamma: gamma,
		Phis:  emath.GqVectorOf(phis...),
	}
}

// EncryptOnes encrypts an all-ones message (used for trivial ciphertexts).
// gamma = g^r, phi_i = pk_i^r
func EncryptOnes(r emath.ZqElement, pk PublicKey) Ciphertext {
	group := pk.Group()
	g := group.Generator()
	gamma := g.Exponentiate(r)

	phis := make([]emath.GqElement, pk.Size())
	for i := 0; i < pk.Size(); i++ {
		phis[i] = pk.Get(i).Exponentiate(r)
	}

	return Ciphertext{
		Gamma: gamma,
		Phis:  emath.GqVectorOf(phis...),
	}
}
