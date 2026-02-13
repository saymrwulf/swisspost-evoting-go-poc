package elgamal

import (
	emath "github.com/user/evote/pkg/math"
)

// Decrypt computes the ElGamal decryption of a ciphertext.
// m_i = phi_i / gamma^sk_i = phi_i * gamma^(-sk_i)
func Decrypt(ct Ciphertext, sk PrivateKey) Message {
	if ct.Size() != sk.Size() {
		panic("ciphertext size must match secret key size")
	}

	elems := make([]emath.GqElement, ct.Size())
	for i := 0; i < ct.Size(); i++ {
		// gamma^sk_i
		gammaSk := ct.Gamma.Exponentiate(sk.Get(i))
		// m_i = phi_i / gamma^sk_i
		elems[i] = ct.GetPhi(i).Divide(gammaSk)
	}

	return Message{Elements: emath.GqVectorOf(elems...)}
}

// PartialDecrypt computes partial decryption using one key share.
// For each phi: phi_i' = phi_i / gamma^sk_i
// The gamma is left unchanged for further partial decryptions.
func PartialDecrypt(ct Ciphertext, sk PrivateKey) Ciphertext {
	if ct.Size() != sk.Size() {
		panic("ciphertext size must match secret key size")
	}

	phis := make([]emath.GqElement, ct.Size())
	for i := 0; i < ct.Size(); i++ {
		gammaSk := ct.Gamma.Exponentiate(sk.Get(i))
		phis[i] = ct.GetPhi(i).Divide(gammaSk)
	}

	return Ciphertext{
		Gamma: ct.Gamma,
		Phis:  emath.GqVectorOf(phis...),
	}
}

// ExtractMessage extracts the plaintext from a fully decrypted ciphertext.
// After all partial decryptions, the phis contain the plaintext directly.
func ExtractMessage(ct Ciphertext) Message {
	return Message{Elements: ct.Phis}
}
