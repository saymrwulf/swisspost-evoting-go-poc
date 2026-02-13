package elgamal

import (
	emath "github.com/user/evote/pkg/math"
)

// CiphertextProduct computes the component-wise product of a vector of ciphertexts.
// Returns a single ciphertext: (Π gamma_i, Π phi_i,j for each j)
func CiphertextProduct(cts *CiphertextVector) Ciphertext {
	if cts.Size() == 0 {
		panic("cannot compute product of empty vector")
	}
	result := cts.Get(0)
	for i := 1; i < cts.Size(); i++ {
		result = result.Multiply(cts.Get(i))
	}
	return result
}

// CiphertextVectorExponentiate exponentiates each ciphertext by the corresponding exponent.
func CiphertextVectorExponentiate(cts *CiphertextVector, exps *emath.ZqVector) *CiphertextVector {
	if cts.Size() != exps.Size() {
		panic("vectors must have same size")
	}
	result := make([]Ciphertext, cts.Size())
	for i := 0; i < cts.Size(); i++ {
		result[i] = cts.Get(i).Exponentiate(exps.Get(i))
	}
	return NewCiphertextVector(result)
}

// CiphertextVectorMultiply multiplies two ciphertext vectors element-wise.
func CiphertextVectorMultiply(a, b *CiphertextVector) *CiphertextVector {
	if a.Size() != b.Size() {
		panic("vectors must have same size")
	}
	result := make([]Ciphertext, a.Size())
	for i := 0; i < a.Size(); i++ {
		result[i] = a.Get(i).Multiply(b.Get(i))
	}
	return NewCiphertextVector(result)
}

// ReEncrypt re-encrypts a ciphertext with fresh randomness.
// C' = C * Enc(1^l, r', pk) = (gamma * g^r', phi_i * pk_i^r')
func ReEncrypt(ct Ciphertext, rPrime emath.ZqElement, pk PublicKey) Ciphertext {
	enc := EncryptOnes(rPrime, pk)
	return ct.Multiply(enc)
}

// MultiExponentiation computes the multi-exponentiation of ciphertexts.
// Returns Π C_i^e_i = (Π gamma_i^e_i, Π phi_i,j^e_i for each j)
func MultiExponentiation(cts *CiphertextVector, exps *emath.ZqVector) Ciphertext {
	if cts.Size() != exps.Size() {
		panic("vectors must have same size")
	}
	if cts.Size() == 0 {
		panic("vectors must not be empty")
	}
	result := cts.Get(0).Exponentiate(exps.Get(0))
	for i := 1; i < cts.Size(); i++ {
		result = result.Multiply(cts.Get(i).Exponentiate(exps.Get(i)))
	}
	return result
}
