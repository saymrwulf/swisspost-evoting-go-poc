package zkp

import (
	emath "github.com/user/evote/pkg/math"
)

// SchnorrProof is a proof of knowledge of discrete logarithm.
// Proves knowledge of x such that y = g^x.
type SchnorrProof struct {
	E emath.ZqElement // Hash challenge
	Z emath.ZqElement // Response
}

// ExponentiationProof proves that multiple values are exponentiations
// of bases by the same exponent.
type ExponentiationProof struct {
	E emath.ZqElement // Hash challenge
	Z emath.ZqElement // Response
}

// PlaintextEqualityProof proves two ciphertexts encrypt the same plaintext
// under different keys.
type PlaintextEqualityProof struct {
	E emath.ZqElement // Hash challenge
	Z *emath.ZqVector // Response vector (size 2)
}

// DecryptionProof proves correct decryption of an ElGamal ciphertext.
type DecryptionProof struct {
	E emath.ZqElement // Hash challenge
	Z *emath.ZqVector // Response vector (size l)
}

// VerifiableDecryptions holds a set of decrypted messages with proofs.
type VerifiableDecryptions struct {
	Messages []emath.GqElement
	Proofs   []DecryptionProof
}
