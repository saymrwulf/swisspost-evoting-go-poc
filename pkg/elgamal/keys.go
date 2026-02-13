package elgamal

import (
	emath "github.com/user/evote/pkg/math"
)

// PrivateKey is a vector of Z_q elements.
type PrivateKey struct {
	Elements *emath.ZqVector
}

// PublicKey is a vector of G_q elements.
type PublicKey struct {
	Elements *emath.GqVector
}

// KeyPair holds a matching private and public key.
type KeyPair struct {
	SK PrivateKey
	PK PublicKey
}

// GenKeyPair generates an ElGamal key pair with l elements.
// sk = [x_0, ..., x_{l-1}] random in Z_q
// pk = [g^x_0, ..., g^x_{l-1}]
func GenKeyPair(group *emath.GqGroup, l int) KeyPair {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	skElements := emath.RandomZqVector(l, zqGroup)

	g := group.Generator()
	pkElems := make([]emath.GqElement, l)
	for i := 0; i < l; i++ {
		pkElems[i] = g.Exponentiate(skElements.Get(i))
	}

	return KeyPair{
		SK: PrivateKey{Elements: skElements},
		PK: PublicKey{Elements: emath.GqVectorOf(pkElems...)},
	}
}

// CombinePublicKeys computes the element-wise product of multiple public keys.
func CombinePublicKeys(keys ...PublicKey) PublicKey {
	if len(keys) == 0 {
		panic("must provide at least one key")
	}
	result := keys[0].Elements
	for i := 1; i < len(keys); i++ {
		result = result.Multiply(keys[i].Elements)
	}
	return PublicKey{Elements: result}
}

// Size returns the number of key elements.
func (pk PublicKey) Size() int {
	return pk.Elements.Size()
}

// Get returns the i-th element of the public key.
func (pk PublicKey) Get(i int) emath.GqElement {
	return pk.Elements.Get(i)
}

// Size returns the number of key elements.
func (sk PrivateKey) Size() int {
	return sk.Elements.Size()
}

// Get returns the i-th element of the private key.
func (sk PrivateKey) Get(i int) emath.ZqElement {
	return sk.Elements.Get(i)
}

// Group returns the GqGroup associated with this public key.
func (pk PublicKey) Group() *emath.GqGroup {
	return pk.Elements.Group()
}
