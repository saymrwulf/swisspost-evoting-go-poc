package elgamal

import (
	emath "github.com/user/evote/pkg/math"
)

// Ciphertext represents an ElGamal multi-recipient ciphertext.
// Gamma is the shared randomness component g^r.
// Phis are the per-recipient encrypted message components pk_i^r * m_i.
type Ciphertext struct {
	Gamma emath.GqElement
	Phis  *emath.GqVector
}

// NewCiphertext creates a new ciphertext.
func NewCiphertext(gamma emath.GqElement, phis *emath.GqVector) Ciphertext {
	return Ciphertext{Gamma: gamma, Phis: phis}
}

// Size returns the number of phi elements (recipients).
func (c Ciphertext) Size() int {
	return c.Phis.Size()
}

// GetPhi returns the i-th phi element.
func (c Ciphertext) GetPhi(i int) emath.GqElement {
	return c.Phis.Get(i)
}

// Group returns the GqGroup of this ciphertext.
func (c Ciphertext) Group() *emath.GqGroup {
	return c.Gamma.Group()
}

// Multiply returns the component-wise product of two ciphertexts.
// (a.gamma * b.gamma, a.phi_i * b.phi_i)
func (c Ciphertext) Multiply(other Ciphertext) Ciphertext {
	if c.Size() != other.Size() {
		panic("ciphertexts must have the same size")
	}
	return Ciphertext{
		Gamma: c.Gamma.Multiply(other.Gamma),
		Phis:  c.Phis.Multiply(other.Phis),
	}
}

// Exponentiate returns this ciphertext raised to the power e.
// (gamma^e, phi_i^e)
func (c Ciphertext) Exponentiate(e emath.ZqElement) Ciphertext {
	return Ciphertext{
		Gamma: c.Gamma.Exponentiate(e),
		Phis:  c.Phis.ExpScalar(e),
	}
}

// CiphertextVector is a vector of Ciphertexts.
type CiphertextVector struct {
	elements []Ciphertext
	group    *emath.GqGroup
}

// NewCiphertextVector creates a vector of ciphertexts.
func NewCiphertextVector(elements []Ciphertext) *CiphertextVector {
	if len(elements) == 0 {
		return &CiphertextVector{elements: []Ciphertext{}}
	}
	copied := make([]Ciphertext, len(elements))
	copy(copied, elements)
	return &CiphertextVector{elements: copied, group: elements[0].Group()}
}

// CiphertextVectorOf creates a vector from variadic ciphertexts.
func CiphertextVectorOf(cts ...Ciphertext) *CiphertextVector {
	return NewCiphertextVector(cts)
}

// Size returns the number of ciphertexts.
func (v *CiphertextVector) Size() int {
	return len(v.elements)
}

// Get returns the i-th ciphertext.
func (v *CiphertextVector) Get(i int) Ciphertext {
	return v.elements[i]
}

// Group returns the common group.
func (v *CiphertextVector) Group() *emath.GqGroup {
	return v.group
}

// Elements returns a copy of the elements.
func (v *CiphertextVector) Elements() []Ciphertext {
	copied := make([]Ciphertext, len(v.elements))
	copy(copied, v.elements)
	return copied
}

// Append creates a new vector with the ciphertext appended.
func (v *CiphertextVector) Append(ct Ciphertext) *CiphertextVector {
	newElems := make([]Ciphertext, len(v.elements)+1)
	copy(newElems, v.elements)
	newElems[len(v.elements)] = ct
	return NewCiphertextVector(newElems)
}

// PhiSize returns the size of the phi vectors (all must be the same).
func (v *CiphertextVector) PhiSize() int {
	if len(v.elements) == 0 {
		return 0
	}
	return v.elements[0].Size()
}

// Gammas returns a vector of all gamma values.
func (v *CiphertextVector) Gammas() *emath.GqVector {
	elems := make([]emath.GqElement, len(v.elements))
	for i, ct := range v.elements {
		elems[i] = ct.Gamma
	}
	return emath.GqVectorOf(elems...)
}

// GetPhiColumn returns a vector of the j-th phi from each ciphertext.
func (v *CiphertextVector) GetPhiColumn(j int) *emath.GqVector {
	elems := make([]emath.GqElement, len(v.elements))
	for i, ct := range v.elements {
		elems[i] = ct.GetPhi(j)
	}
	return emath.GqVectorOf(elems...)
}
