package math

import (
	"fmt"
	"math/big"
)

// GqElement represents an element of the quadratic residue group G_q.
// Immutable: all operations return new instances.
type GqElement struct {
	value *big.Int
	group *GqGroup
}

// NewGqElement creates a GqElement from a value, validating group membership.
func NewGqElement(value *big.Int, group *GqGroup) (GqElement, error) {
	if value == nil || group == nil {
		return GqElement{}, fmt.Errorf("value and group must not be nil")
	}
	if !group.IsGroupMember(value) {
		return GqElement{}, fmt.Errorf("value %v is not a member of the group", value)
	}
	return GqElement{value: new(big.Int).Set(value), group: group}, nil
}

// GqElementFromSquareRoot creates a GqElement by squaring a value, guaranteeing group membership.
// The input element must be in [1, q).
func GqElementFromSquareRoot(element *big.Int, group *GqGroup) (GqElement, error) {
	if element == nil || group == nil {
		return GqElement{}, fmt.Errorf("element and group must not be nil")
	}
	if element.Sign() < 1 || element.Cmp(group.q) >= 0 {
		return GqElement{}, fmt.Errorf("element must be in [1, q)")
	}
	// element^2 mod p is guaranteed to be a quadratic residue
	squared := new(big.Int).Exp(element, big.NewInt(2), group.p)
	return GqElement{value: squared, group: group}, nil
}

// gqElementUnchecked creates a GqElement without validation.
// Only use when the value is mathematically guaranteed to be in the group.
func gqElementUnchecked(value *big.Int, group *GqGroup) GqElement {
	return GqElement{value: new(big.Int).Set(value), group: group}
}

// Value returns the element's value as a new big.Int.
func (e GqElement) Value() *big.Int {
	return new(big.Int).Set(e.value)
}

// Group returns the element's group.
func (e GqElement) Group() *GqGroup {
	return e.group
}

// Multiply returns (this * other) mod p.
func (e GqElement) Multiply(other GqElement) GqElement {
	e.checkSameGroup(other)
	result := new(big.Int).Mul(e.value, other.value)
	result.Mod(result, e.group.p)
	return GqElement{value: result, group: e.group}
}

// Exponentiate returns this^exponent mod p.
func (e GqElement) Exponentiate(exponent ZqElement) GqElement {
	result := new(big.Int).Exp(e.value, exponent.value, e.group.p)
	return GqElement{value: result, group: e.group}
}

// ExpBigInt returns this^exponent mod p where exponent is a raw big.Int.
func (e GqElement) ExpBigInt(exponent *big.Int) GqElement {
	result := new(big.Int).Exp(e.value, exponent, e.group.p)
	return GqElement{value: result, group: e.group}
}

// Invert returns this^(-1) mod p.
func (e GqElement) Invert() GqElement {
	result := new(big.Int).ModInverse(e.value, e.group.p)
	return GqElement{value: result, group: e.group}
}

// Divide returns this / divisor = this * divisor^(-1) mod p.
func (e GqElement) Divide(divisor GqElement) GqElement {
	e.checkSameGroup(divisor)
	inv := divisor.Invert()
	return e.Multiply(inv)
}

// Equals checks if two elements have the same value and group.
func (e GqElement) Equals(other GqElement) bool {
	return e.value.Cmp(other.value) == 0 && e.group.Equals(other.group)
}

// IsIdentity checks if this element is the group identity (1).
func (e GqElement) IsIdentity() bool {
	return e.value.Cmp(big.NewInt(1)) == 0
}

// MultiModExp computes Π(bases[i]^exponents[i]) mod p.
func MultiModExp(bases []GqElement, exponents []ZqElement) GqElement {
	if len(bases) == 0 {
		panic("bases must not be empty")
	}
	if len(bases) != len(exponents) {
		panic("bases and exponents must have the same length")
	}
	group := bases[0].group
	result := new(big.Int).Set(big.NewInt(1))
	for i := range bases {
		term := new(big.Int).Exp(bases[i].value, exponents[i].value, group.p)
		result.Mul(result, term)
		result.Mod(result, group.p)
	}
	return GqElement{value: result, group: group}
}

func (e GqElement) checkSameGroup(other GqElement) {
	if !e.group.Equals(other.group) {
		panic(fmt.Sprintf("elements must be from the same group"))
	}
}

// String returns the string representation of the element value.
func (e GqElement) String() string {
	return e.value.String()
}
