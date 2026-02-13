package math

import (
	"fmt"
	"math/big"
)

// ZqElement represents an element of the group Z_q.
// Immutable: all operations return new instances.
type ZqElement struct {
	value *big.Int
	group *ZqGroup
}

// NewZqElement creates a ZqElement from a value, validating group membership.
func NewZqElement(value *big.Int, group *ZqGroup) (ZqElement, error) {
	if value == nil || group == nil {
		return ZqElement{}, fmt.Errorf("value and group must not be nil")
	}
	if !group.IsGroupMember(value) {
		return ZqElement{}, fmt.Errorf("value %v is not a member of Z_q (q=%v)", value, group.q)
	}
	return ZqElement{value: new(big.Int).Set(value), group: group}, nil
}

// NewZqElementFromInt creates a ZqElement from an int.
func NewZqElementFromInt(value int, group *ZqGroup) (ZqElement, error) {
	return NewZqElement(big.NewInt(int64(value)), group)
}

// zqElementUnchecked creates a ZqElement without validation.
func zqElementUnchecked(value *big.Int, group *ZqGroup) ZqElement {
	return ZqElement{value: new(big.Int).Set(value), group: group}
}

// Value returns the element's value as a new big.Int.
func (e ZqElement) Value() *big.Int {
	return new(big.Int).Set(e.value)
}

// Group returns the element's group.
func (e ZqElement) Group() *ZqGroup {
	return e.group
}

// Add returns (this + other) mod q.
func (e ZqElement) Add(other ZqElement) ZqElement {
	e.checkSameGroup(other)
	result := new(big.Int).Add(e.value, other.value)
	result.Mod(result, e.group.q)
	return ZqElement{value: result, group: e.group}
}

// Subtract returns (this - other) mod q.
func (e ZqElement) Subtract(other ZqElement) ZqElement {
	e.checkSameGroup(other)
	result := new(big.Int).Sub(e.value, other.value)
	result.Mod(result, e.group.q)
	return ZqElement{value: result, group: e.group}
}

// Multiply returns (this * other) mod q.
func (e ZqElement) Multiply(other ZqElement) ZqElement {
	e.checkSameGroup(other)
	result := new(big.Int).Mul(e.value, other.value)
	result.Mod(result, e.group.q)
	return ZqElement{value: result, group: e.group}
}

// Exponentiate returns this^exponent mod q.
func (e ZqElement) Exponentiate(exponent *big.Int) ZqElement {
	if exponent.Sign() < 0 {
		panic("exponent must be non-negative")
	}
	result := new(big.Int).Exp(e.value, exponent, e.group.q)
	return ZqElement{value: result, group: e.group}
}

// Negate returns (-this) mod q.
func (e ZqElement) Negate() ZqElement {
	if e.value.Sign() == 0 {
		return ZqElement{value: big.NewInt(0), group: e.group}
	}
	result := new(big.Int).Sub(e.group.q, e.value)
	return ZqElement{value: result, group: e.group}
}

// Invert returns this^(-1) mod q.
func (e ZqElement) Invert() ZqElement {
	if e.value.Sign() == 0 {
		panic("cannot invert zero element")
	}
	result := new(big.Int).ModInverse(e.value, e.group.q)
	return ZqElement{value: result, group: e.group}
}

// IsZero checks if this element is zero.
func (e ZqElement) IsZero() bool {
	return e.value.Sign() == 0
}

// Equals checks if two elements have the same value and group.
func (e ZqElement) Equals(other ZqElement) bool {
	return e.value.Cmp(other.value) == 0 && e.group.Equals(other.group)
}

func (e ZqElement) checkSameGroup(other ZqElement) {
	if !e.group.Equals(other.group) {
		panic(fmt.Sprintf("elements must be from the same group"))
	}
}

// String returns the string representation.
func (e ZqElement) String() string {
	return e.value.String()
}
