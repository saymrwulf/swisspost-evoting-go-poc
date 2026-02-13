package math

import (
	"fmt"
	"math/big"
)

// ZqGroup represents the group of integers modulo q.
type ZqGroup struct {
	q        *big.Int
	identity ZqElement
}

// NewZqGroup creates a new ZqGroup with the given order q.
func NewZqGroup(q *big.Int) (*ZqGroup, error) {
	if q == nil {
		return nil, fmt.Errorf("q must not be nil")
	}
	if q.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("q must be >= 2")
	}
	group := &ZqGroup{
		q: new(big.Int).Set(q),
	}
	group.identity = ZqElement{value: big.NewInt(0), group: group}
	return group, nil
}

// ZqGroupFromGqGroup creates a ZqGroup with the same order as the given GqGroup.
func ZqGroupFromGqGroup(gqGroup *GqGroup) *ZqGroup {
	group := &ZqGroup{
		q: new(big.Int).Set(gqGroup.q),
	}
	group.identity = ZqElement{value: big.NewInt(0), group: group}
	return group
}

// Q returns the group order q.
func (g *ZqGroup) Q() *big.Int {
	return new(big.Int).Set(g.q)
}

// Identity returns the identity element (0).
func (g *ZqGroup) Identity() ZqElement {
	return g.identity
}

// IsGroupMember checks if value is in Z_q: value >= 0 AND value < q.
func (g *ZqGroup) IsGroupMember(value *big.Int) bool {
	if value == nil {
		return false
	}
	return value.Sign() >= 0 && value.Cmp(g.q) < 0
}

// Equals checks if two groups have the same order.
func (g *ZqGroup) Equals(other *ZqGroup) bool {
	if other == nil {
		return false
	}
	return g.q.Cmp(other.q) == 0
}

// String returns a string representation.
func (g *ZqGroup) String() string {
	return fmt.Sprintf("ZqGroup(q=%v)", g.q)
}
