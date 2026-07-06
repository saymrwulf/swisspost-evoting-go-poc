package math

import (
	"math/big"
	"testing"
)

// TestRandomGqElementIsMember checks that every sampled element is a genuine
// quadratic residue in G_q (regression for the [1,q] square-root range fix).
func TestRandomGqElementIsMember(t *testing.T) {
	group := testGqGroup(t)
	for i := 0; i < 200; i++ {
		e := RandomGqElement(group)
		if !group.IsGroupMember(e.Value()) {
			t.Fatalf("RandomGqElement produced non-member: %v", e.Value())
		}
	}
}

// TestRandomZqElementInRange checks uniform elements stay within [0, q).
func TestRandomZqElementInRange(t *testing.T) {
	group := testGqGroup(t)
	zq := ZqGroupFromGqGroup(group)
	for i := 0; i < 200; i++ {
		v := RandomZqElement(zq).Value()
		if v.Sign() < 0 || v.Cmp(group.Q()) >= 0 {
			t.Fatalf("RandomZqElement out of [0,q): %v", v)
		}
	}
}

// TestGqElementFromSquareRootBoundary verifies the canonical root range is
// [1, q] inclusive — the boundary value q must be accepted (regression for the
// off-by-one that made h+1==q panic in HashAndSquare), while 0 and q+1 are not.
func TestGqElementFromSquareRootBoundary(t *testing.T) {
	group := testGqGroup(t)
	q := group.Q()

	if _, err := GqElementFromSquareRoot(new(big.Int).Set(q), group); err != nil {
		t.Fatalf("root == q must be accepted, got error: %v", err)
	}
	if _, err := GqElementFromSquareRoot(big.NewInt(1), group); err != nil {
		t.Fatalf("root == 1 must be accepted, got error: %v", err)
	}
	if _, err := GqElementFromSquareRoot(big.NewInt(0), group); err == nil {
		t.Fatal("root == 0 must be rejected")
	}
	qPlus1 := new(big.Int).Add(q, big.NewInt(1))
	if _, err := GqElementFromSquareRoot(qPlus1, group); err == nil {
		t.Fatal("root == q+1 must be rejected")
	}
}
