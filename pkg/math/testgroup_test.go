package math

import (
	"math/big"
	"testing"
)

// A fixed 256-bit safe prime group (p = 2q+1, both prime, g=4 a generator of
// G_q) used across math tests so they are fast and deterministic.
const (
	testP = "179688417486862032111147025351064878713905624387098436271724698527496946737299"
	testQ = "89844208743431016055573512675532439356952812193549218135862349263748473368649"
	testG = "4"
)

func testGqGroup(t *testing.T) *GqGroup {
	t.Helper()
	p, _ := new(big.Int).SetString(testP, 10)
	q, _ := new(big.Int).SetString(testQ, 10)
	g, _ := new(big.Int).SetString(testG, 10)
	group, err := NewGqGroup(p, q, g)
	if err != nil {
		t.Fatalf("test group construction failed: %v", err)
	}
	return group
}
