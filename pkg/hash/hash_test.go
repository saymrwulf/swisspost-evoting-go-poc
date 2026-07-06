package hash

import (
	"bytes"
	"math/big"
	"testing"
)

func TestRecursiveHashDeterministic(t *testing.T) {
	a := RecursiveHash(HashableString{Value: "x"}, HashableBigInt{Value: big.NewInt(42)})
	b := RecursiveHash(HashableString{Value: "x"}, HashableBigInt{Value: big.NewInt(42)})
	if !bytes.Equal(a, b) {
		t.Fatal("RecursiveHash is not deterministic")
	}
	c := RecursiveHash(HashableString{Value: "y"}, HashableBigInt{Value: big.NewInt(42)})
	if bytes.Equal(a, c) {
		t.Fatal("distinct inputs produced identical hash")
	}
}

// TestRecursiveHashListInjective guards the injective list-encoding property:
// nesting must matter, so (["a","b"]) and (["ab"]) must differ.
func TestRecursiveHashListInjective(t *testing.T) {
	ab := RecursiveHash(HashableList{Elements: []Hashable{
		HashableString{Value: "a"}, HashableString{Value: "b"},
	}})
	joined := RecursiveHash(HashableList{Elements: []Hashable{
		HashableString{Value: "ab"},
	}})
	if bytes.Equal(ab, joined) {
		t.Fatal("list encoding is not injective")
	}
}

// TestRecursiveHashToZqRange checks the challenge derivation used by every ZK
// proof after the M1 fix: output must be a uniform-ish element of [0, q).
func TestRecursiveHashToZqRange(t *testing.T) {
	q, _ := new(big.Int).SetString("89844208743431016055573512675532439356952812193549218135862349263748473368649", 10)
	for i := 0; i < 100; i++ {
		v := RecursiveHashToZq(q,
			HashableString{Value: "challenge"},
			HashableBigInt{Value: big.NewInt(int64(i))})
		if v.Sign() < 0 || v.Cmp(q) >= 0 {
			t.Fatalf("RecursiveHashToZq out of [0,q): %v", v)
		}
	}
}
