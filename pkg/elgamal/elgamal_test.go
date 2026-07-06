package elgamal

import (
	"math/big"
	"testing"

	emath "github.com/user/evote/pkg/math"
)

const (
	testP = "179688417486862032111147025351064878713905624387098436271724698527496946737299"
	testQ = "89844208743431016055573512675532439356952812193549218135862349263748473368649"
	testG = "4"
)

func testGroup(t *testing.T) *emath.GqGroup {
	t.Helper()
	p, _ := new(big.Int).SetString(testP, 10)
	q, _ := new(big.Int).SetString(testQ, 10)
	g, _ := new(big.Int).SetString(testG, 10)
	group, err := emath.NewGqGroup(p, q, g)
	if err != nil {
		t.Fatalf("test group: %v", err)
	}
	return group
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	kp := GenKeyPair(group, 3)

	plain := NewMessage(emath.GqVectorOf(
		emath.RandomGqElement(group),
		emath.RandomGqElement(group),
		emath.RandomGqElement(group),
	))
	ct := Encrypt(plain, emath.RandomZqElement(zq), kp.PK)
	got := Decrypt(ct, kp.SK)

	for i := 0; i < plain.Size(); i++ {
		if !got.Get(i).Equals(plain.Get(i)) {
			t.Fatalf("round-trip mismatch at %d", i)
		}
	}
}

// TestHomomorphicMultiplication checks Enc(m1)*Enc(m2) decrypts to m1*m2 —
// the property the mix-net and return-code computations rely on.
func TestHomomorphicMultiplication(t *testing.T) {
	group := testGroup(t)
	zq := emath.ZqGroupFromGqGroup(group)
	kp := GenKeyPair(group, 1)

	m1 := emath.RandomGqElement(group)
	m2 := emath.RandomGqElement(group)
	ct1 := Encrypt(NewMessage(emath.GqVectorOf(m1)), emath.RandomZqElement(zq), kp.PK)
	ct2 := Encrypt(NewMessage(emath.GqVectorOf(m2)), emath.RandomZqElement(zq), kp.PK)

	product := ct1.Multiply(ct2)
	got := Decrypt(product, kp.SK).Get(0)
	want := m1.Multiply(m2)
	if !got.Equals(want) {
		t.Fatal("homomorphic product decrypts incorrectly")
	}
}
