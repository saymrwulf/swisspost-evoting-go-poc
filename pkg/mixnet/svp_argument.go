package mixnet

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// SingleValueProductArgument proves that the product of committed vector elements equals b.
type SingleValueProductArgument struct {
	CD        emath.GqElement // Commitment to d
	CDelta    emath.GqElement // Commitment to delta'
	CCapDelta emath.GqElement // Commitment to Δ
	ATilde    *emath.ZqVector // Aggregated a
	BTilde    *emath.ZqVector // Aggregated partial products
	RTilde    emath.ZqElement // Aggregated randomness
	STilde    emath.ZqElement // Aggregated randomness
}

// GenSingleValueProductArgument generates an SVP argument.
func GenSingleValueProductArgument(
	ca emath.GqElement, // Commitment to a
	b emath.ZqElement, // Product b = Π a_i
	a *emath.ZqVector, // Vector a
	r emath.ZqElement, // Randomness for ca
	pk elgamal.PublicKey, // Public key (needed for Fiat-Shamir hash)
	ck CommitmentKey,
	group *emath.GqGroup,
) SingleValueProductArgument {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	n := a.Size()
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)

	emitArgument("svp",
		"Single-value product argument: prove the product of a committed vector equals b",
		`\text{SingleValueProductArgument}:\ \prod_{i=1}^{n} a_i = b, \quad c_a = \mathrm{Comm}(a; r)`,
		"SingleValueProductArgument: Π_i a_i = b   for committed vector a",
		map[string]string{"n": fmt.Sprintf("%d", n), "b": b.Value().String()})

	// 1. Compute partial products b_k = Π_{i=0}^k a_i
	bPartial := make([]emath.ZqElement, n)
	bPartial[0] = a.Get(0)
	for k := 1; k < n; k++ {
		bPartial[k] = bPartial[k-1].Multiply(a.Get(k))
	}

	// 2. Generate random d vector
	d := emath.RandomZqVector(n, zqGroup)
	rd := emath.RandomZqElement(zqGroup)

	// 3. Compute delta: delta[0] = d[0], delta[n-1] = 0, rest random
	deltaElems := make([]emath.ZqElement, n)
	deltaElems[0] = d.Get(0)
	for k := 1; k < n-1; k++ {
		deltaElems[k] = emath.RandomZqElement(zqGroup)
	}
	deltaElems[n-1] = zero
	delta := emath.ZqVectorOf(deltaElems...)

	// 4. Compute delta' and Δ
	deltaPrimeElems := make([]emath.ZqElement, n)
	for k := 0; k < n-1; k++ {
		deltaPrimeElems[k] = delta.Get(k).Negate().Multiply(d.Get(k + 1))
	}
	deltaPrimeElems[n-1] = zero

	capDeltaElems := make([]emath.ZqElement, n)
	for k := 0; k < n-1; k++ {
		capDeltaElems[k] = delta.Get(k + 1).Subtract(a.Get(k + 1).Multiply(delta.Get(k))).Subtract(bPartial[k].Multiply(d.Get(k + 1)))
	}
	capDeltaElems[n-1] = zero

	// 5. Compute commitments
	s0 := emath.RandomZqElement(zqGroup)
	sx := emath.RandomZqElement(zqGroup)

	deltaPrime := emath.ZqVectorOf(deltaPrimeElems...)
	capDelta := emath.ZqVectorOf(capDeltaElems...)

	cd := ck.Commit(d, rd)
	cDelta := ck.Commit(deltaPrime, s0)
	cCapDelta := ck.Commit(capDelta, sx)

	// 6. Fiat-Shamir challenge x
	// Java hash order: (p, q, pk, ck, c_Delta, c_delta, c_d, b, c_a)
	x := svpChallenge(group, pk, &ck, cCapDelta, cDelta, cd, b, ca)

	// 7. Compute proof elements
	aTilde := make([]emath.ZqElement, n)
	for k := 0; k < n; k++ {
		aTilde[k] = x.Multiply(a.Get(k)).Add(d.Get(k))
	}

	bTilde := make([]emath.ZqElement, n)
	for k := 0; k < n; k++ {
		bTilde[k] = x.Multiply(bPartial[k]).Add(delta.Get(k))
	}

	rTilde := x.Multiply(r).Add(rd)
	sTilde := x.Multiply(sx).Add(s0)

	return SingleValueProductArgument{
		CD:        cd,
		CDelta:    cDelta,
		CCapDelta: cCapDelta,
		ATilde:    emath.ZqVectorOf(aTilde...),
		BTilde:    emath.ZqVectorOf(bTilde...),
		RTilde:    rTilde,
		STilde:    sTilde,
	}
}

// VerifySingleValueProductArgument verifies an SVP argument.
func VerifySingleValueProductArgument(
	arg SingleValueProductArgument,
	ca emath.GqElement,
	b emath.ZqElement,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	n := arg.ATilde.Size()

	// Reconstruct x
	x := svpChallenge(group, pk, &ck, arg.CCapDelta, arg.CDelta, arg.CD, b, ca)

	// Check 1: ca^x * c_d = commit(a_tilde, r_tilde)
	lhs1 := ca.Exponentiate(x).Multiply(arg.CD)
	rhs1 := ck.Commit(arg.ATilde, arg.RTilde)
	if !lhs1.Equals(rhs1) {
		return false
	}

	// Check 2: cCapDelta^x * cDelta = commit(e, s_tilde)
	zqGroup := emath.ZqGroupFromGqGroup(group)
	zero, _ := emath.NewZqElement(big.NewInt(0), zqGroup)
	eVec := make([]emath.ZqElement, n)
	for k := 0; k < n-1; k++ {
		eVec[k] = x.Multiply(arg.BTilde.Get(k + 1)).Subtract(arg.BTilde.Get(k).Multiply(arg.ATilde.Get(k + 1)))
	}
	eVec[n-1] = zero

	lhs2 := arg.CCapDelta.Exponentiate(x).Multiply(arg.CDelta)
	rhs2 := ck.Commit(emath.ZqVectorOf(eVec...), arg.STilde)
	if !lhs2.Equals(rhs2) {
		return false
	}

	// Check 3: b_tilde[0] = a_tilde[0]
	if !arg.BTilde.Get(0).Equals(arg.ATilde.Get(0)) {
		return false
	}

	// Check 4: b_tilde[n-1] = x*b
	xb := x.Multiply(b)
	return arg.BTilde.Get(n - 1).Equals(xb)
}

// svpChallenge computes the Fiat-Shamir challenge for SVP.
// Java hash order: (p, q, pk, ck, c_Delta, c_delta, c_d, b, c_a)
func svpChallenge(group *emath.GqGroup, pk elgamal.PublicKey, ck *CommitmentKey, cCapDelta, cDelta, cd emath.GqElement, b emath.ZqElement, ca emath.GqElement) emath.ZqElement {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	q := group.Q()

	hashBytes := hash.RecursiveHash(
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		pkToHashable(pk),
		ckToHashable(ck),
		hash.HashableBigInt{Value: cCapDelta.Value()},
		hash.HashableBigInt{Value: cDelta.Value()},
		hash.HashableBigInt{Value: cd.Value()},
		hash.HashableBigInt{Value: b.Value()},
		hash.HashableBigInt{Value: ca.Value()},
	)

	eVal := new(big.Int).SetBytes(hashBytes)
	eVal.Mod(eVal, q)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
