package zkp

import (
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/trace"
)

// GenSchnorrProof generates a Schnorr proof of knowledge of discrete log.
// Proves knowledge of x such that y = g^x.
func GenSchnorrProof(x emath.ZqElement, y emath.GqElement, group *emath.GqGroup, auxInfo ...hash.Hashable) SchnorrProof {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	// 1. Sample random b
	b := emath.RandomZqElement(zqGroup)

	// 2. Commitment: c = g^b
	c := g.Exponentiate(b)

	// 3. Build hash inputs
	e := schnorrChallenge(group, y, c, zqGroup, auxInfo)

	// 4. Response: z = b + e*x
	z := b.Add(e.Multiply(x))

	return SchnorrProof{E: e, Z: z}
}

// VerifySchnorrProof verifies a Schnorr proof.
func VerifySchnorrProof(proof SchnorrProof, y emath.GqElement, group *emath.GqGroup, auxInfo ...hash.Hashable) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()

	// Reconstruct commitment: c' = g^z * y^(-e)
	gZ := g.Exponentiate(proof.Z)
	yNegE := y.Exponentiate(proof.E.Negate())
	cPrime := gZ.Multiply(yNegE)

	// Recompute challenge
	ePrime := schnorrChallenge(group, y, cPrime, zqGroup, auxInfo)

	return proof.E.Equals(ePrime)
}

// schnorrChallenge computes the Fiat-Shamir challenge for Schnorr proofs.
// Hash order: (p, q, g), y, c, h_aux
func schnorrChallenge(group *emath.GqGroup, y emath.GqElement, c emath.GqElement, zqGroup *emath.ZqGroup, auxInfo []hash.Hashable) emath.ZqElement {
	// f = (p, q, g)
	f := hash.HashableList{Elements: []hash.Hashable{
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		hash.HashableBigInt{Value: group.Generator().Value()},
	}}

	// h_aux
	hAux := buildAuxHash("SchnorrProof", auxInfo)

	// Challenge: RecursiveHashToZq oversamples to q.BitLen()+2λ bits before
	// reducing mod q, giving a uniform Z_q element (per the Swiss Post spec).
	// A plain RecursiveHash reduced mod q would be biased and would cap the
	// challenge space at 256 bits for production-sized groups.
	eVal := hash.RecursiveHashToZq(
		zqGroup.Q(),
		f,
		hash.HashableBigInt{Value: y.Value()},
		hash.HashableBigInt{Value: c.Value()},
		hAux,
	)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	trace.EmitFunc(func() trace.Event {
		return trace.Event{
			Kind:    trace.KindChallenge,
			Caption: "Fiat-Shamir challenge (Schnorr proof)",
			LaTeX:   `e = \mathcal{H}\big((p,q,g),\, y,\, c,\, h_{\mathrm{aux}}\big) \bmod q`,
			ASCII:   "e = H((p,q,g), y, c, h_aux) mod q",
			Values: map[string]string{
				"e": e.Value().String(),
				"y": y.Value().String(),
				"c": c.Value().String(),
			},
		}
	})
	return e
}

// buildAuxHash builds the auxiliary hash list.
// If auxInfo is empty: ["label"]
// Otherwise: ["label", auxInfo...]
func buildAuxHash(label string, auxInfo []hash.Hashable) hash.Hashable {
	elements := []hash.Hashable{hash.HashableString{Value: label}}
	if len(auxInfo) > 0 {
		elements = append(elements, auxInfo...)
	}
	return hash.HashableList{Elements: elements}
}
