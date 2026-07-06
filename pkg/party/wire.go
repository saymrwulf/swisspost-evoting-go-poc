package party

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/zkp"
)

// This file is the validated serialization boundary between parties. Crypto
// objects have unexported fields and cannot be JSON-marshaled directly, so they
// travel as decimal-string DTOs. Every decode routes group elements through the
// checked constructors (NewGqElement / NewZqElement), so a peer can never inject
// a value outside G_q or Z_q — this closes the small-subgroup / non-residue hole
// (finding M4) at the point where proofs and ciphertexts cross a trust boundary.

// --- scalar helpers ---

func gqToStr(e emath.GqElement) string { return e.Value().String() }
func zqToStr(e emath.ZqElement) string { return e.Value().String() }

func strToGq(s string, group *emath.GqGroup) (emath.GqElement, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return emath.GqElement{}, fmt.Errorf("invalid integer %q", s)
	}
	return emath.NewGqElement(v, group) // validates membership in G_q
}

func strToZq(s string, zq *emath.ZqGroup) (emath.ZqElement, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return emath.ZqElement{}, fmt.Errorf("invalid integer %q", s)
	}
	return emath.NewZqElement(v, zq) // validates range [0, q)
}

// --- vectors ---

func gqVecToStrs(v *emath.GqVector) []string {
	out := make([]string, v.Size())
	for i := 0; i < v.Size(); i++ {
		out[i] = gqToStr(v.Get(i))
	}
	return out
}

func strsToGqVec(ss []string, group *emath.GqGroup) (*emath.GqVector, error) {
	elems := make([]emath.GqElement, len(ss))
	for i, s := range ss {
		e, err := strToGq(s, group)
		if err != nil {
			return nil, fmt.Errorf("gq vector element %d: %w", i, err)
		}
		elems[i] = e
	}
	return emath.GqVectorOf(elems...), nil
}

func zqVecToStrs(v *emath.ZqVector) []string {
	out := make([]string, v.Size())
	for i := 0; i < v.Size(); i++ {
		out[i] = zqToStr(v.Get(i))
	}
	return out
}

func strsToZqVec(ss []string, zq *emath.ZqGroup) (*emath.ZqVector, error) {
	elems := make([]emath.ZqElement, len(ss))
	for i, s := range ss {
		e, err := strToZq(s, zq)
		if err != nil {
			return nil, fmt.Errorf("zq vector element %d: %w", i, err)
		}
		elems[i] = e
	}
	return emath.ZqVectorOf(elems...), nil
}

// --- public key ---

type wirePublicKey struct {
	Elements []string `json:"elements"`
}

func encodePK(pk elgamal.PublicKey) wirePublicKey {
	return wirePublicKey{Elements: gqVecToStrs(pk.Elements)}
}

func (w wirePublicKey) decode(group *emath.GqGroup) (elgamal.PublicKey, error) {
	vec, err := strsToGqVec(w.Elements, group)
	if err != nil {
		return elgamal.PublicKey{}, fmt.Errorf("public key: %w", err)
	}
	return elgamal.PublicKey{Elements: vec}, nil
}

// --- Schnorr proof ---

type wireSchnorr struct {
	E string `json:"e"`
	Z string `json:"z"`
}

func encodeSchnorr(p zkp.SchnorrProof) wireSchnorr {
	return wireSchnorr{E: zqToStr(p.E), Z: zqToStr(p.Z)}
}

func (w wireSchnorr) decode(zq *emath.ZqGroup) (zkp.SchnorrProof, error) {
	e, err := strToZq(w.E, zq)
	if err != nil {
		return zkp.SchnorrProof{}, fmt.Errorf("schnorr E: %w", err)
	}
	z, err := strToZq(w.Z, zq)
	if err != nil {
		return zkp.SchnorrProof{}, fmt.Errorf("schnorr Z: %w", err)
	}
	return zkp.SchnorrProof{E: e, Z: z}, nil
}

// --- ciphertext ---

type wireCiphertext struct {
	Gamma string   `json:"gamma"`
	Phis  []string `json:"phis"`
}

func encodeCiphertext(ct elgamal.Ciphertext) wireCiphertext {
	return wireCiphertext{Gamma: gqToStr(ct.Gamma), Phis: gqVecToStrs(ct.Phis)}
}

func (w wireCiphertext) decode(group *emath.GqGroup) (elgamal.Ciphertext, error) {
	gamma, err := strToGq(w.Gamma, group)
	if err != nil {
		return elgamal.Ciphertext{}, fmt.Errorf("ciphertext gamma: %w", err)
	}
	phis, err := strsToGqVec(w.Phis, group)
	if err != nil {
		return elgamal.Ciphertext{}, fmt.Errorf("ciphertext phis: %w", err)
	}
	return elgamal.NewCiphertext(gamma, phis), nil
}

// --- ciphertext vector ---

type wireCiphertextVector struct {
	Cts []wireCiphertext `json:"cts"`
}

func encodeCiphertextVector(v *elgamal.CiphertextVector) wireCiphertextVector {
	out := make([]wireCiphertext, v.Size())
	for i := 0; i < v.Size(); i++ {
		out[i] = encodeCiphertext(v.Get(i))
	}
	return wireCiphertextVector{Cts: out}
}

func (w wireCiphertextVector) decode(group *emath.GqGroup) (*elgamal.CiphertextVector, error) {
	cts := make([]elgamal.Ciphertext, len(w.Cts))
	for i, wc := range w.Cts {
		ct, err := wc.decode(group)
		if err != nil {
			return nil, fmt.Errorf("ciphertext %d: %w", i, err)
		}
		cts[i] = ct
	}
	return elgamal.NewCiphertextVector(cts), nil
}
