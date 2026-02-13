package kdf

import (
	"crypto/sha256"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	emath "github.com/user/evote/pkg/math"
)

// DeriveKey derives a key using HKDF-SHA256.
func DeriveKey(prk, info []byte, length int) []byte {
	reader := hkdf.Expand(sha256.New, prk, info)
	key := make([]byte, length)
	_, err := io.ReadFull(reader, key)
	if err != nil {
		panic("HKDF expand failed: " + err.Error())
	}
	return key
}

// KDFToZq derives a Z_q element using HKDF-SHA256.
// PRK is the pseudorandom key, info is the context info, q is the modulus.
func KDFToZq(prk []byte, info []byte, q *big.Int) *big.Int {
	// Derive enough bytes: ceil(q.BitLen() / 8) + extra for uniformity
	byteLen := (q.BitLen()+7)/8 + 16 // extra 16 bytes for rejection sampling avoidance
	derived := DeriveKey(prk, info, byteLen)
	val := new(big.Int).SetBytes(derived)
	return val.Mod(val, q)
}

// KDFToZqElement derives a ZqElement using HKDF-SHA256.
func KDFToZqElement(prk []byte, info []byte, group *emath.ZqGroup) emath.ZqElement {
	val := KDFToZq(prk, info, group.Q())
	e, err := emath.NewZqElement(val, group)
	if err != nil {
		panic("KDFToZqElement: " + err.Error())
	}
	return e
}

// BuildKDFInfo builds a KDF info string from label and context parts.
func BuildKDFInfo(parts ...string) []byte {
	var info []byte
	for _, p := range parts {
		info = append(info, []byte(p)...)
	}
	return info
}

// Argon2id derives a key using Argon2id.
func Argon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// DefaultArgon2id uses the default parameters from the Swiss Post e-voting system.
func DefaultArgon2id(password, salt []byte) []byte {
	// Typical parameters from the protocol
	return Argon2id(password, salt, 3, 64*1024, 4, 32)
}
