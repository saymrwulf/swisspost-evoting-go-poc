// Package transportsec provides transport-layer security primitives for
// inter-party messages: Ed25519 signatures and X25519 ECDH key agreement.
//
// The cryptography is implemented in Rust (rust/transportsec, using
// ed25519-dalek and x25519-dalek) and linked in as a static library; this
// package is a thin cgo binding. Go code must not implement or substitute
// this cryptography — creating and verifying transport signatures in Rust
// is a design requirement of the PoC.
package transportsec

/*
#cgo CFLAGS: -I${SRCDIR}/../../rust/transportsec/include
#cgo LDFLAGS: ${SRCDIR}/../../rust/transportsec/target/release/libtransportsec.a
#include "transportsec.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	SeedSize      = 32
	PublicKeySize = 32
	SignatureSize = 64
	SharedSize    = 32
)

var (
	ErrNull   = errors.New("transportsec: null pointer")
	ErrBadKey = errors.New("transportsec: malformed or degenerate key")
	ErrVerify = errors.New("transportsec: signature verification failed")
)

func codeToError(code C.int32_t) error {
	switch code {
	case 0:
		return nil
	case -1:
		return ErrNull
	case -2:
		return ErrBadKey
	case -3:
		return ErrVerify
	default:
		return errors.New("transportsec: unknown error code")
	}
}

// bufPtr returns a C pointer to the slice data, or nil for empty slices.
func bufPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// Ed25519GenerateKey creates a new Ed25519 keypair in Rust.
// Returns the 32-byte private seed and 32-byte public key.
func Ed25519GenerateKey() (seed, pub []byte, err error) {
	seed = make([]byte, SeedSize)
	pub = make([]byte, PublicKeySize)
	code := C.ts_ed25519_keygen(bufPtr(seed), bufPtr(pub))
	if err := codeToError(code); err != nil {
		return nil, nil, err
	}
	return seed, pub, nil
}

// Ed25519Sign signs msg with the 32-byte seed, returning a 64-byte signature.
func Ed25519Sign(seed, msg []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, ErrBadKey
	}
	sig := make([]byte, SignatureSize)
	code := C.ts_ed25519_sign(bufPtr(seed), bufPtr(msg), C.size_t(len(msg)), bufPtr(sig))
	if err := codeToError(code); err != nil {
		return nil, err
	}
	return sig, nil
}

// Ed25519Verify checks a 64-byte signature over msg against a 32-byte public key.
// Returns nil if valid, ErrVerify if the signature does not match.
func Ed25519Verify(pub, msg, sig []byte) error {
	if len(pub) != PublicKeySize || len(sig) != SignatureSize {
		return ErrBadKey
	}
	code := C.ts_ed25519_verify(bufPtr(pub), bufPtr(msg), C.size_t(len(msg)), bufPtr(sig))
	return codeToError(code)
}

// X25519GenerateKey creates a new X25519 keypair in Rust.
func X25519GenerateKey() (priv, pub []byte, err error) {
	priv = make([]byte, SeedSize)
	pub = make([]byte, PublicKeySize)
	code := C.ts_x25519_keygen(bufPtr(priv), bufPtr(pub))
	if err := codeToError(code); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// X25519SharedSecret computes the ECDH shared secret priv * peerPub.
// Fails with ErrBadKey on a non-contributory (all-zero) result.
func X25519SharedSecret(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != SeedSize || len(peerPub) != PublicKeySize {
		return nil, ErrBadKey
	}
	shared := make([]byte, SharedSize)
	code := C.ts_x25519_dh(bufPtr(priv), bufPtr(peerPub), bufPtr(shared))
	if err := codeToError(code); err != nil {
		return nil, err
	}
	return shared, nil
}
