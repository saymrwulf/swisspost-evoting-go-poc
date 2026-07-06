package transportsec

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	seed, pub, err := Ed25519GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("mixnet output, CC2 -> CC3")
	sig, err := Ed25519Sign(seed, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Ed25519Verify(pub, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := Ed25519Verify(pub, []byte("tampered"), sig); err != ErrVerify {
		t.Fatalf("tampered message: got %v, want ErrVerify", err)
	}
	sig[0] ^= 0xff
	if err := Ed25519Verify(pub, msg, sig); err != ErrVerify {
		t.Fatalf("corrupted signature: got %v, want ErrVerify", err)
	}
}

// TestEd25519CrossVerifyWithGoStdlib proves the Rust signatures are standard
// RFC 8032 Ed25519: Go's crypto/ed25519 must accept them, and Rust must
// accept Go-produced signatures. This guards against ABI/format drift.
func TestEd25519CrossVerifyWithGoStdlib(t *testing.T) {
	seed, pub, err := Ed25519GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("cross-language conformance")

	rustSig, err := Ed25519Sign(seed, msg)
	if err != nil {
		t.Fatalf("rust sign: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, rustSig) {
		t.Fatal("Go stdlib rejected Rust-produced signature")
	}

	goPriv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(goPriv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("Rust and Go derive different public keys from the same seed")
	}
	goSig := ed25519.Sign(goPriv, msg)
	if err := Ed25519Verify(pub, msg, goSig); err != nil {
		t.Fatalf("Rust rejected Go-produced signature: %v", err)
	}
}

func TestX25519Agreement(t *testing.T) {
	aPriv, aPub, err := X25519GenerateKey()
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	bPriv, bPub, err := X25519GenerateKey()
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}
	s1, err := X25519SharedSecret(aPriv, bPub)
	if err != nil {
		t.Fatalf("dh A: %v", err)
	}
	s2, err := X25519SharedSecret(bPriv, aPub)
	if err != nil {
		t.Fatalf("dh B: %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("shared secrets differ")
	}
	// Degenerate peer key (all zeros) must be rejected.
	if _, err := X25519SharedSecret(aPriv, make([]byte, 32)); err != ErrBadKey {
		t.Fatalf("zero peer key: got %v, want ErrBadKey", err)
	}
}
