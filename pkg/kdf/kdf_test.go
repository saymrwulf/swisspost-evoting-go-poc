package kdf

import (
	"bytes"
	"testing"
)

// TestBuildKDFInfoInjective locks in the domain-separation fix: part tuples
// that would concatenate to the same bytes must now produce distinct info
// strings (e.g. ("e1","23x") vs ("e12","3x")).
func TestBuildKDFInfoInjective(t *testing.T) {
	a := BuildKDFInfo("e1", "23x")
	b := BuildKDFInfo("e12", "3x")
	if bytes.Equal(a, b) {
		t.Fatal("distinct part tuples collided into the same KDF info")
	}
	// Same parts must be deterministic.
	if !bytes.Equal(BuildKDFInfo("label", "ctx"), BuildKDFInfo("label", "ctx")) {
		t.Fatal("BuildKDFInfo is not deterministic")
	}
	// A boundary vs. joined variant must differ too.
	if bytes.Equal(BuildKDFInfo("a", "bc"), BuildKDFInfo("ab", "c")) {
		t.Fatal("boundary shift collided")
	}
}
