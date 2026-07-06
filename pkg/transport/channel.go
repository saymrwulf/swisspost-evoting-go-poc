package transport

import (
	"crypto/sha256"
	"fmt"

	"github.com/user/evote/pkg/symmetric"
	"github.com/user/evote/pkg/transportsec"
)

// deriveSessionKey turns a raw X25519 shared secret into a 32-byte AES key by
// hashing it together with both parties' public keys (a lightweight KDF that
// binds the key to the specific peer pair and avoids using the raw DH output
// directly). The public keys are sorted so both ends derive the same key.
func deriveSessionKey(shared, pubA, pubB []byte) []byte {
	h := sha256.New()
	h.Write([]byte("evote-transport-session-v1"))
	// Order-independent: hash the lexicographically smaller key first.
	if lessBytes(pubA, pubB) {
		h.Write(pubA)
		h.Write(pubB)
	} else {
		h.Write(pubB)
		h.Write(pubA)
	}
	h.Write(shared)
	return h.Sum(nil)
}

func lessBytes(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// SecureChannel is a confidential channel between the local identity and a peer.
// The session key is derived from an X25519 ECDH (performed in Rust); payloads
// are sealed with AES-256-GCM. It complements envelope signing: sign-then-the
// channel gives authenticity, the channel gives confidentiality.
type SecureChannel struct {
	local      *Identity
	peerName   string
	peerXPub   []byte
	sessionKey []byte
}

// NewSecureChannel establishes a channel to a peer given the peer's X25519
// public key. The ECDH is computed in Rust.
func (id *Identity) NewSecureChannel(peerName string, peerXPub []byte) (*SecureChannel, error) {
	shared, err := transportsec.X25519SharedSecret(id.ECDHPrivate(), peerXPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH %s<->%s: %w", id.Name, peerName, err)
	}
	return &SecureChannel{
		local:      id,
		peerName:   peerName,
		peerXPub:   peerXPub,
		sessionKey: deriveSessionKey(shared, id.XPub, peerXPub),
	}, nil
}

// EncryptPayload seals plaintext with the session key, returning ciphertext with
// the GCM nonce prepended (associatedData binds it to a context string).
func (c *SecureChannel) EncryptPayload(plaintext, associatedData []byte) ([]byte, error) {
	ct, nonce, err := symmetric.Encrypt(c.sessionKey, plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, nonce...), ct...), nil
}

// DecryptPayload opens a payload produced by EncryptPayload.
func (c *SecureChannel) DecryptPayload(sealed, associatedData []byte) ([]byte, error) {
	const nonceSize = 12 // AES-GCM standard nonce
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("sealed payload too short")
	}
	nonce, ct := sealed[:nonceSize], sealed[nonceSize:]
	return symmetric.Decrypt(c.sessionKey, ct, nonce, associatedData)
}
