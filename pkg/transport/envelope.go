package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/user/evote/pkg/trace"
	"github.com/user/evote/pkg/transportsec"
)

// Envelope is a single authenticated message from one party to another. The
// signature (Ed25519, produced in Rust) covers the canonical byte encoding of
// all other fields, so From/To/Type/Nonce/Payload are all integrity-protected.
// Encrypted marks whether Payload is AES-GCM ciphertext (see SecureChannel).
type Envelope struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Type      string `json:"type"`
	Nonce     uint64 `json:"nonce"`
	Encrypted bool   `json:"encrypted"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// signingBytes returns the canonical bytes covered by the signature: a
// length-prefixed concatenation of every field except the signature itself.
// Length-prefixing makes the encoding injective (no field-boundary ambiguity).
func (e *Envelope) signingBytes() []byte {
	var b []byte
	appendField := func(data []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(data)))
		b = append(b, l[:]...)
		b = append(b, data...)
	}
	appendField([]byte(e.From))
	appendField([]byte(e.To))
	appendField([]byte(e.Type))
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], e.Nonce)
	appendField(nonce[:])
	if e.Encrypted {
		appendField([]byte{1})
	} else {
		appendField([]byte{0})
	}
	appendField(e.Payload)
	// Hash the concatenation to a fixed 32-byte digest that is what actually
	// gets signed (keeps signed inputs short and uniform).
	h := sha256.Sum256(b)
	return h[:]
}

// Seal signs the envelope with the sender identity's Ed25519 key (via Rust).
func (e *Envelope) Seal(sender *Identity) error {
	sig, err := transportsec.Ed25519Sign(sender.SigningSeed(), e.signingBytes())
	if err != nil {
		return fmt.Errorf("seal %s->%s: %w", e.From, e.To, err)
	}
	e.Signature = sig
	trace.EmitFunc(func() trace.Event {
		return trace.Event{
			Party:   e.From,
			Kind:    trace.KindSign,
			Caption: fmt.Sprintf("%s signs %q → %s", e.From, e.Type, e.To),
			LaTeX:   `\sigma \gets \mathrm{Ed25519.Sign}_{sk}\!\big(\mathrm{SHA256}(\text{envelope})\big),\quad |\sigma| = 64\text{ B}`,
			ASCII:   "σ ← Ed25519.Sign(sk, H(envelope))",
			Values: map[string]string{
				"party": e.From,
				"to":    e.To,
				"type":  e.Type,
				"sigma": hexOf(sig),
			},
		}
	})
	return nil
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// Verify checks the envelope signature against senderEdPub (via Rust).
func (e *Envelope) Verify(senderEdPub []byte) error {
	if err := transportsec.Ed25519Verify(senderEdPub, e.signingBytes(), e.Signature); err != nil {
		return fmt.Errorf("envelope %s->%s type=%s: %w", e.From, e.To, e.Type, err)
	}
	return nil
}

// MarshalPayload JSON-encodes v into the payload.
func MarshalPayload(v any) ([]byte, error) { return json.Marshal(v) }

// UnmarshalPayload JSON-decodes the payload into v.
func UnmarshalPayload(data []byte, v any) error { return json.Unmarshal(data, v) }
