package elgamal

import (
	"math/big"

	emath "github.com/user/evote/pkg/math"
)

// Message represents a multi-recipient plaintext message (vector of G_q elements).
type Message struct {
	Elements *emath.GqVector
}

// NewMessage creates a Message from a GqVector.
func NewMessage(elements *emath.GqVector) Message {
	return Message{Elements: elements}
}

// OnesMessage creates a message of all 1s (identity elements).
func OnesMessage(size int, group *emath.GqGroup) Message {
	return Message{Elements: emath.GqVectorOfIdentities(size, group)}
}

// Size returns the number of message elements.
func (m Message) Size() int {
	return m.Elements.Size()
}

// Get returns the i-th message element.
func (m Message) Get(i int) emath.GqElement {
	return m.Elements.Get(i)
}

// IsOnes checks if all elements are the identity (1).
func (m Message) IsOnes() bool {
	for i := 0; i < m.Size(); i++ {
		if !m.Get(i).IsIdentity() {
			return false
		}
	}
	return true
}

// MessageFromBigInts creates a message from big.Int values.
func MessageFromBigInts(values []*big.Int, group *emath.GqGroup) (Message, error) {
	v, err := emath.GqVectorFromBigInts(values, group)
	if err != nil {
		return Message{}, err
	}
	return Message{Elements: v}, nil
}
