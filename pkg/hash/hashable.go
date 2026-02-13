package hash

import (
	"math/big"
)

// Tag bytes for the Hashable type system
const (
	TagBytes  byte = 0x00
	TagBigInt byte = 0x01
	TagString byte = 0x02
	TagList   byte = 0x03
)

// Hashable represents a value that can be recursively hashed.
type Hashable interface {
	hashableTag() byte
	hashableData() interface{}
}

// HashableBytes wraps a byte slice.
type HashableBytes struct {
	Data []byte
}

func (h HashableBytes) hashableTag() byte      { return TagBytes }
func (h HashableBytes) hashableData() interface{} { return h.Data }

// HashableBigInt wraps a non-negative big.Int.
type HashableBigInt struct {
	Value *big.Int
}

func (h HashableBigInt) hashableTag() byte      { return TagBigInt }
func (h HashableBigInt) hashableData() interface{} { return h.Value }

// HashableString wraps a string.
type HashableString struct {
	Value string
}

func (h HashableString) hashableTag() byte      { return TagString }
func (h HashableString) hashableData() interface{} { return h.Value }

// HashableList wraps a list of Hashable values.
type HashableList struct {
	Elements []Hashable
}

func (h HashableList) hashableTag() byte      { return TagList }
func (h HashableList) hashableData() interface{} { return h.Elements }

// RawBigIntToHashable converts big.Int to HashableBigInt.
func RawBigIntToHashable(v *big.Int) Hashable {
	return HashableBigInt{Value: v}
}

// RawStringToHashable converts string to HashableString.
func RawStringToHashable(s string) Hashable {
	return HashableString{Value: s}
}

// RawBytesToHashable converts bytes to HashableBytes.
func RawBytesToHashable(b []byte) Hashable {
	return HashableBytes{Data: b}
}
