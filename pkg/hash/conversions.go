package hash

import (
	"math/big"
)

// IntegerToByteArray converts a non-negative big.Int to unsigned big-endian bytes.
// This matches Java's behavior: strip sign byte from BigInteger.toByteArray().
// Go's big.Int.Bytes() already returns unsigned big-endian, so this is a direct match.
// Zero produces an empty byte array.
func IntegerToByteArray(x *big.Int) []byte {
	if x.Sign() < 0 {
		panic("value must be non-negative")
	}
	return x.Bytes() // Go big.Int.Bytes() returns unsigned big-endian
}

// IntegerToFixedLengthByteArray converts a non-negative big.Int to a fixed-length
// unsigned big-endian byte array, zero-padded on the left.
func IntegerToFixedLengthByteArray(x *big.Int, length int) []byte {
	if x.Sign() < 0 {
		panic("value must be non-negative")
	}
	b := x.Bytes()
	if len(b) > length {
		panic("value too large for requested length")
	}
	if len(b) == length {
		return b
	}
	result := make([]byte, length)
	copy(result[length-len(b):], b)
	return result
}

// ByteArrayToInteger converts unsigned big-endian bytes to a non-negative big.Int.
// This matches Java's new BigInteger(1, bytes).
func ByteArrayToInteger(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// StringToByteArray converts a string to UTF-8 bytes.
func StringToByteArray(s string) []byte {
	return []byte(s)
}

// ByteLength returns the byte length of a big.Int: ceil(bitLength / 8).
func ByteLength(x *big.Int) int {
	bits := x.BitLen()
	if bits == 0 {
		return 0
	}
	return (bits + 7) / 8
}

// CutToBitLength extracts the rightmost n bits from a byte array B.
// Returns a byte array of ceil(n/8) bytes with only the rightmost n bits set.
func CutToBitLength(b []byte, n int) []byte {
	if n == 0 {
		return []byte{}
	}
	length := (n + 7) / 8 // ceil(n/8)
	offset := len(b) - length
	result := make([]byte, length)
	copy(result, b[offset:])
	// Mask the leftmost byte if n is not byte-aligned
	remainder := n % 8
	if remainder != 0 {
		mask := byte((1 << remainder) - 1)
		result[0] &= mask
	}
	return result
}
