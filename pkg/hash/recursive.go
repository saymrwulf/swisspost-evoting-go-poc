package hash

import (
	"math/big"

	"golang.org/x/crypto/sha3"
)

// SecurityLambda is the security parameter (128 bits).
const SecurityLambda = 128

// RecursiveHash computes the recursive hash using SHA3-256.
// If multiple values are provided, they are wrapped in a HashableList.
func RecursiveHash(values ...Hashable) []byte {
	if len(values) == 0 {
		panic("values must not be empty")
	}
	if len(values) > 1 {
		return RecursiveHash(HashableList{Elements: values})
	}

	v := values[0]
	switch h := v.(type) {
	case HashableBytes:
		return sha3Hash256(TagBytes, h.Data)

	case HashableBigInt:
		if h.Value.Sign() < 0 {
			panic("big.Int must be non-negative")
		}
		return sha3Hash256(TagBigInt, IntegerToByteArray(h.Value))

	case HashableString:
		return sha3Hash256(TagString, StringToByteArray(h.Value))

	case HashableList:
		// Recursively hash each element to 256 bits, then concatenate
		var data []byte
		for _, elem := range h.Elements {
			data = append(data, RecursiveHash(elem)...)
		}
		return sha3Hash256(TagList, data)

	default:
		panic("unknown Hashable type")
	}
}

// sha3Hash256 computes SHA3-256(tag || data).
func sha3Hash256(tag byte, data []byte) []byte {
	h := sha3.New256()
	h.Write([]byte{tag})
	h.Write(data)
	return h.Sum(nil)
}

// RecursiveHashOfLength computes the recursive hash using SHAKE-256 XOF,
// producing output of the requested bit length.
// For lists, each element is recursively hashed to the REQUESTED bit length (not 256 bits).
func RecursiveHashOfLength(requestedBitLength int, values ...Hashable) []byte {
	if len(values) == 0 {
		panic("values must not be empty")
	}
	if requestedBitLength < 512 {
		panic("requested bit length must be >= 512")
	}
	if len(values) > 1 {
		return RecursiveHashOfLength(requestedBitLength, HashableList{Elements: values})
	}

	v := values[0]
	byteLen := (requestedBitLength + 7) / 8 // ceil(bitLength/8)

	switch h := v.(type) {
	case HashableBytes:
		return CutToBitLength(shake256XOF(byteLen, TagBytes, h.Data), requestedBitLength)

	case HashableBigInt:
		if h.Value.Sign() < 0 {
			panic("big.Int must be non-negative")
		}
		return CutToBitLength(shake256XOF(byteLen, TagBigInt, IntegerToByteArray(h.Value)), requestedBitLength)

	case HashableString:
		return CutToBitLength(shake256XOF(byteLen, TagString, StringToByteArray(h.Value)), requestedBitLength)

	case HashableList:
		// CRITICAL: For lists, each element is recursively hashed to the REQUESTED bit length
		var data []byte
		for _, elem := range h.Elements {
			data = append(data, RecursiveHashOfLength(requestedBitLength, elem)...)
		}
		return CutToBitLength(shake256XOF(byteLen, TagList, data), requestedBitLength)

	default:
		panic("unknown Hashable type")
	}
}

// shake256XOF computes SHAKE-256 XOF with the specified output length.
func shake256XOF(outputLen int, tag byte, data []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte{tag})
	h.Write(data)
	output := make([]byte, outputLen)
	h.Read(output)
	return output
}

// RecursiveHashToZq hashes values to an element of Z_q.
// Prepends q and "RecursiveHash" to the input, then reduces modulo q.
func RecursiveHashToZq(q *big.Int, values ...Hashable) *big.Int {
	if q.Sign() <= 0 {
		panic("q must be positive")
	}

	// Target bit length: q.BitLen() + 2*lambda
	targetBits := q.BitLen() + 2*SecurityLambda

	// Construct extended input: [q, "RecursiveHash", values...]
	extended := make([]Hashable, 0, len(values)+2)
	extended = append(extended, HashableBigInt{Value: q})
	extended = append(extended, HashableString{Value: "RecursiveHash"})
	extended = append(extended, values...)

	// Hash to extended length
	hashBytes := RecursiveHashOfLength(targetBits, extended...)

	// Convert to integer and reduce mod q
	hPrime := ByteArrayToInteger(hashBytes)
	return new(big.Int).Mod(hPrime, q)
}
