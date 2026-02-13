package mixnet

import (
	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// pkToHashable converts an ElGamal public key to a HashableList.
// Java: ElGamalMultiRecipientPublicKey implements HashableList,
// toHashableForm() returns the list of key elements.
func pkToHashable(pk elgamal.PublicKey) hash.Hashable {
	elems := make([]hash.Hashable, pk.Size())
	for i := 0; i < pk.Size(); i++ {
		elems[i] = hash.HashableBigInt{Value: pk.Get(i).Value()}
	}
	return hash.HashableList{Elements: elems}
}

// ckToHashable converts a CommitmentKey to a HashableList.
// Java: CommitmentKey implements HashableList,
// toHashableForm() returns Stream.concat(Stream.of(h), gElements.stream())
func ckToHashable(ck *CommitmentKey) hash.Hashable {
	elems := make([]hash.Hashable, 1+ck.Size())
	elems[0] = hash.HashableBigInt{Value: ck.H.Value()}
	for i := 0; i < ck.Size(); i++ {
		elems[1+i] = hash.HashableBigInt{Value: ck.G.Get(i).Value()}
	}
	return hash.HashableList{Elements: elems}
}

// gqVectorToHashable converts a GqVector to a HashableList.
// Java: GroupVector<GqElement> implements HashableList,
// toHashableForm() returns the list of elements.
func gqVectorToHashable(v *emath.GqVector) hash.Hashable {
	elems := make([]hash.Hashable, v.Size())
	for i := 0; i < v.Size(); i++ {
		elems[i] = hash.HashableBigInt{Value: v.Get(i).Value()}
	}
	return hash.HashableList{Elements: elems}
}

// ciphertextToHashable converts an ElGamal ciphertext to a HashableList.
// Java: ElGamalMultiRecipientCiphertext implements HashableList,
// toHashableForm() returns [gamma, phi_0, phi_1, ...]
func ciphertextToHashable(ct elgamal.Ciphertext) hash.Hashable {
	elems := make([]hash.Hashable, 1+ct.Size())
	elems[0] = hash.HashableBigInt{Value: ct.Gamma.Value()}
	for i := 0; i < ct.Size(); i++ {
		elems[1+i] = hash.HashableBigInt{Value: ct.GetPhi(i).Value()}
	}
	return hash.HashableList{Elements: elems}
}

// ciphertextVectorToHashable converts a CiphertextVector to a HashableList.
// Java: GroupVector<ElGamalMultiRecipientCiphertext> implements HashableList,
// toHashableForm() returns list of ciphertexts (each is itself a HashableList).
func ciphertextVectorToHashable(v *elgamal.CiphertextVector) hash.Hashable {
	elems := make([]hash.Hashable, v.Size())
	for i := 0; i < v.Size(); i++ {
		elems[i] = ciphertextToHashable(v.Get(i))
	}
	return hash.HashableList{Elements: elems}
}

// ciphertextMatrixToHashable converts a slice of CiphertextVectors (matrix) to a HashableList.
// Java: GroupMatrix<ElGamalMultiRecipientCiphertext> — represented as list of row vectors.
func ciphertextMatrixToHashable(rows []*elgamal.CiphertextVector) hash.Hashable {
	elems := make([]hash.Hashable, len(rows))
	for i, row := range rows {
		elems[i] = ciphertextVectorToHashable(row)
	}
	return hash.HashableList{Elements: elems}
}

// zqVectorToHashable converts a ZqVector to a HashableList.
func zqVectorToHashable(v *emath.ZqVector) hash.Hashable {
	elems := make([]hash.Hashable, v.Size())
	for i := 0; i < v.Size(); i++ {
		elems[i] = hash.HashableBigInt{Value: v.Get(i).Value()}
	}
	return hash.HashableList{Elements: elems}
}
