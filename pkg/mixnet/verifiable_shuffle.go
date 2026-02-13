package mixnet

import (
	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
)

// VerifiableShuffle holds the result of a verifiable shuffle.
type VerifiableShuffle struct {
	ShuffledCiphertexts *elgamal.CiphertextVector
	Argument            ShuffleArgument
}

// GenVerifiableShuffle performs a shuffle and generates a proof.
func GenVerifiableShuffle(
	C *elgamal.CiphertextVector,
	pk elgamal.PublicKey,
	group *emath.GqGroup,
) VerifiableShuffle {
	// Determine matrix dimensions
	N := C.Size()
	_, n := GetMatrixDimensions(N)

	// Generate commitment key of size n
	ck := GenCommitmentKey(n, group)

	// Perform shuffle
	shuffle := GenShuffle(C, pk)

	// Generate shuffle argument
	arg := GenShuffleArgument(C, shuffle.Shuffled, shuffle.Perm, shuffle.Rho, pk, ck, group)

	return VerifiableShuffle{
		ShuffledCiphertexts: shuffle.Shuffled,
		Argument:            arg,
	}
}

// VerifyShuffle verifies a verifiable shuffle.
func VerifyShuffle(
	C *elgamal.CiphertextVector,
	vs VerifiableShuffle,
	pk elgamal.PublicKey,
	group *emath.GqGroup,
) bool {
	N := C.Size()
	_, n := GetMatrixDimensions(N)

	// Regenerate commitment key (deterministic from group)
	ck := GenCommitmentKey(n, group)

	return VerifyShuffleArgument(vs.Argument, C, vs.ShuffledCiphertexts, pk, ck, group)
}
