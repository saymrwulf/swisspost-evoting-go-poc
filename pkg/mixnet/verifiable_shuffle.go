package mixnet

import (
	"fmt"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/trace"
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

	trace.EmitFunc(func() trace.Event {
		return trace.Event{
			Kind:    trace.KindShuffle,
			Caption: fmt.Sprintf("Bayer-Groth verifiable shuffle of %d ciphertexts", N),
			LaTeX:   `\mathbf{C}' = \big\{\, \mathrm{ReEnc}_{pk}\!\big(C_{\pi(i)};\, \rho_i\big) \,\big\}_{i=1}^{\VAL{N}}, \qquad \pi \xleftarrow{\$} S_{\VAL{N}}`,
			ASCII:   "C' = { ReEnc_pk(C_π(i); ρ_i) }  for a secret permutation π",
			Values: map[string]string{
				"N": fmt.Sprintf("%d", N),
				"m": fmt.Sprintf("%d", N/n),
				"n": fmt.Sprintf("%d", n),
			},
		}
	})

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
