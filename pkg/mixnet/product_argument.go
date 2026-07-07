package mixnet

import (
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
)

// ProductArgument proves that the product of all elements in a committed matrix equals b.
type ProductArgument struct {
	CB       *emath.GqElement           // Commitment to Hadamard product (nil if m=1)
	Hadamard *HadamardArgument          // nil if m=1
	SVP      SingleValueProductArgument // Always present
}

// GenProductArgument generates a product argument.
func GenProductArgument(
	cA *emath.GqVector, // Commitments to A columns (size m)
	b emath.ZqElement, // Product b = Π A[i,j]
	A *emath.ZqMatrix, // n×m matrix
	r *emath.ZqVector, // Randomness for A columns
	pk elgamal.PublicKey, // Public key (needed for sub-argument hashes)
	ck CommitmentKey,
	group *emath.GqGroup,
) ProductArgument {
	n := A.NumRows()
	m := A.NumCols()

	emitArgument("product",
		"Product argument: prove the product of all matrix entries equals b",
		`\text{ProductArgument}:\ \prod_{i=1}^{n}\prod_{j=1}^{m} A_{ij} = b \quad(\text{via Hadamard} \circ \text{SVP})`,
		"ProductArgument: Π_ij A_ij = b   (Hadamard ∘ single-value-product)",
		dims(m, n))

	if m == 1 {
		// Single column: just use SVP directly
		svp := GenSingleValueProductArgument(cA.Get(0), b, A.GetColumn(0), r.Get(0), pk, ck, group)
		return ProductArgument{SVP: svp}
	}

	// m > 1: Hadamard + SVP
	zqGroup := emath.ZqGroupFromGqGroup(group)

	// Compute b_vector = row-wise products (Hadamard product of all columns)
	bVector := make([]emath.ZqElement, n)
	for i := 0; i < n; i++ {
		prod := A.Get(i, 0)
		for j := 1; j < m; j++ {
			prod = prod.Multiply(A.Get(i, j))
		}
		bVector[i] = prod
	}
	bVec := emath.ZqVectorOf(bVector...)

	// Commit to Hadamard product
	s := emath.RandomZqElement(zqGroup)
	cb := ck.Commit(bVec, s)

	// Generate Hadamard argument (now with pk)
	hadamardArg := GenHadamardArgument(cA, cb, A, bVec, r, s, pk, ck, group)

	// Generate SVP argument (now with pk)
	svpArg := GenSingleValueProductArgument(cb, b, bVec, s, pk, ck, group)

	return ProductArgument{
		CB:       &cb,
		Hadamard: &hadamardArg,
		SVP:      svpArg,
	}
}

// VerifyProductArgument verifies a product argument.
func VerifyProductArgument(
	arg ProductArgument,
	cA *emath.GqVector,
	b emath.ZqElement,
	pk elgamal.PublicKey,
	ck CommitmentKey,
	group *emath.GqGroup,
) bool {
	m := cA.Size()

	if m == 1 {
		return VerifySingleValueProductArgument(arg.SVP, cA.Get(0), b, pk, ck, group)
	}

	// Verify Hadamard
	if arg.CB == nil || arg.Hadamard == nil {
		return false
	}
	if !VerifyHadamardArgument(*arg.Hadamard, cA, *arg.CB, pk, ck, group) {
		return false
	}

	// Verify SVP
	return VerifySingleValueProductArgument(arg.SVP, *arg.CB, b, pk, ck, group)
}

func computeProduct(matrix *emath.ZqMatrix) emath.ZqElement {
	one, _ := emath.NewZqElement(big.NewInt(1), matrix.Group())
	result := one
	for i := 0; i < matrix.NumRows(); i++ {
		for j := 0; j < matrix.NumCols(); j++ {
			result = result.Multiply(matrix.Get(i, j))
		}
	}
	return result
}
