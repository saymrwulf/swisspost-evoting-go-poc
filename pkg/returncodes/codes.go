package returncodes

import (
	"encoding/hex"
	"math/big"

	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// GenerateShortCode generates a short human-readable return code from a GqElement.
func GenerateShortCode(value emath.GqElement) string {
	hashBytes := hash.RecursiveHash(hash.HashableBigInt{Value: value.Value()})
	// Take first 4 bytes and encode as hex for a short code
	return hex.EncodeToString(hashBytes[:4])
}

// ComputeLCCValue computes the long choice return code value from partial choice return codes.
// lCC = H(pC, vcID, eeID, tau)
func ComputeLCCValue(pC emath.GqElement, vcID, eeID string, tau *big.Int) *big.Int {
	return hash.RecursiveHashToZq(
		pC.Group().Q(),
		hash.HashableBigInt{Value: pC.Value()},
		hash.HashableString{Value: vcID},
		hash.HashableString{Value: eeID},
		hash.HashableBigInt{Value: tau},
	)
}

// ComputeLVCCValue computes the long vote cast return code value.
// lVCC = H(pVCC, vcID, eeID)
func ComputeLVCCValue(pVCC emath.GqElement, vcID, eeID string) *big.Int {
	return hash.RecursiveHashToZq(
		pVCC.Group().Q(),
		hash.HashableBigInt{Value: pVCC.Value()},
		hash.HashableString{Value: vcID},
		hash.HashableString{Value: eeID},
	)
}
