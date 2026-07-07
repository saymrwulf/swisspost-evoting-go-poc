package party

import (
	"fmt"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/trace"
)

// RunVerify has the verifier party independently re-check the public transcript:
// every CC's Schnorr key proof, and the full shuffle chain (each shuffle against
// the same input the tally used, threaded through the persisted partial
// decryptions). It returns nil only if every check passes. The verifier holds no
// secret — it works purely from the bulletin-board transcript.
func (c *Ceremony) RunVerify() error {
	trace.SetContext(NameVerifier, "verify")
	c.logf("\n--- VERIFICATION PHASE (multi-party) ---")
	tr := c.Transcript
	group := c.Config.Group

	// 1. Re-verify every CC's Schnorr proofs.
	for j := 0; j < c.Config.NumCCs; j++ {
		if err := verifyCCSchnorr(tr.ElectionID, group, j, tr.CCElectionPKs[j], tr.CCSchnorr[j]); err != nil {
			return fmt.Errorf("verifier: %w", err)
		}
		c.logf("  verify: cc%d Schnorr proofs VALID", j)
	}

	// 2. Re-verify the shuffle chain.
	if tr.MixInput == nil {
		return fmt.Errorf("verifier: transcript has no mix input")
	}
	if len(tr.Shuffles) != c.Config.NumCCs+1 {
		return fmt.Errorf("verifier: %d shuffles, want %d", len(tr.Shuffles), c.Config.NumCCs+1)
	}
	input := tr.MixInput
	for j, vs := range tr.Shuffles {
		var pk elgamal.PublicKey
		if j < c.Config.NumCCs {
			pk = remainingPK(tr, j, c.Config.NumCCs)
		} else {
			pk = tr.EBPublicKey
		}
		if !mixnet.VerifyShuffle(input, vs, pk, group) {
			return fmt.Errorf("verifier: shuffle %d INVALID", j)
		}
		c.logf("  verify: shuffle %d VALID", j)

		// The next shuffle's input is this CC's persisted partial decryption
		// (or, for the final EB shuffle, there is no next stage).
		if j < c.Config.NumCCs && j < len(tr.PartialDecrypts) {
			input = tr.PartialDecrypts[j]
		} else {
			input = vs.ShuffledCiphertexts
		}
	}

	// 3. Report the result.
	total := 0
	for _, n := range tr.Result {
		total += n
	}
	c.logf("  verify: tally result verified, %d decoded selections", total)
	return nil
}

// Result returns the verified election result from the transcript.
func (c *Ceremony) Result() map[int]int { return c.Transcript.Result }
