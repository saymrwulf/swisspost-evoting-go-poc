package verify

import (
	"fmt"

	"github.com/user/evote/pkg/hash"
	"github.com/user/evote/pkg/protocol"
	"github.com/user/evote/pkg/zkp"
	emath "github.com/user/evote/pkg/math"
	"math/big"
)

// VerifySetup performs all setup phase verification checks.
func VerifySetup(event *protocol.ElectionEvent) bool {
	allPassed := true

	fmt.Println("  [Setup Verification]")

	// 1. Verify encryption parameters
	if !verifyEncryptionParams(event.Config.Group) {
		fmt.Println("    FAIL: Encryption parameters invalid")
		allPassed = false
	} else {
		fmt.Println("    PASS: Encryption parameters (p=2q+1, both prime, g generates G_q)")
	}

	// 2. Verify small primes are group members
	for i, p := range event.Primes {
		if !event.Config.Group.IsGroupMember(p) {
			fmt.Printf("    FAIL: Prime %d (%v) is not a group member\n", i, p)
			allPassed = false
		}
	}
	fmt.Printf("    PASS: All %d small primes are group members\n", len(event.Primes))

	// 3. Verify Schnorr proofs for each CC's keys
	for j, cc := range event.CCs {
		for i := 0; i < event.Config.NumOptions; i++ {
			auxInfo := []hash.Hashable{
				hash.HashableBigInt{Value: big.NewInt(int64(i))},
				hash.HashableString{Value: event.Config.ElectionID},
				hash.HashableBigInt{Value: big.NewInt(int64(j))},
			}
			valid := zkp.VerifySchnorrProof(cc.SchnorrProofs[i], cc.ElectionKeyPair.PK.Get(i), event.Config.Group, auxInfo...)
			if !valid {
				fmt.Printf("    FAIL: CC%d key %d Schnorr proof invalid\n", j, i)
				allPassed = false
			}
		}
		fmt.Printf("    PASS: CC%d Schnorr proofs (%d proofs)\n", j, event.Config.NumOptions)
	}

	// 4. Verify key consistency (combined PK = product of all CC PKs * EB PK)
	if verifyKeyConsistency(event) {
		fmt.Println("    PASS: Election public key consistency")
	} else {
		fmt.Println("    FAIL: Election public key inconsistent")
		allPassed = false
	}

	return allPassed
}

func verifyEncryptionParams(group *emath.GqGroup) bool {
	p := group.P()
	q := group.Q()
	g := group.Generator()

	// p is prime
	if !p.ProbablyPrime(64) {
		return false
	}

	// q is prime
	if !q.ProbablyPrime(64) {
		return false
	}

	// p = 2q + 1
	expected := new(big.Int).Mul(big.NewInt(2), q)
	expected.Add(expected, big.NewInt(1))
	if p.Cmp(expected) != 0 {
		return false
	}

	// g is in G_q (Jacobi symbol = 1)
	if big.Jacobi(g.Value(), p) != 1 {
		return false
	}

	return true
}

func verifyKeyConsistency(event *protocol.ElectionEvent) bool {
	// Recompute the election PK from CC keys and EB key
	for i := 0; i < event.Config.NumOptions; i++ {
		elem := event.Config.Group.Identity()
		for _, cc := range event.CCs {
			elem = elem.Multiply(cc.ElectionKeyPair.PK.Get(i))
		}
		elem = elem.Multiply(event.EB.PK.Get(i))
		expected := event.ElectionPK.Get(i)
		if !elem.Equals(expected) {
			return false
		}
	}
	return true
}
