package zkp

import (
	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
)

// GenDecryptionProof generates a proof of correct ElGamal decryption.
// Proves that message = Decrypt(ciphertext, sk).
func GenDecryptionProof(
	ct elgamal.Ciphertext,
	sk elgamal.PrivateKey,
	pk elgamal.PublicKey,
	msg elgamal.Message,
	group *emath.GqGroup,
	auxInfo ...hash.Hashable,
) DecryptionProof {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()
	l := ct.Size()
	gamma := ct.Gamma

	// 1. Sample random b = (b_0, ..., b_{l-1})
	bVec := emath.RandomZqVector(l, zqGroup)

	// 2. Commitment: phi(b, gamma)
	// c = [g^b_0, ..., g^b_{l-1}, gamma^b_0, ..., gamma^b_{l-1}]
	commitments := computePhiDecryption(bVec, g, gamma, group)

	// 3. Statement: y = [pk_0, ..., pk_{l-1}, phi_0/m_0, ..., phi_{l-1}/m_{l-1}]
	statement := buildDecryptionStatement(pk, ct, msg, l)

	// 4. Compute challenge
	e := decryptionChallenge(group, gamma, statement, commitments, ct, msg, zqGroup, auxInfo)

	// 5. Response: z_i = b_i + e * sk_i
	zElems := make([]emath.ZqElement, l)
	for i := 0; i < l; i++ {
		zElems[i] = bVec.Get(i).Add(e.Multiply(sk.Get(i)))
	}

	return DecryptionProof{
		E: e,
		Z: emath.ZqVectorOf(zElems...),
	}
}

// VerifyDecryptionProof verifies a decryption proof.
func VerifyDecryptionProof(
	ct elgamal.Ciphertext,
	pk elgamal.PublicKey,
	msg elgamal.Message,
	proof DecryptionProof,
	group *emath.GqGroup,
	auxInfo ...hash.Hashable,
) bool {
	zqGroup := emath.ZqGroupFromGqGroup(group)
	g := group.Generator()
	l := ct.Size()
	gamma := ct.Gamma

	// Compute phi(z, gamma)
	x := computePhiDecryption(proof.Z, g, gamma, group)

	// Statement
	statement := buildDecryptionStatement(pk, ct, msg, l)

	// Reconstruct commitments: c'_i = x_i * (y_i^(-1))^e
	negE := proof.E.Negate()
	cPrime := make([]emath.GqElement, len(x))
	for i := range x {
		yInvE := statement[i].Exponentiate(negE)
		cPrime[i] = x[i].Multiply(yInvE)
	}

	// Recompute challenge
	ePrime := decryptionChallenge(group, gamma, statement, cPrime, ct, msg, zqGroup, auxInfo)

	return proof.E.Equals(ePrime)
}

// GenVerifiableDecryptions generates decryption proofs for a batch of ciphertexts.
func GenVerifiableDecryptions(
	cts *elgamal.CiphertextVector,
	sk elgamal.PrivateKey,
	pk elgamal.PublicKey,
	group *emath.GqGroup,
	auxInfo ...hash.Hashable,
) ([]elgamal.Ciphertext, []DecryptionProof) {
	n := cts.Size()
	decrypted := make([]elgamal.Ciphertext, n)
	proofs := make([]DecryptionProof, n)

	for i := 0; i < n; i++ {
		ct := cts.Get(i)
		// Partial decrypt
		dec := elgamal.PartialDecrypt(ct, sk)
		decrypted[i] = dec

		// Get message for proof
		msg := elgamal.Decrypt(ct, sk)

		// Generate proof
		proofs[i] = GenDecryptionProof(ct, sk, pk, msg, group, auxInfo...)
	}

	return decrypted, proofs
}

func computePhiDecryption(zVec *emath.ZqVector, g emath.GqElement, gamma emath.GqElement, group *emath.GqGroup) []emath.GqElement {
	l := zVec.Size()
	// [g^z_0, ..., g^z_{l-1}, gamma^z_0, ..., gamma^z_{l-1}]
	result := make([]emath.GqElement, 2*l)
	for i := 0; i < l; i++ {
		result[i] = g.Exponentiate(zVec.Get(i))
		result[l+i] = gamma.Exponentiate(zVec.Get(i))
	}
	return result
}

func buildDecryptionStatement(pk elgamal.PublicKey, ct elgamal.Ciphertext, msg elgamal.Message, l int) []emath.GqElement {
	// y = [pk_0, ..., pk_{l-1}, phi_0/m_0, ..., phi_{l-1}/m_{l-1}]
	statement := make([]emath.GqElement, 2*l)
	for i := 0; i < l; i++ {
		statement[i] = pk.Get(i)
		statement[l+i] = ct.GetPhi(i).Divide(msg.Get(i))
	}
	return statement
}

func decryptionChallenge(group *emath.GqGroup, gamma emath.GqElement, statement, commitments []emath.GqElement, ct elgamal.Ciphertext, msg elgamal.Message, zqGroup *emath.ZqGroup, auxInfo []hash.Hashable) emath.ZqElement {
	l := ct.Size()

	// f = (p, q, g, gamma)
	f := hash.HashableList{Elements: []hash.Hashable{
		hash.HashableBigInt{Value: group.P()},
		hash.HashableBigInt{Value: group.Q()},
		hash.HashableBigInt{Value: group.Generator().Value()},
		hash.HashableBigInt{Value: gamma.Value()},
	}}

	// y as HashableList
	yElems := make([]hash.Hashable, len(statement))
	for i, s := range statement {
		yElems[i] = hash.HashableBigInt{Value: s.Value()}
	}
	yHash := hash.HashableList{Elements: yElems}

	// c as HashableList
	cElems := make([]hash.Hashable, len(commitments))
	for i, c := range commitments {
		cElems[i] = hash.HashableBigInt{Value: c.Value()}
	}
	cHash := hash.HashableList{Elements: cElems}

	// h_aux: ["DecryptionProof", [phi_0,...], [m_0,...]] or with i_aux
	phiElems := make([]hash.Hashable, l)
	mElems := make([]hash.Hashable, l)
	for i := 0; i < l; i++ {
		phiElems[i] = hash.HashableBigInt{Value: ct.GetPhi(i).Value()}
		mElems[i] = hash.HashableBigInt{Value: msg.Get(i).Value()}
	}
	auxElements := []hash.Hashable{
		hash.HashableString{Value: "DecryptionProof"},
		hash.HashableList{Elements: phiElems},
		hash.HashableList{Elements: mElems},
	}
	if len(auxInfo) > 0 {
		auxElements = append(auxElements, auxInfo...)
	}
	hAux := hash.HashableList{Elements: auxElements}

	// Uniform Z_q challenge via oversample-then-reduce (Swiss Post spec).
	eVal := hash.RecursiveHashToZq(zqGroup.Q(), f, yHash, cHash, hAux)
	e, _ := emath.NewZqElement(eVal, zqGroup)
	return e
}
