package party

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/mixnet"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
	"github.com/user/evote/pkg/zkp"
)

// Tally-phase message types.
const (
	MsgStartTally = "start-tally" // ceremony -> server: produce padded mix input
	MsgMixInput   = "mix-input"   // server -> ceremony: padded ciphertexts
	MsgShuffle    = "shuffle"     // ceremony -> CCj: shuffle + partial decrypt
	MsgShuffled   = "shuffled"    // CCj -> ceremony: partially decrypted ciphertexts
	MsgFinalMix   = "final-mix"   // ceremony -> EB: final shuffle + decrypt
	MsgFinalDone  = "final-done"  // EB -> ceremony
)

type mixInputPayload struct {
	Cts wireCiphertextVector `json:"cts"`
}

type shuffleReq struct {
	Stage int                  `json:"stage"` // CC index driving the remaining-key computation
	Cts   wireCiphertextVector `json:"cts"`
}

type shuffleResp struct {
	Cts wireCiphertextVector `json:"cts"` // partially decrypted ciphertexts
}

type finalResp struct {
	Result map[int]int `json:"result"`
}

// RunTally drives the mix-net: the server pads the ballot box and hands it to
// CC0; each CC shuffles + partially decrypts and passes the result to the next;
// the electoral board performs the final shuffle + decryption. Ciphertext
// handoffs travel over the signed transport (validated on decode); each party
// posts its shuffle and decryption proofs to the public transcript (the
// bulletin board), which the verifier re-checks in RunVerify.
func (c *Ceremony) RunTally() error {
	c.logf("\n--- TALLY PHASE (multi-party) ---")
	group := c.Config.Group

	// 1. Ask the server for the padded mix input.
	env, err := c.send(c.Verifier.id, NameServer, MsgStartTally, struct{}{})
	if err != nil {
		return fmt.Errorf("start tally: %w", err)
	}
	var mi mixInputPayload
	if err := transport.UnmarshalPayload(env.Payload, &mi); err != nil {
		return err
	}
	cts, err := mi.Cts.decode(group)
	if err != nil {
		return fmt.Errorf("mix input: %w", err)
	}
	c.Transcript.MixInput = cts
	c.Transcript.Shuffles = nil
	c.Transcript.PartialDecrypts = nil
	c.Transcript.DecryptProofs = nil
	c.logf("  tally: mixing %d ciphertexts through %d CCs + EB", cts.Size(), c.Config.NumCCs)

	// 2. Chain through the control components.
	for j := 0; j < c.Config.NumCCs; j++ {
		env, err := c.send(c.Verifier.id, CCName(j), MsgShuffle, shuffleReq{
			Stage: j, Cts: encodeCiphertextVector(cts),
		})
		if err != nil {
			return fmt.Errorf("cc%d shuffle: %w", j, err)
		}
		var resp shuffleResp
		if err := transport.UnmarshalPayload(env.Payload, &resp); err != nil {
			return err
		}
		cts, err = resp.Cts.decode(group)
		if err != nil {
			return fmt.Errorf("cc%d output: %w", j, err)
		}
		c.logf("  tally: cc%d shuffled + partially decrypted %d ciphertexts", j, cts.Size())
	}

	// 3. Electoral board: final shuffle + full decryption.
	env, err = c.send(c.Verifier.id, NameEB, MsgFinalMix, shuffleReq{Cts: encodeCiphertextVector(cts)})
	if err != nil {
		return fmt.Errorf("eb final mix: %w", err)
	}
	var fr finalResp
	if err := transport.UnmarshalPayload(env.Payload, &fr); err != nil {
		return err
	}
	c.Transcript.Result = fr.Result
	c.logf("  tally: electoral board decrypted final plaintexts; result posted to transcript")
	return nil
}

// handleStartTally (server) pads the ballot box to N>=2 and returns the mix
// input, persisting it so the verifier can check shuffle 0 against it.
func (p *VotingServer) handleStartTally(env *transport.Envelope) (*transport.Envelope, error) {
	group := p.cer.Config.Group
	zq := emath.ZqGroupFromGqGroup(group)

	cts := make([]elgamal.Ciphertext, len(p.st.ballotBox))
	for i, b := range p.st.ballotBox {
		cts[i] = b.Ciphertext
	}
	vec := elgamal.NewCiphertextVector(cts)
	for vec.Size() < 2 {
		trivial := elgamal.EncryptOnes(emath.RandomZqElement(zq), p.st.electionPK)
		vec = vec.Append(trivial)
	}
	return reply(p.id, env.From, MsgMixInput, env.Nonce, mixInputPayload{Cts: encodeCiphertextVector(vec)})
}

// handleShuffle (CC) shuffles + partially decrypts, posts proofs to the
// transcript, and returns the partially decrypted ciphertexts.
func (p *ControlComponent) handleShuffle(env *transport.Envelope) (*transport.Envelope, error) {
	var req shuffleReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	cfg := p.cer.Config
	group := cfg.Group
	in, err := req.Cts.decode(group)
	if err != nil {
		return nil, fmt.Errorf("cc%d shuffle input: %w", p.index, err)
	}

	// Remaining public key = CCs[stage..] + EB, read from the public transcript.
	remaining := remainingPK(p.cer.Transcript, req.Stage, cfg.NumCCs)

	vs := mixnet.GenVerifiableShuffle(in, remaining, group)

	// Partial decrypt with this CC's private key; produce decryption proofs.
	decrypted := make([]elgamal.Ciphertext, vs.ShuffledCiphertexts.Size())
	decProofs := make([]zkp.DecryptionProof, vs.ShuffledCiphertexts.Size())
	for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
		ct := vs.ShuffledCiphertexts.Get(i)
		decrypted[i] = elgamal.PartialDecrypt(ct, p.st.keyPair.SK)
		msg := elgamal.Decrypt(ct, p.st.keyPair.SK)
		decProofs[i] = zkp.GenDecryptionProof(ct, p.st.keyPair.SK, p.st.keyPair.PK, msg, group)
	}
	out := elgamal.NewCiphertextVector(decrypted)

	// Post proofs to the transcript (bulletin board).
	p.cer.Transcript.Shuffles = append(p.cer.Transcript.Shuffles, vs)
	p.cer.Transcript.PartialDecrypts = append(p.cer.Transcript.PartialDecrypts, out)
	p.cer.Transcript.DecryptProofs = append(p.cer.Transcript.DecryptProofs, decProofs)

	return reply(p.id, env.From, MsgShuffled, env.Nonce, shuffleResp{Cts: encodeCiphertextVector(out)})
}

// handleFinalMix (EB) performs the final shuffle and full decryption, posts the
// shuffle to the transcript, decodes plaintexts, and returns the tally.
func (p *ElectoralBoard) handleFinalMix(env *transport.Envelope) (*transport.Envelope, error) {
	var req shuffleReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	cfg := p.cer.Config
	group := cfg.Group
	in, err := req.Cts.decode(group)
	if err != nil {
		return nil, fmt.Errorf("eb final input: %w", err)
	}

	vs := mixnet.GenVerifiableShuffle(in, p.st.keyPair.PK, group)
	p.cer.Transcript.Shuffles = append(p.cer.Transcript.Shuffles, vs)

	// Full decryption and decode.
	plaintexts := make([]*emath.GqVector, vs.ShuffledCiphertexts.Size())
	result := make(map[int]int)
	primes := transcriptPrimes(p.cer.Transcript)
	for i := 0; i < vs.ShuffledCiphertexts.Size(); i++ {
		msg := elgamal.Decrypt(vs.ShuffledCiphertexts.Get(i), p.st.keyPair.SK)
		plaintexts[i] = msg.Elements
		first := msg.Get(0)
		if first.IsIdentity() {
			continue // padding ciphertext
		}
		selected, err := returncodes.DecodeVoteChecked(first.Value(), primes)
		if err != nil {
			// A ballot that does not decode is counted as spoiled, not fatal.
			continue
		}
		for _, opt := range selected {
			result[opt]++
		}
	}
	p.cer.Transcript.FinalPlaintexts = plaintexts

	return reply(p.id, env.From, MsgFinalDone, env.Nonce, finalResp{Result: result})
}

// remainingPK combines CCs[stage..NumCCs) + EB public keys from the transcript.
func remainingPK(tr *PublicTranscript, stage, numCCs int) elgamal.PublicKey {
	pks := make([]elgamal.PublicKey, 0, numCCs-stage+1)
	for k := stage; k < numCCs; k++ {
		pks = append(pks, tr.CCElectionPKs[k])
	}
	pks = append(pks, tr.EBPublicKey)
	return elgamal.CombinePublicKeys(pks...)
}

func transcriptPrimes(tr *PublicTranscript) []*big.Int {
	out := make([]*big.Int, len(tr.Primes))
	for i, s := range tr.Primes {
		out[i], _ = new(big.Int).SetString(s, 10)
	}
	return out
}
