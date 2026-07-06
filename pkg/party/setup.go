package party

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/hash"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/transport"
	"github.com/user/evote/pkg/zkp"
)

// Setup-phase message types.
const (
	MsgGenCCKeys = "gen-cc-keys" // setup -> CCj: generate election keys
	MsgCCKeys    = "cc-keys"     // CCj -> setup: PK + Schnorr proofs
	MsgGenEBKey  = "gen-eb-key"  // setup -> EB: generate board key
	MsgEBKey     = "eb-key"      // EB -> setup: PK
)

// --- payloads ---

type genCCKeysReq struct {
	ElectionID string `json:"election_id"`
	NumOptions int    `json:"num_options"`
	CCIndex    int    `json:"cc_index"`
}

type ccKeysResp struct {
	PK      wirePublicKey `json:"pk"`
	Schnorr []wireSchnorr `json:"schnorr"`
}

type genEBKeyReq struct {
	ElectionID string `json:"election_id"`
	NumOptions int    `json:"num_options"`
}

type ebKeyResp struct {
	PK wirePublicKey `json:"pk"`
}

// RunSetup executes the distributed key-generation part of the setup phase over
// the transport. Each CC and the EB generate their own key material privately;
// only public keys and proofs cross the bus. The setup component verifies every
// CC's Schnorr proof on receipt, combines the keys, and publishes the setup
// artifacts to the public transcript.
func (c *Ceremony) RunSetup() error {
	cfg := c.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)

	c.logf("\n--- SETUP PHASE (multi-party) ---")

	// 1. Encoding primes (public, computed by the setup component).
	raw := emath.SmallPrimes(cfg.NumOptions)
	c.Setup.st.primes = make([]*big.Int, cfg.NumOptions)
	for i, rp := range raw {
		sq := new(big.Int).Exp(rp, big.NewInt(2), group.P())
		if !group.IsGroupMember(sq) {
			return fmt.Errorf("encoding prime %d not a group member", i)
		}
		c.Setup.st.primes[i] = sq
	}

	// 2. Ask each CC to generate its election keys; verify the returned proofs.
	ccPKs := make([]elgamal.PublicKey, cfg.NumCCs)
	c.Transcript.CCElectionPKs = make([]elgamal.PublicKey, cfg.NumCCs)
	c.Transcript.CCSchnorr = make([][]zkp.SchnorrProof, cfg.NumCCs)

	for j := 0; j < cfg.NumCCs; j++ {
		env, err := c.send(c.Setup.id, CCName(j), MsgGenCCKeys, genCCKeysReq{
			ElectionID: cfg.ElectionID, NumOptions: cfg.NumOptions, CCIndex: j,
		})
		if err != nil {
			return fmt.Errorf("setup->cc%d keygen: %w", j, err)
		}
		var resp ccKeysResp
		if err := transport.UnmarshalPayload(env.Payload, &resp); err != nil {
			return err
		}
		pk, err := resp.PK.decode(group)
		if err != nil {
			return fmt.Errorf("cc%d pk: %w", j, err)
		}
		proofs := make([]zkp.SchnorrProof, len(resp.Schnorr))
		for i, ws := range resp.Schnorr {
			p, err := ws.decode(zq)
			if err != nil {
				return fmt.Errorf("cc%d schnorr %d: %w", j, i, err)
			}
			proofs[i] = p
		}
		// Verify each CC's proof of knowledge of its secret key (the setup
		// component does not trust the CC's word).
		if err := verifyCCSchnorr(cfg.ElectionID, group, j, pk, proofs); err != nil {
			return err
		}
		c.logf("  setup: cc%d keys received, %d Schnorr proofs VALID", j, len(proofs))

		ccPKs[j] = pk
		c.Transcript.CCElectionPKs[j] = pk
		c.Transcript.CCSchnorr[j] = proofs
	}

	// 3. Ask the electoral board to generate its key.
	env, err := c.send(c.Setup.id, NameEB, MsgGenEBKey, genEBKeyReq{
		ElectionID: cfg.ElectionID, NumOptions: cfg.NumOptions,
	})
	if err != nil {
		return fmt.Errorf("setup->eb keygen: %w", err)
	}
	var ebResp ebKeyResp
	if err := transport.UnmarshalPayload(env.Payload, &ebResp); err != nil {
		return err
	}
	ebPK, err := ebResp.PK.decode(group)
	if err != nil {
		return fmt.Errorf("eb pk: %w", err)
	}
	c.logf("  setup: electoral board key received")

	// 4. Combine keys.
	c.Setup.st.returnCodePK = elgamal.CombinePublicKeys(ccPKs...)
	c.Setup.st.electionPK = elgamal.CombinePublicKeys(append(append([]elgamal.PublicKey{}, ccPKs...), ebPK)...)

	// 5. Publish setup artifacts to the transcript.
	c.Transcript.ElectionID = cfg.ElectionID
	c.Transcript.EBPublicKey = ebPK
	c.Transcript.ElectionPK = c.Setup.st.electionPK
	c.Transcript.Primes = make([]string, len(c.Setup.st.primes))
	for i, p := range c.Setup.st.primes {
		c.Transcript.Primes[i] = p.String()
	}
	c.logf("  setup: election public key assembled and published to transcript")
	return nil
}

// verifyCCSchnorr checks that every key element's Schnorr proof is valid for the
// stated CC index (using the same aux binding as generation).
func verifyCCSchnorr(electionID string, group *emath.GqGroup, j int, pk elgamal.PublicKey, proofs []zkp.SchnorrProof) error {
	if len(proofs) != pk.Elements.Size() {
		return fmt.Errorf("cc%d: %d proofs for %d keys", j, len(proofs), pk.Elements.Size())
	}
	for i := 0; i < pk.Elements.Size(); i++ {
		aux := []hash.Hashable{
			hash.HashableBigInt{Value: big.NewInt(int64(i))},
			hash.HashableString{Value: electionID},
			hash.HashableBigInt{Value: big.NewInt(int64(j))},
		}
		if !zkp.VerifySchnorrProof(proofs[i], pk.Elements.Get(i), group, aux...) {
			return fmt.Errorf("cc%d key %d: Schnorr proof INVALID", j, i)
		}
	}
	return nil
}

// --- CC handler: generate election keys ---

func (p *ControlComponent) handleGenCCKeys(env *transport.Envelope) (*transport.Envelope, error) {
	var req genCCKeysReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	cfg := p.cer.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)

	kp := elgamal.GenKeyPair(group, req.NumOptions)
	proofs := make([]zkp.SchnorrProof, req.NumOptions)
	wireProofs := make([]wireSchnorr, req.NumOptions)
	for i := 0; i < req.NumOptions; i++ {
		aux := []hash.Hashable{
			hash.HashableBigInt{Value: big.NewInt(int64(i))},
			hash.HashableString{Value: req.ElectionID},
			hash.HashableBigInt{Value: big.NewInt(int64(req.CCIndex))},
		}
		proofs[i] = zkp.GenSchnorrProof(kp.SK.Get(i), kp.PK.Get(i), group, aux...)
		wireProofs[i] = encodeSchnorr(proofs[i])
	}

	// Store private key material; only the PK and proofs leave the CC.
	p.st.keyPair = kp
	p.st.returnCodeSecret = emath.RandomZqElement(zq)
	p.st.schnorrProofs = proofs

	return reply(p.id, env.From, MsgCCKeys, env.Nonce, ccKeysResp{
		PK:      encodePK(kp.PK),
		Schnorr: wireProofs,
	})
}

// --- EB handler: generate board key ---

func (p *ElectoralBoard) handleGenEBKey(env *transport.Envelope) (*transport.Envelope, error) {
	var req genEBKeyReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	cfg := p.cer.Config
	group := cfg.Group
	zq := emath.ZqGroupFromGqGroup(group)

	// EB key is derived from board passwords (as in the single-process version),
	// but the secret never leaves the EB.
	p.st.passwords = []string{"password1", "password2"}
	g := group.Generator()
	skElems := make([]emath.ZqElement, req.NumOptions)
	pkElems := make([]emath.GqElement, req.NumOptions)
	for i := 0; i < req.NumOptions; i++ {
		args := []hash.Hashable{
			hash.HashableString{Value: "ElectoralBoardSecretKey"},
			hash.HashableString{Value: req.ElectionID},
			hash.HashableBigInt{Value: big.NewInt(int64(i))},
		}
		for _, pw := range p.st.passwords {
			args = append(args, hash.HashableString{Value: pw})
		}
		skVal := hash.RecursiveHashToZq(group.Q(), args...)
		skElems[i], _ = emath.NewZqElement(skVal, zq)
		pkElems[i] = g.Exponentiate(skElems[i])
	}
	p.st.keyPair = elgamal.KeyPair{
		SK: elgamal.PrivateKey{Elements: emath.ZqVectorOf(skElems...)},
		PK: elgamal.PublicKey{Elements: emath.GqVectorOf(pkElems...)},
	}

	return reply(p.id, env.From, MsgEBKey, env.Nonce, ebKeyResp{PK: encodePK(p.st.keyPair.PK)})
}
