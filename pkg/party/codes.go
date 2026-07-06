package party

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/hash"
	"github.com/user/evote/pkg/kdf"
	emath "github.com/user/evote/pkg/math"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
)

// Return-code share generation (the GenEncLongCodeShares exchange). The setup
// component asks each CC for its per-voter shares; each CC computes them from
// its PRIVATE return-code secret using deriveReturnCodeKey — the SINGLE key
// derivation used both here (card assembly) and later at vote-time extraction,
// which is what keeps the two consistent (this is the structural fix for the
// old setup/extraction derivation mismatch, finding F1).

const (
	MsgLongCodeShareReq  = "long-code-share-req" // setup -> CCj
	MsgLongCodeShareResp = "long-code-share-resp"
	MsgVotingCard        = "voting-card"   // setup -> voter (confidential)
	MsgMappingTable      = "mapping-table" // setup -> server (confidential)

	labelChoice  = "VoterChoiceReturnCodeGeneration"
	labelConfirm = "VoterVoteCastReturnCodeGeneration"
)

// deriveReturnCodeKey derives a CC's voter-specific return-code key from its
// secret. Used identically at setup and extraction time.
func deriveReturnCodeKey(secret emath.ZqElement, label, electionID, vcID string, group *emath.GqGroup) emath.ZqElement {
	zq := emath.ZqGroupFromGqGroup(group)
	info := kdf.BuildKDFInfo(label, electionID, vcID)
	kVal := kdf.KDFToZq(hash.IntegerToByteArray(secret.Value()), info, group.Q())
	k, _ := emath.NewZqElement(kVal, zq)
	return k
}

type longCodeShareReq struct {
	VcID       string   `json:"vc_id"`
	ElectionID string   `json:"election_id"`
	Primes     []string `json:"primes"` // decimal encodings of the encoding primes
}

type longCodeShareResp struct {
	ChoiceShares []string `json:"choice_shares"` // hpCC_i^{k_choice} per option
	ConfirmShare string   `json:"confirm_share"` // hCK^{k_confirm}
}

// handleLongCodeShare computes this CC's return-code shares for one voter.
func (p *ControlComponent) handleLongCodeShare(env *transport.Envelope) (*transport.Envelope, error) {
	var req longCodeShareReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group

	kChoice := deriveReturnCodeKey(p.st.returnCodeSecret, labelChoice, req.ElectionID, req.VcID, group)
	choiceShares := make([]string, len(req.Primes))
	for i, ps := range req.Primes {
		prime, ok := new(big.Int).SetString(ps, 10)
		if !ok {
			return nil, fmt.Errorf("cc%d: invalid prime %q", p.index, ps)
		}
		// Base is the encoding prime itself (a G_q element), NOT a hash of it:
		// this keeps the code base algebraic so the CCs can recompute prime^k
		// homomorphically from the submitted ciphertext at vote time
		// (cast-as-intended). The combined card code is prime_i^{Σ_j k_j}.
		base, err := emath.NewGqElement(prime, group)
		if err != nil {
			return nil, fmt.Errorf("cc%d: prime %d not in group: %w", p.index, i, err)
		}
		choiceShares[i] = base.Exponentiate(kChoice).Value().String()
	}

	// Confirmation-code share, keyed off a per-voter confirmation key.
	kConfirm := deriveReturnCodeKey(p.st.returnCodeSecret, labelConfirm, req.ElectionID, req.VcID, group)
	ckElem := confirmationKeyElement(req.VcID, group)
	hCK := hash.HashAndSquare(ckElem.Value(), group)
	confirmShare := hCK.Exponentiate(kConfirm).Value().String()

	return reply(p.id, env.From, MsgLongCodeShareResp, env.Nonce, longCodeShareResp{
		ChoiceShares: choiceShares,
		ConfirmShare: confirmShare,
	})
}

// RunCards assembles each voter's return-code card (collecting shares from the
// CCs) and distributes cards to voters and the mapping table to the voting
// server — both over CONFIDENTIAL (X25519-encrypted, Ed25519-signed) channels.
func (c *Ceremony) RunCards() error {
	cfg := c.Config
	c.Setup.st.mappingTable = returncodes.NewMappingTable()

	c.logf("  setup: generating %d voting cards from CC shares...", cfg.NumVoters)
	for v := 0; v < cfg.NumVoters; v++ {
		card, err := c.assembleVotingCard(v)
		if err != nil {
			return err
		}
		// Deliver the card plus the public election parameters the voter needs
		// to encrypt, confidentially.
		primeStrs := make([]string, len(c.Setup.st.primes))
		for i, p := range c.Setup.st.primes {
			primeStrs[i] = p.String()
		}
		delivery := cardDelivery{
			Card:         *card,
			ElectionPK:   encodePK(c.Setup.st.electionPK),
			ReturnCodePK: encodePK(c.Setup.st.returnCodePK),
			Primes:       primeStrs,
		}
		if _, err := c.sendConfidential(c.Setup.id, VoterName(v), MsgVotingCard, delivery); err != nil {
			return fmt.Errorf("deliver card to voter %d: %w", v, err)
		}
	}

	// Hand the mapping table and public election data to the voting server.
	rows := c.Setup.st.mappingTable.Export()
	primeStrs := make([]string, len(c.Setup.st.primes))
	for i, p := range c.Setup.st.primes {
		primeStrs[i] = p.String()
	}
	payload := mappingTablePayload{
		Rows:         rows,
		ElectionPK:   encodePK(c.Setup.st.electionPK),
		ReturnCodePK: encodePK(c.Setup.st.returnCodePK),
		Primes:       primeStrs,
	}
	if _, err := c.sendConfidential(c.Setup.id, NameServer, MsgMappingTable, payload); err != nil {
		return fmt.Errorf("deliver mapping table to server: %w", err)
	}
	c.logf("  setup: %d cards delivered to voters; mapping table delivered to server (all confidential)", cfg.NumVoters)
	return nil
}

type mappingTablePayload struct {
	Rows         []returncodes.MappingRow `json:"rows"`
	ElectionPK   wirePublicKey            `json:"election_pk"`
	ReturnCodePK wirePublicKey            `json:"return_code_pk"`
	Primes       []string                 `json:"primes"`
}

// cardDelivery is the confidential payload a voter receives: its private card
// plus the public election parameters it needs to encrypt a ballot.
type cardDelivery struct {
	Card         votingCard    `json:"card"`
	ElectionPK   wirePublicKey `json:"election_pk"`
	ReturnCodePK wirePublicKey `json:"return_code_pk"`
	Primes       []string      `json:"primes"`
}

// handleVotingCard (voter) receives and stores its confidential card + params.
func (p *VoterClient) handleVotingCard(env *transport.Envelope) (*transport.Envelope, error) {
	var d cardDelivery
	if err := p.cer.openConfidential(p.id, env, &d); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group
	pk, err := d.ElectionPK.decode(group)
	if err != nil {
		return nil, err
	}
	p.st.card = &d.Card
	p.st.electionPK = pk
	p.st.primes = make([]*big.Int, len(d.Primes))
	for i, ps := range d.Primes {
		v, ok := new(big.Int).SetString(ps, 10)
		if !ok {
			return nil, fmt.Errorf("voter: invalid prime %q", ps)
		}
		p.st.primes[i] = v
	}
	return reply(p.id, env.From, MsgAck, env.Nonce, ackPayload{Party: p.id.Name, OK: true})
}

// handleMappingTable (server) receives and stores the confidential mapping table
// and public election parameters.
func (p *VotingServer) handleMappingTable(env *transport.Envelope) (*transport.Envelope, error) {
	var payload mappingTablePayload
	if err := p.cer.openConfidential(p.id, env, &payload); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group
	p.st.mappingTable = returncodes.ImportMappingTable(payload.Rows)
	pk, err := payload.ElectionPK.decode(group)
	if err != nil {
		return nil, err
	}
	rcPK, err := payload.ReturnCodePK.decode(group)
	if err != nil {
		return nil, err
	}
	p.st.electionPK = pk
	p.st.returnCodePK = rcPK
	p.st.primes = make([]*big.Int, len(payload.Primes))
	for i, ps := range payload.Primes {
		v, ok := new(big.Int).SetString(ps, 10)
		if !ok {
			return nil, fmt.Errorf("server: invalid prime %q", ps)
		}
		p.st.primes[i] = v
	}
	return reply(p.id, env.From, MsgAck, env.Nonce, ackPayload{Party: p.id.Name, OK: true})
}

// confirmationKeyElement deterministically maps a voter id to a G_q element used
// as the confirmation key (as in the single-process version).
func confirmationKeyElement(vcID string, group *emath.GqGroup) emath.GqElement {
	seed := hash.RecursiveHashToZq(group.Q(),
		hash.HashableString{Value: "ConfirmationKey"},
		hash.HashableString{Value: vcID},
	)
	plusOne := new(big.Int).Add(seed, big.NewInt(1))
	elem, err := emath.GqElementFromSquareRoot(plusOne, group)
	if err != nil {
		// plusOne is in [1, q] by construction, so this cannot fail.
		panic("confirmation key element: " + err.Error())
	}
	return elem
}

// assembleVotingCard collects return-code shares from all CCs for one voter,
// combines them into the long code values, registers the (value -> short code)
// entries in the mapping table, and returns the voter's card.
func (c *Ceremony) assembleVotingCard(voterIdx int) (*votingCard, error) {
	cfg := c.Config
	group := cfg.Group
	vcID := fmt.Sprintf("vc-%04d", voterIdx)

	primeStrs := make([]string, len(c.Setup.st.primes))
	for i, p := range c.Setup.st.primes {
		primeStrs[i] = p.String()
	}

	// Collect combined choice shares across all CCs.
	choiceCombined := make([]emath.GqElement, cfg.NumOptions)
	for i := range choiceCombined {
		choiceCombined[i] = group.Identity()
	}
	confirmCombined := group.Identity()

	for j := 0; j < cfg.NumCCs; j++ {
		env, err := c.send(c.Setup.id, CCName(j), MsgLongCodeShareReq, longCodeShareReq{
			VcID: vcID, ElectionID: cfg.ElectionID, Primes: primeStrs,
		})
		if err != nil {
			return nil, fmt.Errorf("voter %d cc%d share: %w", voterIdx, j, err)
		}
		var resp longCodeShareResp
		if err := transport.UnmarshalPayload(env.Payload, &resp); err != nil {
			return nil, err
		}
		if len(resp.ChoiceShares) != cfg.NumOptions {
			return nil, fmt.Errorf("voter %d cc%d: %d shares, want %d", voterIdx, j, len(resp.ChoiceShares), cfg.NumOptions)
		}
		for i, ss := range resp.ChoiceShares {
			share, err := strToGq(ss, group) // validated group membership
			if err != nil {
				return nil, fmt.Errorf("voter %d cc%d share %d: %w", voterIdx, j, i, err)
			}
			choiceCombined[i] = choiceCombined[i].Multiply(share)
		}
		cShare, err := strToGq(resp.ConfirmShare, group)
		if err != nil {
			return nil, fmt.Errorf("voter %d cc%d confirm share: %w", voterIdx, j, err)
		}
		confirmCombined = confirmCombined.Multiply(cShare)
	}

	// Derive the short codes and register mapping-table entries.
	choiceCodes := make([]string, cfg.NumOptions)
	for i := 0; i < cfg.NumOptions; i++ {
		lCC := returncodes.ComputeLCCValue(choiceCombined[i], vcID, cfg.ElectionID, c.Setup.st.primes[i])
		short := fmt.Sprintf("CC-%02d", i)
		choiceCodes[i] = short
		c.Setup.st.mappingTable.Add(lCC, short)
	}
	lVCC := returncodes.ComputeLVCCValue(confirmCombined, vcID, cfg.ElectionID)
	vcc := fmt.Sprintf("VCC-%04d", voterIdx)
	c.Setup.st.mappingTable.Add(lVCC, vcc)

	return &votingCard{
		VoterID:            fmt.Sprintf("voter-%04d", voterIdx),
		VerificationCardID: vcID,
		StartVotingKey:     fmt.Sprintf("SVK-%04d", voterIdx),
		ChoiceReturnCodes:  choiceCodes,
		VoteConfirmCode:    vcc,
		BallotCastingKey:   fmt.Sprintf("BCK-%04d", voterIdx),
	}, nil
}
