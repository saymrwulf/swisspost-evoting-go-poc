package party

import (
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/elgamal"
	"github.com/user/evote/pkg/returncodes"
	"github.com/user/evote/pkg/transport"
)

// Return-code extraction message types.
const (
	MsgRCExpReq  = "rc-exp-req" // server -> CCj: exponentiate E2 by k_j
	MsgRCExpResp = "rc-exp-resp"
	MsgRCDecReq  = "rc-dec-req" // server -> CCj: partial-decrypt factor
	MsgRCDecResp = "rc-dec-resp"
)

// tauFixed is the option-independent tau fed to ComputeLCCValue at both card
// generation and vote-time extraction (see codes.go for why it is fixed).
var tauFixed = big.NewInt(1)

type rcExpReq struct {
	VcID string         `json:"vc_id"`
	E2   wireCiphertext `json:"e2"`
}
type rcExpResp struct {
	Exp wireCiphertext `json:"exp"` // E2^{k_j}
}

type rcDecReq struct {
	Gamma string `json:"gamma"` // gamma of the combined exponentiated ciphertext
}
type rcDecResp struct {
	Factor string `json:"factor"` // gamma^{sk_j[0]}
}

// extractChoiceReturnCode (server) recovers the voter's return code from E2 by
// asking each CC to exponentiate E2 by its return-code key and to contribute a
// partial-decryption factor, then combining and looking the value up in the
// mapping table. The value recovered is vote^{Σk_j}, which equals the card base
// prime_sel^{Σk_j} — so the code returned is the code for the ACTUALLY SUBMITTED
// vote (cast-as-intended). Returns the short code, or "" if no match.
func (p *VotingServer) extractChoiceReturnCode(vcID string, e2 elgamal.Ciphertext) (string, error) {
	group := p.cer.Config.Group

	// Phase 1: each CC exponentiates E2 by its return-code key; product over CCs
	// yields Enc(vote^{Σk}, ·, returnCodesPK).
	var combined elgamal.Ciphertext
	for j := 0; j < p.cer.Config.NumCCs; j++ {
		env, err := p.cer.send(p.id, CCName(j), MsgRCExpReq, rcExpReq{VcID: vcID, E2: encodeCiphertext(e2)})
		if err != nil {
			return "", fmt.Errorf("rc-exp cc%d: %w", j, err)
		}
		var resp rcExpResp
		if err := transport.UnmarshalPayload(env.Payload, &resp); err != nil {
			return "", err
		}
		expCt, err := resp.Exp.decode(group)
		if err != nil {
			return "", fmt.Errorf("rc-exp cc%d decode: %w", j, err)
		}
		if j == 0 {
			combined = expCt
		} else {
			combined = combined.Multiply(expCt)
		}
	}

	// Phase 2: each CC contributes gamma^{sk_j[0]}; product is the decryption
	// mask returnCodesPK^{R}. vote^{Σk} = phi / mask.
	mask := group.Identity()
	for j := 0; j < p.cer.Config.NumCCs; j++ {
		env, err := p.cer.send(p.id, CCName(j), MsgRCDecReq, rcDecReq{Gamma: combined.Gamma.Value().String()})
		if err != nil {
			return "", fmt.Errorf("rc-dec cc%d: %w", j, err)
		}
		var resp rcDecResp
		if err := transport.UnmarshalPayload(env.Payload, &resp); err != nil {
			return "", err
		}
		factor, err := strToGq(resp.Factor, group)
		if err != nil {
			return "", fmt.Errorf("rc-dec cc%d decode: %w", j, err)
		}
		mask = mask.Multiply(factor)
	}
	voteToK := combined.GetPhi(0).Divide(mask)

	// Look up the recovered value in the mapping table.
	lCC := returncodes.ComputeLCCValue(voteToK, vcID, p.cer.Config.ElectionID, tauFixed)
	code, err := p.st.mappingTable.Lookup(lCC)
	if err != nil {
		return "", nil // no match (e.g. spoiled) — not an error
	}
	return code, nil
}

// handleRCExp (CC) exponentiates E2 by this CC's return-code key k_j.
func (p *ControlComponent) handleRCExp(env *transport.Envelope) (*transport.Envelope, error) {
	var req rcExpReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group
	e2, err := req.E2.decode(group)
	if err != nil {
		return nil, fmt.Errorf("cc%d rc-exp: %w", p.index, err)
	}
	k := deriveReturnCodeKey(p.st.returnCodeSecret, labelChoice, p.cer.Config.ElectionID, req.VcID, group)
	return reply(p.id, env.From, MsgRCExpResp, env.Nonce, rcExpResp{Exp: encodeCiphertext(e2.Exponentiate(k))})
}

// handleRCDec (CC) returns gamma^{sk_j[0]}, its factor of the decryption mask.
func (p *ControlComponent) handleRCDec(env *transport.Envelope) (*transport.Envelope, error) {
	var req rcDecReq
	if err := transport.UnmarshalPayload(env.Payload, &req); err != nil {
		return nil, err
	}
	group := p.cer.Config.Group
	gamma, err := strToGq(req.Gamma, group)
	if err != nil {
		return nil, fmt.Errorf("cc%d rc-dec: %w", p.index, err)
	}
	factor := gamma.Exponentiate(p.st.keyPair.SK.Get(0))
	return reply(p.id, env.From, MsgRCDecResp, env.Nonce, rcDecResp{Factor: factor.Value().String()})
}
