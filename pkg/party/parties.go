package party

import (
	"fmt"

	"github.com/user/evote/pkg/transport"
)

// Message type constants exchanged over the bus.
const (
	MsgHello = "hello" // enrollment handshake
	MsgAck   = "ack"
)

// reply is a small helper for a party to build a signed reply envelope.
func reply(from *transport.Identity, to, msgType string, nonce uint64, payload any) (*transport.Envelope, error) {
	data, err := transport.MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	env := &transport.Envelope{From: from.Name, To: to, Type: msgType, Nonce: nonce, Payload: data}
	if err := env.Seal(from); err != nil {
		return nil, err
	}
	return env, nil
}

// ackPayload is returned by every party's hello handler.
type ackPayload struct {
	Party string `json:"party"`
	OK    bool   `json:"ok"`
}

// handleHello is the shared handshake handler: any party acknowledges a hello.
func handleHello(id *transport.Identity, env *transport.Envelope) (*transport.Envelope, error) {
	if env.Type != MsgHello {
		return nil, fmt.Errorf("%s: unexpected message type %q", id.Name, env.Type)
	}
	return reply(id, env.From, MsgAck, env.Nonce, ackPayload{Party: id.Name, OK: true})
}

// SetupComponent is the SDM analog: it generates election parameters and
// assembles voting cards and the return-codes mapping table.
type SetupComponent struct {
	id  *transport.Identity
	cer *Ceremony
	st  setupState
}

func (p *SetupComponent) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	default:
		return p.handleSetupMsg(env)
	}
}

// ControlComponent is one of the split-trust CCs.
type ControlComponent struct {
	index int
	id    *transport.Identity
	cer   *Ceremony
	st    ccState
}

func (p *ControlComponent) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	default:
		return p.handleCCMsg(env)
	}
}

// ElectoralBoard performs the final (offline) shuffle and decryption.
type ElectoralBoard struct {
	id  *transport.Identity
	cer *Ceremony
	st  ebState
}

func (p *ElectoralBoard) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	default:
		return p.handleEBMsg(env)
	}
}

// VotingServer receives ballots and drives return-code extraction and tally.
type VotingServer struct {
	id  *transport.Identity
	cer *Ceremony
	st  serverState
}

func (p *VotingServer) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	default:
		return p.handleServerMsg(env)
	}
}

// VoterClient encrypts a ballot and checks return codes.
type VoterClient struct {
	index int
	id    *transport.Identity
	cer   *Ceremony
	st    voterState
}

func (p *VoterClient) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	case MsgVotingCard:
		return p.handleVotingCard(env)
	default:
		return nil, fmt.Errorf("%s: unexpected message type %q", p.id.Name, env.Type)
	}
}

// VerifierParty independently re-checks the public transcript.
type VerifierParty struct {
	id  *transport.Identity
	cer *Ceremony
}

func (p *VerifierParty) handle(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgHello:
		return handleHello(p.id, env)
	default:
		return nil, fmt.Errorf("%s: unexpected message type %q", p.id.Name, env.Type)
	}
}

// Handshake sends a signed hello to every enrolled party and verifies the acks.
// It proves the full sign → route → verify → reply → verify path works for all
// party types before any election logic runs.
func (c *Ceremony) Handshake() error {
	targets := []string{NameSetup, NameEB, NameServer, NameVerifier}
	for _, cc := range c.CCs {
		targets = append(targets, cc.id.Name)
	}
	for _, v := range c.Voters {
		targets = append(targets, v.id.Name)
	}
	for _, to := range targets {
		env, err := c.send(c.Setup.id, to, MsgHello, nil)
		if err != nil {
			return fmt.Errorf("handshake to %s: %w", to, err)
		}
		var ack ackPayload
		if err := transport.UnmarshalPayload(env.Payload, &ack); err != nil {
			return err
		}
		if !ack.OK || ack.Party != to {
			return fmt.Errorf("handshake to %s: bad ack %+v", to, ack)
		}
	}
	c.logf("  [ceremony] handshake OK: %d parties enrolled and reachable", len(targets)+1)
	return nil
}
