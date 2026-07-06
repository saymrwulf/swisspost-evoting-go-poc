// Package party implements the multi-party e-voting ceremony. Each party
// (setup component, four control components, electoral board, voting server,
// voter clients, verifier) is a distinct endpoint holding only its own private
// state; all data that crosses between parties travels as Ed25519-signed
// envelopes over the transport bus (pkg/transport), with the signature and key
// agreement performed in Rust (pkg/transportsec).
//
// This mirrors the Swiss Post trust structure without emulating its scale: the
// point is the trust boundaries and their transport security, not throughput.
package party

import (
	"fmt"

	"github.com/user/evote/pkg/protocol"
	"github.com/user/evote/pkg/transport"
)

// Party name constants used as transport addresses and certificate CNs.
const (
	NameSetup    = "setup-component"
	NameEB       = "electoral-board"
	NameServer   = "voting-server"
	NameVerifier = "verifier"
)

// CCName returns the transport name of control component j.
func CCName(j int) string { return fmt.Sprintf("control-component-%d", j) }

// VoterName returns the transport name of voter v.
func VoterName(v int) string { return fmt.Sprintf("voter-%04d", v) }

// Ceremony wires the parties, the PKI, and the bus together.
type Ceremony struct {
	Config *protocol.Config

	CA  *transport.CA
	Dir *transport.Directory
	Bus *transport.Bus

	Setup    *SetupComponent
	CCs      []*ControlComponent
	EB       *ElectoralBoard
	Server   *VotingServer
	Voters   []*VoterClient
	Verifier *VerifierParty

	Transcript *PublicTranscript

	logf func(string, ...any)
}

// NewCeremony bootstraps the PKI and every party identity, registering each in
// the CA-anchored directory and wiring its handler into the bus. It does not run
// the election — call RunSetup/RunVoting/RunTally/RunVerify (added incrementally).
func NewCeremony(cfg *protocol.Config, logf func(string, ...any)) (*Ceremony, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	c := &Ceremony{Config: cfg, logf: logf}

	// 1. Root CA (Ed25519, Rust-signed).
	ca, err := transport.NewCA("evote-root-ca")
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}
	c.CA = ca
	c.Dir = transport.NewDirectory(ca)
	c.Bus = transport.NewBus(c.Dir)
	c.Bus.Log = func(format string, args ...any) { c.logf(format, args...) }

	// 2. Enroll every party: issue an Ed25519 identity cert and register it.
	enroll := func(name string) (*transport.Identity, error) {
		id, err := ca.Issue(name)
		if err != nil {
			return nil, err
		}
		if err := c.Dir.Register(id); err != nil {
			return nil, err
		}
		return id, nil
	}

	setupID, err := enroll(NameSetup)
	if err != nil {
		return nil, err
	}
	c.Setup = &SetupComponent{id: setupID, cer: c}

	c.CCs = make([]*ControlComponent, cfg.NumCCs)
	for j := 0; j < cfg.NumCCs; j++ {
		id, err := enroll(CCName(j))
		if err != nil {
			return nil, err
		}
		c.CCs[j] = &ControlComponent{index: j, id: id, cer: c}
	}

	ebID, err := enroll(NameEB)
	if err != nil {
		return nil, err
	}
	c.EB = &ElectoralBoard{id: ebID, cer: c}

	serverID, err := enroll(NameServer)
	if err != nil {
		return nil, err
	}
	c.Server = &VotingServer{id: serverID, cer: c}

	verID, err := enroll(NameVerifier)
	if err != nil {
		return nil, err
	}
	c.Verifier = &VerifierParty{id: verID, cer: c}

	c.Voters = make([]*VoterClient, cfg.NumVoters)
	for v := 0; v < cfg.NumVoters; v++ {
		id, err := enroll(VoterName(v))
		if err != nil {
			return nil, err
		}
		c.Voters[v] = &VoterClient{index: v, id: id, cer: c}
	}

	// 3. Register message handlers on the bus.
	c.Bus.Handle(NameSetup, c.Setup.handle)
	for _, cc := range c.CCs {
		c.Bus.Handle(cc.id.Name, cc.handle)
	}
	c.Bus.Handle(NameEB, c.EB.handle)
	c.Bus.Handle(NameServer, c.Server.handle)
	c.Bus.Handle(NameVerifier, c.Verifier.handle)
	for _, v := range c.Voters {
		c.Bus.Handle(v.id.Name, v.handle)
	}

	c.Transcript = &PublicTranscript{}
	return c, nil
}

// send is a helper the parties use to sign and dispatch a typed message,
// returning the (verified) reply payload.
func (c *Ceremony) send(from *transport.Identity, to, msgType string, payload any) (*transport.Envelope, error) {
	data, err := transport.MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	env := &transport.Envelope{From: from.Name, To: to, Type: msgType, Nonce: c.nextNonce(), Payload: data}
	if err := env.Seal(from); err != nil {
		return nil, err
	}
	return c.Bus.Send(env)
}

var globalNonce uint64

func (c *Ceremony) nextNonce() uint64 { globalNonce++; return globalNonce }

// sendConfidential signs AND encrypts a message: the payload is sealed under an
// X25519-derived session key (AES-256-GCM) before the envelope is Ed25519-signed.
// This gives both confidentiality (channel) and authenticity (signature).
func (c *Ceremony) sendConfidential(from *transport.Identity, to, msgType string, payload any) (*transport.Envelope, error) {
	peer, err := c.Dir.Lookup(to)
	if err != nil {
		return nil, err
	}
	ch, err := from.NewSecureChannel(to, peer.XPub)
	if err != nil {
		return nil, err
	}
	plain, err := transport.MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	sealed, err := ch.EncryptPayload(plain, []byte(msgType))
	if err != nil {
		return nil, err
	}
	env := &transport.Envelope{From: from.Name, To: to, Type: msgType, Nonce: c.nextNonce(), Encrypted: true, Payload: sealed}
	if err := env.Seal(from); err != nil {
		return nil, err
	}
	return c.Bus.Send(env)
}

// openConfidential decrypts an encrypted envelope addressed to the local party.
func (c *Ceremony) openConfidential(local *transport.Identity, env *transport.Envelope, v any) error {
	peer, err := c.Dir.Lookup(env.From)
	if err != nil {
		return err
	}
	ch, err := local.NewSecureChannel(env.From, peer.XPub)
	if err != nil {
		return err
	}
	plain, err := ch.DecryptPayload(env.Payload, []byte(env.Type))
	if err != nil {
		return fmt.Errorf("decrypt %s->%s: %w", env.From, env.To, err)
	}
	return transport.UnmarshalPayload(plain, v)
}
