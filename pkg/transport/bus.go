package transport

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
)

// Peer is the public identity information the directory holds for a party:
// its CA-verified certificate and the Ed25519/X25519 public keys bound by it.
type Peer struct {
	Name  string
	EdPub []byte
	XPub  []byte
	Cert  *x509.Certificate
}

// Directory maps party names to their verified public identities. A party is
// only added after its certificate chains to the trusted CA (verified in Rust).
type Directory struct {
	ca    *CA
	peers map[string]*Peer
}

// NewDirectory creates an empty directory anchored to a CA.
func NewDirectory(ca *CA) *Directory {
	return &Directory{ca: ca, peers: make(map[string]*Peer)}
}

// Register validates id's certificate against the CA and adds it. The XPub is
// carried alongside (it is not part of the Ed25519 cert, but is distributed
// through the same trusted enrollment step in this PoC).
func (d *Directory) Register(id *Identity) error {
	if err := d.ca.VerifyCertificate(id.Cert); err != nil {
		return fmt.Errorf("register %s: %w", id.Name, err)
	}
	if id.Cert.Subject.CommonName != id.Name {
		return fmt.Errorf("register %s: cert CN %q does not match name", id.Name, id.Cert.Subject.CommonName)
	}
	// Bind the Ed25519 public key from the (verified) certificate, not from the
	// identity struct, so a party cannot register a cert for one key while
	// signing with another.
	certPub, ok := id.Cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("register %s: certificate is not Ed25519", id.Name)
	}
	d.peers[id.Name] = &Peer{
		Name:  id.Name,
		EdPub: []byte(certPub),
		XPub:  id.XPub,
		Cert:  id.Cert,
	}
	return nil
}

// Lookup returns the peer for name, or an error if unknown.
func (d *Directory) Lookup(name string) (*Peer, error) {
	p, ok := d.peers[name]
	if !ok {
		return nil, fmt.Errorf("unknown party %q", name)
	}
	return p, nil
}

// Handler processes an inbound envelope and optionally returns a reply.
type Handler func(env *Envelope) (*Envelope, error)

// Bus is an in-process message router. It emulates the network between parties:
// every message it carries has its Ed25519 signature verified (in Rust) against
// the sender's directory entry before delivery, and replies are verified on the
// way back. This is where authenticity is enforced at the transport boundary.
type Bus struct {
	dir      *Directory
	handlers map[string]Handler
	Log      func(format string, args ...any)
	count    int
}

// NewBus creates a bus over a directory.
func NewBus(dir *Directory) *Bus {
	return &Bus{
		dir:      dir,
		handlers: make(map[string]Handler),
		Log:      func(string, ...any) {},
	}
}

// Handle registers the handler a party uses to receive messages addressed to it.
func (b *Bus) Handle(name string, h Handler) { b.handlers[name] = h }

// Count returns the number of verified messages carried so far.
func (b *Bus) Count() int { return b.count }

// Send verifies the request signature, delivers it to the recipient handler,
// then verifies the reply signature (if any) before returning it.
func (b *Bus) Send(env *Envelope) (*Envelope, error) {
	sender, err := b.dir.Lookup(env.From)
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	if err := env.Verify(sender.EdPub); err != nil {
		return nil, err
	}
	b.count++
	b.Log("  [transport] %s -> %s : %s (%d bytes, encrypted=%v) signature OK",
		env.From, env.To, env.Type, len(env.Payload), env.Encrypted)

	h, ok := b.handlers[env.To]
	if !ok {
		return nil, fmt.Errorf("send: no handler for %q", env.To)
	}
	reply, err := h(env)
	if err != nil {
		return nil, fmt.Errorf("handler %s: %w", env.To, err)
	}
	if reply != nil {
		replier, err := b.dir.Lookup(reply.From)
		if err != nil {
			return nil, fmt.Errorf("reply: %w", err)
		}
		if err := reply.Verify(replier.EdPub); err != nil {
			return nil, fmt.Errorf("reply verification: %w", err)
		}
		b.count++
	}
	return reply, nil
}
