package transport

import (
	"bytes"
	"testing"
)

func newTestPKI(t *testing.T, names ...string) (*CA, *Directory, map[string]*Identity) {
	t.Helper()
	serials := &serialCounter{}
	ca, err := NewCA("evote-root-ca", serials)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	dir := NewDirectory(ca)
	ids := make(map[string]*Identity)
	for _, n := range names {
		id, err := ca.Issue(n, serials)
		if err != nil {
			t.Fatalf("issue %s: %v", n, err)
		}
		if err := dir.Register(id); err != nil {
			t.Fatalf("register %s: %v", n, err)
		}
		ids[n] = id
	}
	return ca, dir, ids
}

func TestCertificateChainVerifies(t *testing.T) {
	ca, _, ids := newTestPKI(t, "cc0")
	if err := ca.VerifyCertificate(ids["cc0"].Cert); err != nil {
		t.Fatalf("issued cert should verify: %v", err)
	}
	// A cert from a different CA must not verify against this one.
	serials := &serialCounter{}
	other, _ := NewCA("evil-ca", serials)
	forged, _ := other.Issue("cc0", serials)
	if err := ca.VerifyCertificate(forged.Cert); err == nil {
		t.Fatal("cert from foreign CA must not verify")
	}
}

func TestEnvelopeSignVerifyRoundTrip(t *testing.T) {
	_, dir, ids := newTestPKI(t, "server", "cc1")
	env := &Envelope{From: "server", To: "cc1", Type: "ballot", Nonce: 1, Payload: []byte("hello cc1")}
	if err := env.Seal(ids["server"]); err != nil {
		t.Fatalf("seal: %v", err)
	}
	peer, _ := dir.Lookup("server")
	if err := env.Verify(peer.EdPub); err != nil {
		t.Fatalf("honest envelope rejected: %v", err)
	}
	// Tamper the payload → signature must fail.
	env.Payload = []byte("hello attacker")
	if err := env.Verify(peer.EdPub); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestBusRejectsForgedSender(t *testing.T) {
	_, dir, ids := newTestPKI(t, "server", "cc1")
	bus := NewBus(dir)
	bus.Handle("cc1", func(env *Envelope) (*Envelope, error) { return nil, nil })

	// Envelope claims to be from "server" but is signed by cc1's key.
	env := &Envelope{From: "server", To: "cc1", Type: "spoof", Nonce: 1, Payload: []byte("x")}
	if err := env.Seal(ids["cc1"]); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := bus.Send(env); err == nil {
		t.Fatal("bus accepted a message signed by the wrong party")
	}
}

func TestSecureChannelRoundTrip(t *testing.T) {
	_, _, ids := newTestPKI(t, "cc0", "cc1")
	ch01, err := ids["cc0"].NewSecureChannel("cc1", ids["cc1"].XPub)
	if err != nil {
		t.Fatalf("channel cc0->cc1: %v", err)
	}
	ch10, err := ids["cc1"].NewSecureChannel("cc0", ids["cc0"].XPub)
	if err != nil {
		t.Fatalf("channel cc1->cc0: %v", err)
	}

	msg := []byte("partial decryption shares")
	ad := []byte("stage-2")
	sealed, err := ch01.EncryptPayload(msg, ad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	opened, err := ch10.DecryptPayload(sealed, ad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatal("secure channel round-trip mismatch")
	}
	// Wrong associated data must fail authentication.
	if _, err := ch10.DecryptPayload(sealed, []byte("stage-3")); err == nil {
		t.Fatal("decryption succeeded under wrong associated data")
	}
}
