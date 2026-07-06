// Package transport provides the authenticated, confidential message-passing
// layer that connects the separate parties of the e-voting system (setup
// component, control components, electoral board, voting server, voter clients,
// verifier).
//
// Every inter-party message is Ed25519-signed and every confidential channel is
// keyed by X25519 ECDH — both implemented in Rust (pkg/transportsec). Party
// identities are X.509 certificates signed by a root CA using Ed25519 (no RSA,
// no RSA CA signatures). The Ed25519 signing under CreateCertificate and all
// certificate-signature verification are routed through the Rust library via a
// crypto.Signer shim, so no signature is ever produced or checked by Go.
package transport

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/user/evote/pkg/transportsec"
)

// rustSigner is a crypto.Signer whose Ed25519 signing is performed in Rust.
// It lets crypto/x509.CreateCertificate emit certificates whose signature bytes
// are produced by transportsec (ed25519-dalek), not by Go's crypto/ed25519.
type rustSigner struct {
	seed []byte // 32-byte Ed25519 seed
	pub  ed25519.PublicKey
}

func (s rustSigner) Public() crypto.PublicKey { return s.pub }

// Sign ignores the (already-hashed=identity) opts as required for Ed25519 and
// signs the message directly through Rust.
func (s rustSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return transportsec.Ed25519Sign(s.seed, message)
}

// Identity is a party's cryptographic identity: an Ed25519 signing key (for
// message and certificate signatures), an X25519 key (for ECDH channel keys),
// and an X.509 certificate binding the party name to its Ed25519 public key.
type Identity struct {
	Name string

	edSeed []byte // 32-byte Ed25519 seed (private)
	EdPub  []byte // 32-byte Ed25519 public key

	xPriv []byte // 32-byte X25519 private scalar
	XPub  []byte // 32-byte X25519 public key

	Cert    *x509.Certificate
	CertDER []byte
}

// SigningSeed exposes the Ed25519 seed to same-package channel/envelope code.
func (id *Identity) SigningSeed() []byte { return id.edSeed }

// ECDHPrivate exposes the X25519 scalar to same-package channel code.
func (id *Identity) ECDHPrivate() []byte { return id.xPriv }

// CA is a minimal root certificate authority that issues Ed25519 identity
// certificates. Its own signing key is Rust-backed. It owns a serial counter so
// certificate serials are deterministic (crypto/rand serials would make runs
// non-reproducible; a counter suffices for a single-CA PoC).
type CA struct {
	signer  rustSigner
	Cert    *x509.Certificate
	CertDER []byte
	serials serialCounter
}

// serialCounter deterministically supplies certificate serial numbers.
type serialCounter struct{ n int64 }

func (c *serialCounter) next() *big.Int { c.n++; return big.NewInt(c.n) }

// fixedNotBefore/After bound certificate validity. The values are fixed so
// ceremonies are reproducible; time.Now is avoided deliberately.
var (
	fixedNotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedNotAfter  = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// NewCA creates a self-signed Ed25519 root CA named name.
func NewCA(name string) (*CA, error) {
	seed, pub, err := transportsec.Ed25519GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("CA keygen: %w", err)
	}
	signer := rustSigner{seed: seed, pub: ed25519.PublicKey(pub)}
	ca := &CA{signer: signer}

	tmpl := &x509.Certificate{
		SerialNumber:          ca.serials.next(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             fixedNotBefore,
		NotAfter:              fixedNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	// Self-signed: parent == template, public key is the CA's own Ed25519 key,
	// signer is the Rust-backed CA signer.
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, signer.pub, signer)
	if err != nil {
		return nil, fmt.Errorf("CA self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("CA parse: %w", err)
	}
	ca.Cert = cert
	ca.CertDER = der
	return ca, nil
}

// Issue creates an Identity for a party, with an Ed25519 cert signed by the CA.
func (ca *CA) Issue(name string) (*Identity, error) {
	edSeed, edPub, err := transportsec.Ed25519GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("%s ed keygen: %w", name, err)
	}
	xPriv, xPub, err := transportsec.X25519GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("%s x keygen: %w", name, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: ca.serials.next(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    fixedNotBefore,
		NotAfter:     fixedNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// Subject public key is the party's Ed25519 key; the signature is produced
	// by the CA's Rust-backed signer.
	der, err := x509.CreateCertificate(nil, tmpl, ca.Cert, ed25519.PublicKey(edPub), ca.signer)
	if err != nil {
		return nil, fmt.Errorf("%s cert sign: %w", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%s cert parse: %w", name, err)
	}

	return &Identity{
		Name:    name,
		edSeed:  edSeed,
		EdPub:   edPub,
		xPriv:   xPriv,
		XPub:    xPub,
		Cert:    cert,
		CertDER: der,
	}, nil
}

// VerifyCertificate checks that cert was signed by the CA, with the Ed25519
// signature verified in Rust rather than by Go's x509 internals.
func (ca *CA) VerifyCertificate(cert *x509.Certificate) error {
	return verifyCertSignature(cert, ca.Cert.PublicKey.(ed25519.PublicKey))
}

// verifyCertSignature verifies an X.509 certificate's Ed25519 signature over its
// TBS bytes using the Rust verifier.
func verifyCertSignature(cert *x509.Certificate, caPub ed25519.PublicKey) error {
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("unexpected signature algorithm %v (want Ed25519)", cert.SignatureAlgorithm)
	}
	if err := transportsec.Ed25519Verify(caPub, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("certificate signature invalid: %w", err)
	}
	return nil
}

// PEM renders a certificate as PEM (for logging/inspection).
func PEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
