# Multi-Party Architecture

This PoC emulates the Swiss Post e-voting system's **trust structure**: the
parties that in production run on separate machines under separate operators are
modeled here as separate in-process endpoints that communicate **only** through
an authenticated, confidential transport. No party reaches into another's
private state; every inter-party message is Ed25519-signed and verified, and
confidential channels are keyed by X25519 ECDH — all of that cryptography
implemented in **Rust** (`pkg/transportsec` → `rust/transportsec`).

Scalability is explicitly out of scope (it remains a single-binary PoC). What is
in scope is **full cryptographic emulation of the trust boundaries**.

## Parties

| Party | Role | Private state (never leaves the party) |
|-------|------|----------------------------------------|
| **Setup component** (SDM analog) | Generates election parameters, assembles voting cards and the return-codes mapping table | election-event seed, assembled card secrets |
| **CC0–CC3** (4 control components) | Split-trust key generation; ballot proof checks; mix-net shuffle + partial decryption | each CC's ElGamal secret key, return-code secret, shuffle permutation & randomness |
| **Electoral Board** (offline) | Final shuffle and decryption on the air-gapped side | EB secret key, board passwords |
| **Voting server / ballot box** | Receives ballots, drives return-code extraction, stores the ballot box | mapping table, ballot box contents |
| **Voter client** | Encrypts the ballot, produces ballot proofs, checks return codes | card secrets, encryption randomness, `vcSK` |
| **Verifier / auditor** | Independently re-checks the entire public transcript | nothing — public data only |

## Transport security (all crypto in Rust)

```
             ┌──────────────── Ed25519 root CA (Rust-signed X.509) ───────────────┐
             │                                                                     │
      issues identity certs (Ed25519, no RSA) binding party name → Ed25519 pubkey  │
             │                                                                     │
   ┌─────────▼──────────┐   signed Envelope    ┌──────────▼─────────┐
   │  Party A (Identity)│ ───────────────────▶ │  Party B (Identity)│
   │  Ed25519 seed      │  Ed25519 sig (Rust)  │  verifies sig (Rust)│
   │  X25519 keypair    │ ◀─────────────────── │                    │
   └────────────────────┘   secure channel     └────────────────────┘
                         X25519 ECDH (Rust) → AES-256-GCM payloads
```

- **Identity** (`pkg/transport/identity.go`): each party holds an Ed25519 signing
  key, an X25519 ECDH key, and an X.509 certificate. The CA signs certificates
  through a `crypto.Signer` shim whose `Sign` calls the Rust Ed25519 — so even
  `x509.CreateCertificate`'s signature bytes come from Rust. Certificate
  verification extracts the TBS bytes and calls the Rust verifier (never Go's
  x509 internals).
- **Envelope** (`envelope.go`): a signed message `{from,to,type,nonce,payload}`.
  The signature covers an injective length-prefixed encoding of all fields.
- **SecureChannel** (`channel.go`): X25519 ECDH shared secret → session key →
  AES-256-GCM. Used where a payload must be confidential, not just authentic.
- **Directory + Bus** (`bus.go`): the directory admits a party only after its
  cert chains to the CA, binding the name to the cert's Ed25519 key. The bus
  routes envelopes and verifies every message's signature (request and reply)
  before delivery — this is where authenticity is enforced at the boundary.

## Why EdDSA / ECDH instead of the production RSA

The production system uses RSASSA-PSS signatures and RSA-based channel security.
This PoC deliberately substitutes an **elliptic-curve stack** — Ed25519 for
signatures, X25519 for key agreement — with **no RSA anywhere**, including the
X.509 CA. This is a design choice for the PoC, not a claim about the production
system.

## Message inventory (implemented incrementally)

Setup: CC key shares + Schnorr proofs → setup; setup → voter (card), → server
(mapping table), → all (signed election config). Voting: voter → server (ballot);
server → CCj (proof check); server ↔ CCj (return-code shares). Tally: server →
CC0 (ballot box); CCj → CCj+1 (shuffle + partial decryption + proofs); CC3 → EB;
EB → bulletin board (result + final proof). Audit: bulletin board → verifier
(public transcript).

## Deferred trust-boundary hardening folded in here

Findings from the due-diligence pass that only matter once inputs are remote are
addressed as parties are split: verifiers return errors instead of panicking on
malformed peer input, group elements/proofs are re-validated on receipt, and the
artifacts a remote verifier needs (padded mix input, per-stage decryption proofs,
`vcPK`) are persisted into a serializable public transcript.
