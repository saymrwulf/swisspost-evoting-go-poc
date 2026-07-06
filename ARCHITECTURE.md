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

## Message flow (implemented)

Run it with `evote netdemo --verbose` to watch every signed envelope.

- **Setup** — `setup → CCj: gen-cc-keys`; `CCj → setup: cc-keys` (PK + Schnorr
  proofs, verified on receipt); `setup → EB: gen-eb-key`; `EB → setup: eb-key`.
  Setup combines the keys and publishes them to the transcript.
- **Cards** — for each voter, `setup → CCj: long-code-share-req`; `CCj → setup:
  long-code-share-resp` (return-code shares from the CC's private secret). Setup
  assembles cards and delivers them **confidentially**: `setup → voter:
  voting-card` and `setup → server: mapping-table` (both X25519-encrypted).
- **Voting** — `voter → server: cast-ballot`; `server → CCj: verify-ballot`;
  `CCj → server: ballot-verdict`. Stored on unanimous acceptance (vcPK persisted).
- **Tally** — `→ server: start-tally` (server pads the ballot box); then
  `→ CCj: shuffle` / `CCj →: shuffled` chained through all CCs; `→ EB: final-mix`
  / `EB →: final-done`. Each party posts its shuffle + decryption proofs to the
  transcript.
- **Audit** — the verifier re-checks the whole transcript (`RunVerify`): every CC
  Schnorr proof and the full shuffle chain, from public data alone.

### Design decision: proofs on the bulletin board, ciphertexts on the wire

Fully serializing the Bayer-Groth argument tree (product / Hadamard / zero / SVP
/ multi-exponentiation sub-arguments, each with nested vectors) as JSON for every
CC→CC hop would be enormous. Instead — matching the real system, where control
components publish to a public bulletin board — the **ciphertext handoffs** between
parties cross the signed transport (and are re-validated as G_q members on
decode), while the **zero-knowledge proofs** are posted to the public transcript
that the verifier independently re-checks. The vote data itself always crosses
the authenticated channel; the proofs live on the board, exactly where an auditor
reads them.

## Trust-boundary hardening folded in here

Findings from the due-diligence pass that only bite once inputs are remote are
addressed in the party layer:

- **M4** (unvalidated deserialization): every crypto object is decoded through
  `NewGqElement`/`NewZqElement` at the wire boundary (`pkg/party/wire.go`), so a
  peer cannot inject a non-residue or out-of-range value.
- **F6** (`vcPK` not persisted): the ballot carries `vcPK`, stored in the ballot
  box, so the exponentiation-proof statement is reconstructible by any party.
- **F7 / F8** (padding / partial decryptions not persisted): the padded mix input
  and every per-stage partial decryption are published to the transcript, and the
  verifier checks the shuffle chain against exactly those.
- **F12** (panic on malformed plaintext): tally uses `DecodeVoteChecked`, so a
  ballot that does not decode is spoiled, not fatal; handlers reject malformed
  messages cleanly rather than panicking.

### Honest scope limits

- **F5** (the unsound plaintext-equality proof) is *not* reimplemented. The
  multi-party ballot uses only the **sound exponentiation proof** binding the
  ballot to `vcPK`; the return-code path that encrypts partial choice codes under
  the return-codes key (E2 / plaintext-equality) is omitted.
- Consistent with the original system (finding F16), the **cast-as-intended**
  return codes are derived deterministically from CC shares rather than
  homomorphically over the submitted ciphertext. The return-code *mechanism*
  (per-CC shares combined into a mapping-table lookup) is real and consistent
  across card generation and would-be extraction (fixing the old derivation
  mismatch, F1); the property that the shown code is computed *from the actual
  ballot* remains simulated.
