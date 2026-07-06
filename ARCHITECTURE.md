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
- **Voting** — `voter → server: cast-ballot` (ballot + E2 + equality proof);
  `server → CCj: verify-ballot`; `CCj → server: ballot-verdict`. Stored on
  unanimous acceptance (vcPK persisted). Then the return-code extraction:
  `server → CCj: rc-exp-req` / `rc-dec-req`; `CCj →: rc-exp-resp` / `rc-dec-resp`.
  The server returns the recovered code to the voter, who checks it against the
  card (cast-as-intended — see below).
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
- **F5 / F16** (return codes were decorative): the return-code path is now
  genuinely **cast-as-intended** — see below.

## Cast-as-intended return codes

The return code the voter checks is computed by the control components **from the
submitted ciphertext**, so client-side vote substitution is detected:

1. The voter submits the ballot `E1` plus a second ciphertext `E2 =
   Enc(vote, returnCodesPK)` and a **plaintext-equality proof** that `E1` and
   `E2` encrypt the same vote. Every CC verifies this proof; a ballot whose two
   ciphertexts disagree is rejected.
2. The card code for option *i* is the algebraic base `prime_i^{Σ_j k_j}`, where
   `k_j` is CC *j*'s voter-specific return-code key. Setup builds it by combining
   per-CC shares; the same `k_j` is used at vote time (one derivation — the old
   F1 mismatch is gone by construction).
3. At vote time each CC exponentiates `E2` by its `k_j` (product over CCs =
   `Enc(vote^{Σk})`), then contributes a partial-decryption factor. The server
   recovers `vote^{Σk}` — which equals `prime_sel^{Σk}` — and looks up the short
   code, returning it to the voter.
4. The voter checks the returned code against the card for the chosen option. A
   mismatch means the tallied vote differs from the intended one.

**Soundness**: because the equality proof binds `E2` to `E1` (the tallied
ballot), the code is derived from the vote that is actually counted. Malware that
alters the vote cannot produce a matching card code without the CC secrets. A
unit test drives the substitution attack (`E1`=A, `E2`=B) and confirms the CCs
reject it.

### Remaining scope limits (honest)

- The return-code path is defined for a **single selected option** per voter (the
  demo case); multi-selection return codes are not implemented.
- **Privacy**: the return-code lookup lets the server learn which mapping entry
  matched, so in this PoC the return-code-computing parties can infer the
  selection. The real system separates these roles to keep the vote secret from
  any single party; that role separation is simplified here. Vote secrecy of the
  **tally** is unaffected (it rests on the mix-net, not the return-code channel).
