# Changelog

The project's story in five arcs, newest first. Hashes reference this repo's history.

## Arc 5 — The Live Crypto Cockpit (2026-07-07)

*The cryptography narrates itself.* A surface-agnostic event stream (`pkg/trace`)
lets every meaningful cryptographic operation emit its notation as LaTeX plus the
**real runtime values**, the instant it executes — at zero cost when tracing is off.

- `evote cockpit` — browser view: each operation rendered as typeset mathematics
  (native MathML, no libraries, offline) with live values, a stakeholder sidebar,
  and a phase timeline. Auto-opens the browser; Replay button when done.
  (`1e0b286`, `a1e4ec6`)
- `evote cockpit --tmux` — terminal view: one tmux pane per stakeholder, each
  streaming its own party's operations as colored ASCII math. Same event stream,
  two surfaces. (`b38b990`)
- **Deep instrumentation to the Swiss Post class granularity** (`c246508`):
  Pedersen matrix commitments (`CommitmentService` analog), all five Bayer-Groth
  sub-arguments (`ShuffleArgument`, `ProductArgument`, `HadamardArgument`,
  `ZeroArgument`, `SingleValueProductArgument`, `MultiExponentiationArgument`),
  and partial decryption with proofs (`DecryptionProofService` analog). The
  shuffle proof is watched being *constructed*, not just referenced.
- Verified in a real browser: a 6-voter run (2×3 shuffle matrix, so the full
  argument tree fires) renders ~345 live operations across 8 kinds, no errors.

## Arc 4 — Cast-as-Intended Return Codes (2026-07-06 → 07)

*The return code is computed from the ballot that is actually counted.*

- The ballot now carries `E2 = Enc(vote, returnCodesPK)` plus a **plaintext-
  equality proof** binding E2 to the tallied ciphertext; every control component
  verifies it. (`d2cfbf2`)
- Return-code extraction: CCs exponentiate E2 by their per-voter keys and
  jointly decrypt, recovering `vote^Σk = prime_sel^Σk` → mapping-table lookup →
  code returned to the voter, who checks it against the card. (`127ae61`)
- Soundness test: a malicious client encrypting option A for the tally but
  option B for the return-code channel is **rejected** — vote substitution is
  caught. Closes findings F5/F16; the F1 derivation mismatch is gone by
  construction (single key-derivation function).

## Arc 3 — Multi-Party Architecture over Rust-Signed Transport (2026-07-06)

*From one process simulating everyone to separate endpoints that trust nothing
unsigned.*

- `rust/transportsec`: Ed25519 signatures + X25519 ECDH (ed25519-dalek,
  x25519-dalek), compiled to a C-ABI static library, called from Go via cgo.
  **No RSA anywhere** — including the X.509 CA, whose certificates are signed
  through a Rust-backed `crypto.Signer`. Cross-language test proves RFC 8032
  interop with Go's stdlib. (`ec4be74`, `f7cbe4f`)
- `pkg/transport`: CA-anchored identity directory, signed envelopes over an
  injective encoding, X25519 secure channels, a bus that verifies every message
  before delivery. (`f7cbe4f`)
- `pkg/party`: setup component, four control components, electoral board, voting
  server, voters, and verifier as separate endpoints holding only their own
  state; distributed key generation, confidential card delivery, CC-verified
  ballots, the CC→CC→EB mix-net cascade, and independent verification from the
  public transcript alone. (`313db92` → `23723fd`)
- `evote netdemo` runs it end-to-end; `--verbose` logs every signed envelope.
  (`b1f5606`)

## Arc 2 — Due-Diligence Hardening (2026-07-06)

*A full correctness/security review of the original PoC, with fixes and
regression tests.* (`ec4be74`)

- **Critical**: the multi-exponentiation verifier's `c_{B_m} = commit(0;0)` check
  was stubbed out — a malicious mixer could prove a non-permutation "shuffle".
  Now enforced.
- Fiat-Shamir challenges switched from biased `hash mod q` to the spec-correct
  oversample-then-reduce (`RecursiveHashToZq`).
- `VerifyTally` actually verifies (it used to return `true` unconditionally);
  mix padding persisted so small-N verification checks the real input.
- KDF domain separation made injective; `[1, q]` square-root off-by-one fixed;
  CLI flag validation; `crypto/rand` everywhere.
- Test suite added across math, hash, elgamal, zkp, mixnet, kdf, returncodes,
  protocol, and the Rust FFI bridge.

## Arc 1 — The Original PoC (2026-02-13)

*The cryptographic core of Switzerland's internet voting system, distilled into
a single Go binary.* (`e8b6f30`, `37072a5`)

- ElGamal over G_q (safe prime p = 2q+1), Schnorr / exponentiation / decryption /
  plaintext-equality proofs, the Bayer-Groth verifiable shuffle with its full
  sub-argument tree, return-code mapping tables, Argon2id + HKDF + AES-GCM.
- `evote demo` (full ceremony), `evote present` (terminal walkthrough),
  `evote serve` (embedded, iPad-optimized lecture decks).
