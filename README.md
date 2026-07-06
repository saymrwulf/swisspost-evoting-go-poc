# Swiss Post E-Voting — Go PoC

A ground-up reimplementation of the Swiss Post e-voting cryptographic protocol as a single Go binary, with a multi-party mode where the parties talk over a Rust-signed transport.

The Swiss Post system is Switzerland's official internet voting platform, used in binding federal elections. The production system spans **14 Java repositories, 500K+ lines of code, and requires 50GB of RAM**. This PoC distills the core cryptographic protocol into **~94 Go files (~10.5K lines) plus a small Rust crate for transport security**. Two runtime modes: `demo` (single process) and `netdemo` (each party a separate endpoint, communicating only over Ed25519-signed / X25519-encrypted messages implemented in Rust — see [ARCHITECTURE.md](ARCHITECTURE.md)).

## What This Implements

The full election lifecycle with end-to-end verifiability:

```
Setup        4 Control Components + Electoral Board generate keys
             Voting cards with secret codes are produced
                              |
Vote         Voter encrypts ballot client-side (ElGamal)
             Server validates zero-knowledge proofs
             Return codes confirm vote was recorded correctly
                              |
Tally        5 sequential verifiable shuffles (Bayer-Groth)
             Each shuffle: permute -> re-encrypt -> partial decrypt
             Final decryption by air-gapped Electoral Board
                              |
Verify       Public audit: all proofs are independently checkable
             No secrets required — anyone can verify the election
```

## Cryptographic Components

| Package | What It Does |
|---------|-------------|
| `pkg/math` | Quadratic residue groups (G_q), safe prime generation, group vectors/matrices |
| `pkg/elgamal` | ElGamal encryption, partial decryption, homomorphic ciphertext operations |
| `pkg/zkp` | Schnorr proofs, exponentiation proofs, decryption proofs, plaintext equality proofs |
| `pkg/mixnet` | Bayer-Groth verifiable shuffle with 6 sub-arguments (product, Hadamard, zero, SVP, multi-exponentiation, shuffle) |
| `pkg/hash` | SHA-256 hash-and-square for Fiat-Shamir transforms |
| `pkg/kdf` | HKDF key derivation for return code generation |
| `pkg/symmetric` | AES-GCM authenticated encryption |
| `pkg/returncodes` | Vote encoding as small primes, return code mapping tables |
| `pkg/protocol` | Single-process election orchestration (setup, vote, confirm, tally) |
| `pkg/verify` | Independent verification of all proofs |
| `pkg/transportsec` | Transport-layer security (Ed25519 signatures, X25519 ECDH) — **implemented in Rust**, linked via cgo (see below) |
| `pkg/transport` | Authenticated message bus: Ed25519 X.509 PKI, signed envelopes, X25519 secure channels |
| `pkg/party` | **Multi-party ceremony**: each endpoint (setup, 4 CCs, electoral board, voting server, voters, verifier) as a separate party communicating only over the signed transport |

## Transport Security in Rust

Channel security between parties uses **Ed25519** signatures and **X25519 (ECDH)** key
agreement — deliberately elliptic-curve, with **no RSA anywhere**. These primitives are
implemented in Rust (`rust/transportsec`, using `ed25519-dalek` and `x25519-dalek`),
compiled to a C-ABI static library, and called from Go through cgo (`pkg/transportsec`).
The Go side never implements or duplicates this cryptography. A cross-language conformance
test proves the Rust signatures are standard RFC 8032 Ed25519 (Go's `crypto/ed25519`
verifies them and vice-versa).

## Quick Start

Building requires a **Rust toolchain** (for the transport-security static library) in
addition to Go. The Makefile builds the Rust library first, then the Go binary:

```bash
make build          # cargo build --release, then go build -o evote ./cmd/evote
make test           # runs cargo test + go test ./...

# Run a complete election ceremony, single process (10 voters, 3 candidates)
./evote demo --voters 10 --options 3

# Run the SAME election as separate parties over Rust-signed transport
./evote netdemo --voters 10 --options 3
./evote netdemo --voters 3 --options 2 --verbose   # log every signed message

# Serve presentations on local network (for iPad viewing)
./evote serve --port 8080

# Theatrical step-by-step terminal walkthrough
./evote present
```

The `demo` command runs the whole protocol in one process. `netdemo` runs the
**multi-party** architecture: every party is a separate endpoint holding only its
own private state, and every message between them is Ed25519-signed (and, for
card/mapping-table delivery, X25519-encrypted) — all transport cryptography in
Rust. The `netdemo` return codes are **cast-as-intended**: each voter's code is
recomputed by the control components from the submitted ciphertext (bound to the
ballot by a plaintext-equality proof), so a substituted vote is detected. See
[ARCHITECTURE.md](ARCHITECTURE.md).

If you build Go directly (`go build ./...`), run `make rust` first so the static library
at `rust/transportsec/target/release/libtransportsec.a` exists for cgo to link.

## Demo Output

```
=== SWISS POST E-VOTING PROTOCOL PoC ===

Phase 1: SETUP
  Generated safe prime group (q: 256 bits, p: 257 bits)
  CC[0]: generated ElGamal keypair, Schnorr proof OK
  CC[1]: generated ElGamal keypair, Schnorr proof OK
  CC[2]: generated ElGamal keypair, Schnorr proof OK
  CC[3]: generated ElGamal keypair, Schnorr proof OK
  EB: generated ElGamal keypair, Schnorr proof OK
  Combined election public key (product of all 5)
  Generated 10 voting cards with return codes

Phase 2: VOTING
  Voter 1: encrypted vote for option 2, proof verified
  Voter 2: encrypted vote for option 0, proof verified
  ...

Phase 3: TALLY
  Shuffle 1/5 (CC[0]): permute + re-encrypt + partial decrypt
  Shuffle 2/5 (CC[1]): permute + re-encrypt + partial decrypt
  ...
  Final decryption by Electoral Board
  Results: Option 0: 4 votes, Option 1: 3 votes, Option 2: 3 votes

Phase 4: VERIFICATION
  All 5 Schnorr key proofs: VALID
  All 5 shuffle proofs: VALID
  Vote count matches ballot box: VALID
  Election integrity: VERIFIED
```

## Production vs. PoC

| Aspect | Production (Swiss Post) | This PoC |
|--------|------------------------|----------|
| Group size | 3072-bit safe prime | 256-bit safe prime |
| Codebase | 14 repos, 500K+ lines (Java) | ~94 Go files (~10.5K lines) + Rust crate |
| Infrastructure | Kubernetes, HSMs, air-gapped machines | Single binary, your laptop |
| Signatures / key exchange | RSASSA-PSS, RSA channels | Ed25519 / X25519 (Rust), no RSA |
| Dependencies | Spring Boot, Bouncy Castle, Angular, ... | Cobra + golang.org/x/crypto; ed25519-dalek + x25519-dalek (Rust) |
| Party isolation | Separate machines / operators | Separate in-process endpoints over a signed bus (`netdemo`) |
| Memory | 50GB+ RAM | ~50MB |
| Binary | N/A (Java services) | ~9.5MB (Go + linked Rust static lib) |
| Startup | Minutes (JVM + Spring) | Instant |

## Presentations

HTML slide decks are embedded in the binary and served via `./evote serve` (iPad-friendly);
the same files live under [cmd/evote/web/](cmd/evote/web/):

- **index.html** — Landing page and operations overview
- **demo.html** — Protocol walkthrough: how a cryptographic election works
- **crypto.html** — The mathematics (ElGamal, ZKPs, Bayer-Groth, Ed25519/X25519 transport, cast-as-intended)
- **swe.html** — Software engineering: building it in Go, plus the multi-party re-architecture and the Rust transport-security layer

Standalone copies (`presentation*.html`, `manual.html`) are kept at the repo root for direct browsing.

## Project Structure

```
cmd/evote/
    main.go              Cobra CLI root
    demo.go              Full election ceremony
    serve.go             HTTP server for presentations
    present.go           Theatrical terminal demo (772 lines)
    web/                 Embedded HTML presentations
pkg/
    math/                Group theory (GQ, ZQ, vectors, matrices)
    elgamal/             Encryption, decryption, key management
    zkp/                 Zero-knowledge proofs (4 types)
    mixnet/              Verifiable shuffle (Bayer-Groth, 12 files)
    hash/                Hash-and-square, Fiat-Shamir
    kdf/                 HKDF key derivation
    symmetric/           AES-GCM
    returncodes/         Vote encoding, return code mapping
    protocol/            Single-process election orchestration
    verify/              Independent proof verification
    transportsec/        Rust FFI: Ed25519 sign/verify, X25519 ECDH
    transport/           PKI, signed envelopes, secure channels, message bus
    party/               Multi-party ceremony (one object per endpoint)
rust/transportsec/       Rust crate: ed25519-dalek + x25519-dalek, C ABI
```

## Security Hardening (Due-Diligence Pass)

A full correctness/security review of the codebase produced the following fixes,
each covered by a regression test:

| Area | Issue | Fix |
|------|-------|-----|
| `pkg/mixnet` | The multi-exponentiation verifier's `c_{B_m} = commit(0;0)` check was stubbed out (empty `if`), letting a malicious mixer prove a **non-permutation** shuffle | Check enforced; honest shuffles still verify |
| `pkg/zkp` | All four Fiat–Shamir challenges were `hash mod q` — biased, and capped at 256 bits for production groups | Switched to spec-correct `RecursiveHashToZq` (oversample-then-reduce) |
| `pkg/protocol` | `VerifyTally` returned `true` unconditionally; Schnorr proofs were never actually verified | Real `zkp.VerifySchnorrProof` calls; returns the true aggregate result |
| `pkg/protocol` | Mix padding for N<2 was regenerated with fresh randomness at verify time → shuffle 0 always failed | Padded input persisted as `event.MixInput` and reused by the verifier |
| `pkg/kdf` | `BuildKDFInfo` concatenated parts without separators (`("e1","23x")` == `("e12","3x")`) | Length-prefixed, injective encoding |
| `pkg/math` | `GqElementFromSquareRoot` rejected the valid root `q` (off-by-one), a latent panic; `RandomGqElement` skipped one element | Range corrected to `[1, q]` |
| `cmd/evote` | `--options=0` / `--voters=-1` panicked | Validated flags return clean errors |
| everywhere | `math/rand` used in the demo driver | Replaced with `crypto/rand` |

Trust-boundary hardening (validated deserialization, verifiers returning `false`
rather than panicking on malformed peer input) is handled in the multi-party
re-architecture, where inputs actually arrive over the wire.

## References

- [Swiss Post E-Voting System Specification (PDF)](https://gitlab.com/swisspost-evoting)
- Bayer, S. & Groth, J. (2012). *Efficient Zero-Knowledge Argument for Correctness of a Shuffle*
- Haines, T. & Groth, J. (2020). *Verifiable Shuffle of Large Ciphertexts*
- ElGamal, T. (1985). *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*

## License

MIT
