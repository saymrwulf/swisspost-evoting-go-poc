# Swiss Post E-Voting — Go PoC

A ground-up reimplementation of the Swiss Post e-voting cryptographic protocol as a single Go binary.

The Swiss Post system is Switzerland's official internet voting platform, used in binding federal elections. The production system spans **14 Java repositories, 500K+ lines of code, and requires 50GB of RAM**. This PoC distills the core cryptographic protocol into **52 Go files with 2 dependencies**.

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
| `pkg/protocol` | Full election orchestration (setup, vote, confirm, tally) |
| `pkg/verify` | Independent verification of all proofs |

## Quick Start

```bash
go build -o evote ./cmd/evote

# Run a complete election ceremony (10 voters, 3 candidates)
./evote demo --voters 10 --options 3

# Serve presentations on local network (for iPad viewing)
./evote serve --port 8080

# Theatrical step-by-step terminal walkthrough
./evote present
```

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
| Codebase | 14 repos, 500K+ lines (Java) | 52 files, 15K lines (Go) |
| Infrastructure | Kubernetes, HSMs, air-gapped machines | Single binary, your laptop |
| Dependencies | Spring Boot, Bouncy Castle, Angular, ... | Cobra + stdlib crypto |
| Memory | 50GB+ RAM | ~50MB |
| Binary | N/A (Java services) | 9.5MB static binary |
| Startup | Minutes (JVM + Spring) | Instant |

## Presentations

Three HTML slide decks are included, viewable in any browser or served to iPad via `./evote serve`:

- **presentation.html** — Protocol overview: how a cryptographic election works
- **presentation-crypto.html** — Deep dive into the mathematics (ElGamal, ZKPs, Bayer-Groth)
- **presentation-swe.html** — Software engineering perspective: building a government election system in Go

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
    protocol/            Election orchestration
    verify/              Independent proof verification
```

## References

- [Swiss Post E-Voting System Specification (PDF)](https://gitlab.com/swisspost-evoting)
- Bayer, S. & Groth, J. (2012). *Efficient Zero-Knowledge Argument for Correctness of a Shuffle*
- Haines, T. & Groth, J. (2020). *Verifiable Shuffle of Large Ciphertexts*
- ElGamal, T. (1985). *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*

## License

MIT
