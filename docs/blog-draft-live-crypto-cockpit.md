---
title: "The cryptography narrates itself: a live-math cockpit for the Swiss Post e-voting PoC"
date: 2026-07-07
tags: ["e-voting", "zero-knowledge", "bayer-groth", "go", "rust", "mathml", "pedagogy"]
draft: false
---

<!--
DRAFT for blog.zkdefi.org — written to follow the February post
"A 52-file Go re-implementation of Swiss Post's e-voting protocol".
Copy into the blog's content/posts/ directory (Hugo) and adjust front matter
to taste. Teaser suggestion for the listing:

  The Go re-implementation of Swiss Post's e-voting protocol grew up: it now
  runs as mutually distrusting parties over Rust-signed transport, its return
  codes are genuinely cast-as-intended, and — the headline — every cryptographic
  operation renders itself as typeset mathematics with live values, the instant
  it executes.
-->

Back in February I wrote about distilling Swiss Post's internet voting protocol
— 14 Java repositories, 500K+ lines — into a small Go binary. That post ended
where most reimplementations end: the ceremony runs, the proofs verify, the
tally is right. Since then the project has grown in three directions, and the
third one is the reason for this post.

## First: it became honest about trust

The original PoC was faithful to the *protocol* but not to the *trust model* —
every party (the setup component, four control components, the electoral board,
the voting server, the voters, the verifier) lived as fields on one shared Go
struct. Anyone could read anyone's secret key; nothing stopped them but
politeness.

Now each party is a separate endpoint holding only its own private state, and
everything that crosses between them travels as an **Ed25519-signed envelope**
over a message bus that verifies every signature before delivery. Voting cards
are delivered confidentially under **X25519-derived session keys**. Identities
are real X.509 certificates from a root CA — and there is **no RSA anywhere**,
including the CA: certificate signatures are produced through a Go
`crypto.Signer` shim that forwards to Rust.

That's the second point worth pausing on: all transport cryptography lives in a
small **Rust** crate (`ed25519-dalek`, `x25519-dalek`) behind a five-function C
ABI, linked into Go via cgo. The election mathematics — ElGamal over a
safe-prime group, the zero-knowledge proofs, the Bayer-Groth shuffle — remains
hand-built Go, because understanding every line of the *protocol* is the point.
But hand-rolling Ed25519 would be reckless; audited constant-time
implementations are exactly what one should depend on. A cross-language test
keeps both sides honest: Go's `crypto/ed25519` must verify Rust's signatures
and vice versa, from the same seed.

## Second: the return codes stopped being decorative

Swiss voters check short **return codes** against a printed card to detect
malware that swaps their vote after encryption. In the original PoC (and, to be
fair, in an early reading of the real system's structure) the displayed code
came *from the card* — cast-as-intended theater rather than cast-as-intended.

Now the ballot carries a second ciphertext `E2 = Enc(vote, returnCodesPK)` and
a **plaintext-equality proof** that `E2` and the tallied ballot encrypt the
same vote. Every control component verifies that proof before accepting the
ballot. Then the CCs exponentiate `E2` by their per-voter secret keys and
jointly decrypt, recovering `vote^Σk` — which equals the card's precomputed
base `prime_selected^Σk` — and the resulting short code goes back to the voter.
A unit test drives the actual attack (encrypt option A for the tally, option B
for the return-code channel) and watches the equality proof reject it. The code
you check is now derived from the vote that is actually counted.

## Third, the headline: watch the mathematics execute

Here is the thing I have not seen elsewhere. Run

```
./evote cockpit
```

and your browser opens on a page where **every cryptographic operation renders
itself as typeset mathematics with its real runtime values, the instant the
code executes**. Not an animation of the protocol. A readout of it.

When a voter's client encrypts, you see

> *E₁ = (γ, φ) = (g^r, pk^r·m),  r ←$ ℤ_q*

with the actual 77-digit `r` and the actual encoded vote (a squared prime — you
watch `m₀ = 25` scroll past and know someone picked option 3). When a control
component builds its shuffle proof, the **Bayer-Groth argument tree assembles
itself in construction order**: the Pedersen commitment to the permutation
matrix, then the Product, Hadamard, Zero, Single-Value-Product and
Multi-Exponentiation arguments, each with its defining relation —

> *∑ᵢ aᵢ ∗_y bᵢ = 0*, *b = a₁ ∘ a₂ ∘ ⋯ ∘ aₘ*, *C = (∏∏ Cᵢⱼ^{Aᵢⱼ})·ReEnc_pk(1;ρ)*

— and its live dimensions and values. Then the partial decryptions with their
proofs, every Fiat-Shamir challenge, every Ed25519 transport signature. A
sidebar highlights which stakeholder is acting; a timeline tracks
setup → cards → voting → tally → verify. Prefer a terminal?
`./evote cockpit --tmux` opens one pane per stakeholder, each narrating its own
operations in ASCII math from the same event stream.

Two implementation notes for the curious. The math is **native browser MathML**
— no KaTeX, no fonts, no network; a two-hundred-line LaTeX→MathML converter
handles exactly the notation the instrumentation emits, and unknown tokens fall
back to literal text so the view can never crash. And the instrumentation
itself costs nothing when off: emitters sit behind an atomic check and build
their event (including formatting those 77-digit values) only if a sink is
subscribed, so `demo` and `netdemo` runs are untouched.

The pedagogical claim, made precisely: the sub-argument tree that the February
post could only *diagram* is now something you *watch happen*, with the same
granularity as the production system's class structure — `CommitmentService`,
the five `*ArgumentService` classes, `DecryptionProofService` — because the Go
packages mirror those classes one-to-one. The tree is not a picture of the
code. It is the code, narrating itself.

## Honest limits

It remains a PoC: a 256-bit demo group (production uses 3072), one OS process
(the parties are isolation-by-architecture, not by kernel), single-choice
ballots on the return-code path, and the return-code lookup lets the server
learn which entry matched — a privacy simplification the real system avoids by
separating roles. The mix-net's tally secrecy is untouched by that caveat.

Code, tests, lecture decks and an operations manual:
[github.com/saymrwulf/swisspost-evoting-go-poc](https://github.com/saymrwulf/swisspost-evoting-go-poc)
(mirrored on this site). Build with `make build`; the cockpit is one command.
