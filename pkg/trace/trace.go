// Package trace is a live event stream for the cryptographic operations the
// system performs. Each meaningful operation (sampling, encryption, commitment,
// Fiat-Shamir challenge, shuffle, signature, key agreement) emits one Event
// carrying its notation as a LaTeX template plus the REAL runtime values, so a
// renderer can show the mathematics that is executing at the instant it runs.
//
// The stream is surface-agnostic: a terminal view renders ASCII/Unicode, a
// browser view renders typeset LaTeX (KaTeX) — both consume the same events.
//
// Tracing is off by default and has near-zero cost when no sink is attached:
// Emit returns immediately if there are no subscribers. Instrumentation sites
// wrap value formatting in a closure (via EmitFunc) so that formatting work is
// skipped entirely when tracing is off.
package trace

import (
	"sync"
	"sync/atomic"
)

// Kind categorizes an operation so a renderer can group or icon it.
type Kind string

const (
	KindSample    Kind = "sample"    // random sampling from Z_q / permutations
	KindEncrypt   Kind = "encrypt"   // ElGamal encryption
	KindDecrypt   Kind = "decrypt"   // (partial) decryption
	KindExp       Kind = "exp"       // group exponentiation of note
	KindCommit    Kind = "commit"    // Pedersen commitment
	KindChallenge Kind = "challenge" // Fiat-Shamir challenge derivation
	KindProof     Kind = "proof"     // ZK proof generation / verification
	KindArgument  Kind = "argument"  // a Bayer-Groth sub-argument (product/Hadamard/zero/SVP/multi-exp)
	KindShuffle   Kind = "shuffle"   // mix-net permutation + re-encryption
	KindSign      Kind = "sign"      // Ed25519 signature (transport)
	KindVerify    Kind = "verify"    // signature / proof verification
	KindKeyEx     Kind = "keyex"     // X25519 key agreement
	KindNote      Kind = "note"      // phase/step narration, no math
)

// Event is one instrumented operation.
type Event struct {
	Seq     uint64            `json:"seq"`     // monotonic sequence number
	Party   string            `json:"party"`   // which stakeholder performed it
	Phase   string            `json:"phase"`   // setup / voting / tally / verify
	Kind    Kind              `json:"kind"`    // operation category
	Caption string            `json:"caption"` // one-line human description
	LaTeX   string            `json:"latex"`   // notation, with \VAL{name} placeholders
	ASCII   string            `json:"ascii"`   // terminal-friendly fallback (optional)
	Values  map[string]string `json:"values"`  // placeholder name -> real runtime value (decimal/hex)
}

// Sink receives events. Implementations must be safe for concurrent use and must
// not block the emitter for long (buffer or drop internally if needed).
type Sink interface {
	Handle(Event)
}

var (
	mu       sync.RWMutex
	sinks    []Sink
	active   atomic.Bool // fast path: true when at least one sink is attached
	seqCtr   atomic.Uint64
	curParty atomic.Value // string: default party if an emit omits one
	curPhase atomic.Value // string: current phase
)

// Subscribe attaches a sink and returns an unsubscribe function.
func Subscribe(s Sink) func() {
	mu.Lock()
	sinks = append(sinks, s)
	active.Store(true)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		for i, x := range sinks {
			if x == s {
				sinks = append(sinks[:i], sinks[i+1:]...)
				break
			}
		}
		active.Store(len(sinks) > 0)
	}
}

// Enabled reports whether any sink is attached. Instrumentation can check this
// to skip expensive value formatting.
func Enabled() bool { return active.Load() }

// SetContext sets the default party/phase stamped onto events that omit them.
func SetContext(party, phase string) {
	curParty.Store(party)
	curPhase.Store(phase)
}

// Phase sets just the current phase.
func Phase(phase string) { curPhase.Store(phase) }

func ctxParty() string {
	if v, ok := curParty.Load().(string); ok {
		return v
	}
	return ""
}
func ctxPhase() string {
	if v, ok := curPhase.Load().(string); ok {
		return v
	}
	return ""
}

// Emit publishes an event. It fills Seq, and Party/Phase from context if unset.
// Returns immediately when tracing is disabled.
func Emit(e Event) {
	if !active.Load() {
		return
	}
	e.Seq = seqCtr.Add(1)
	if e.Party == "" {
		e.Party = ctxParty()
	}
	if e.Phase == "" {
		e.Phase = ctxPhase()
	}
	mu.RLock()
	current := sinks
	mu.RUnlock()
	for _, s := range current {
		s.Handle(e)
	}
}

// EmitFunc builds and emits an event only when tracing is enabled, so callers
// can defer all value formatting into build. Use this at hot instrumentation
// sites where formatting big integers would otherwise cost even when tracing off.
func EmitFunc(build func() Event) {
	if !active.Load() {
		return
	}
	Emit(build())
}
