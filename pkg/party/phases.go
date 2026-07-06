package party

import (
	"fmt"

	"github.com/user/evote/pkg/transport"
)

// Phase message handlers. These are filled in incrementally (setup, then
// voting, then tally). Until a phase is implemented its handler rejects unknown
// message types cleanly rather than panicking — the transport boundary must
// never crash on an unexpected message.

func (p *SetupComponent) handleSetupMsg(env *transport.Envelope) (*transport.Envelope, error) {
	return nil, fmt.Errorf("%s: unhandled message type %q", p.id.Name, env.Type)
}

func (p *ControlComponent) handleCCMsg(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgGenCCKeys:
		return p.handleGenCCKeys(env)
	default:
		return nil, fmt.Errorf("%s: unhandled message type %q", p.id.Name, env.Type)
	}
}

func (p *ElectoralBoard) handleEBMsg(env *transport.Envelope) (*transport.Envelope, error) {
	switch env.Type {
	case MsgGenEBKey:
		return p.handleGenEBKey(env)
	default:
		return nil, fmt.Errorf("%s: unhandled message type %q", p.id.Name, env.Type)
	}
}

func (p *VotingServer) handleServerMsg(env *transport.Envelope) (*transport.Envelope, error) {
	return nil, fmt.Errorf("%s: unhandled message type %q", p.id.Name, env.Type)
}
