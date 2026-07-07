package mixnet

import (
	"fmt"

	"github.com/user/evote/pkg/trace"
)

// emitArgument publishes a KindArgument trace event for one Bayer-Groth
// sub-argument, mirroring the *ArgumentService classes of the Swiss Post
// crypto-primitives library. Cheap when tracing is off.
func emitArgument(name, caption, latex, ascii string, values map[string]string) {
	trace.EmitFunc(func() trace.Event {
		return trace.Event{
			Kind:    trace.KindArgument,
			Caption: caption,
			LaTeX:   latex,
			ASCII:   ascii,
			Values:  values,
		}
	})
}

func dims(m, n int) map[string]string {
	return map[string]string{"m": fmt.Sprintf("%d", m), "n": fmt.Sprintf("%d", n)}
}
