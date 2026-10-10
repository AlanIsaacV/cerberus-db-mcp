package mcpserve

import (
	"io"
	"sync"

	"github.com/rs/zerolog"
)

// Auditor writes the audit stream.
//
// It is a distinct logger over a distinct writer rather than a level or a field
// on the application log, because the two have different retention answers and
// different audiences: the application log is for whoever is debugging this
// process, and the audit stream is the record of what was asked of somebody
// else's data source. Merging them makes the second one's completeness depend on
// the first one's log level.
type Auditor struct {
	// One event is one Write on the writer, and [NewAuditor] takes an io.Writer,
	// which promises nothing at all about two goroutines calling Write at once.
	// Tool calls are served on independent HTTP goroutines because the transport
	// is stateless, so two overlapping records are the ordinary case and not an
	// exotic one, and a record is large: the agent's request is carried verbatim
	// and in full and has no bound. A destination that splits or reorders
	// a large write — a bufio.Writer, a rotating file, a tee, a bytes.Buffer in a
	// test — turns two overlapping records into two lines that parse as neither,
	// in the one stream whose completeness is its entire justification, and a
	// mangled audit record cannot be reconstructed from anywhere else.
	//
	// The process passes stdout, whose file descriptor currently holds a per-file
	// write lock across each Write (internal/poll's FD.Write), so it would survive
	// without this. That is a property of what main happens to pass, not of what
	// this type accepts, and it is not what the guarantee should rest on.
	mu  sync.Mutex
	log zerolog.Logger
}

// NewAuditor builds an auditor over a plain zerolog logger, with no level
// filter and no sampler: a stream whose completeness is the whole point of it
// cannot have a knob that drops records, and an event this process decided not
// to write is one nobody can reconstruct afterwards. The timestamp is attached
// here rather than by [Auditor.Record] so that no caller can produce an event
// without one.
func NewAuditor(w io.Writer) *Auditor {
	return &Auditor{log: zerolog.New(w).With().Timestamp().Logger()}
}

func (a *Auditor) Record(tool, identity, subject string, fields func(*zerolog.Event)) {
	// The audit stream records what happened rather than application diagnostics,
	// so application log levels must not silence it; its events are level-less.
	ev := a.log.Log().
		Str("stream", "audit").
		Str("tool", tool).
		Str("identity", identity).
		Str("subject", subject)
	if fields != nil {
		fields(ev)
	}
	// The lock is taken around the write and not around the whole event, since
	// building it touches nothing shared. See [Auditor] for what it is for.
	a.mu.Lock()
	defer a.mu.Unlock()
	ev.Msg("tool call")
}
