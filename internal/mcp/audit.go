package mcp

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// Outcome is the class of a tool call, as the audit stream records it.
//
// Three values rather than a bare success flag, because the question this log
// exists to answer is what was attempted against a database this project does
// not own, and "refused" and "failed" are different answers to it: the first
// says the gate stopped something, the second says the engine did.
type Outcome string

const (
	// OutcomeAllowed is a call that ran and returned rows.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeRefused is a call the gate would not permit. Nothing reached a
	// socket.
	OutcomeRefused Outcome = "refused"
	// OutcomeFailed is a call the gate permitted and that failed afterwards: the
	// engine rejected it, the deadline expired, the host was unreachable.
	OutcomeFailed Outcome = "failed"
)

// AuditEvent is one tool call, as recorded.
//
// The statement is carried verbatim and in full, deliberately. A truncated or
// summarised statement cannot answer the question the log is for — a DBA asking
// what this process sent their server needs the bytes, not a description of
// them — and there is nothing to redact: the statement is the agent's own text,
// which is the one input to this process that never touched a credential.
type AuditEvent struct {
	// Tool is the tool that was called. Both tools are recorded, because an
	// enumeration of the configured connections is also something the agent did.
	Tool string
	// Identity is who made the call. It is empty for the whole of this objective
	// — there is no authentication yet — and the field exists now so that the
	// objective which adds one fills a field rather than changes a schema every
	// downstream reader has already learned.
	Identity string

	Alias     string
	Engine    gate.Engine
	Statement string

	Outcome Outcome
	// Verdict, Reason, RuleID and Pending are the gate's own, copied from the
	// decision that produced the outcome. They are empty for a call that never
	// reached the gate, such as one naming an alias that is not configured.
	Verdict gate.Verdict
	Reason  gate.Reason
	RuleID  string
	Pending []string
	// ErrorKind is internal/db's classification when the call failed. It is the
	// class and not the engine's words: the operator-facing detail goes to the
	// application log, which is where a person debugging looks, and keeping it out
	// of here means the audit stream can be shipped somewhere less trusted.
	ErrorKind db.Kind

	Rows      int
	Truncated bool
	Elapsed   time.Duration
}

// Auditor writes the audit stream.
//
// It is a distinct logger over a distinct writer rather than a level or a field
// on the application log, because the two have different retention answers and
// different audiences: the application log is for whoever is debugging this
// process, and the audit stream is the record of what was asked of somebody
// else's database. Merging them makes the second one's completeness depend on
// the first one's log level.
type Auditor struct {
	// One event is one Write on the writer, and [NewAuditor] takes an io.Writer,
	// which promises nothing at all about two goroutines calling Write at once.
	// Tool calls are served on independent HTTP goroutines because the transport
	// is stateless, so two overlapping records are the ordinary case and not an
	// exotic one, and a record is large: the statement is carried verbatim and in
	// full and an agent's SQL has no bound. A destination that splits or reorders
	// a large write — a bufio.Writer, a rotating file, a tee, a bytes.Buffer in a
	// test — turns two overlapping records into two lines that parse as neither,
	// in the one stream whose completeness is its entire justification, and a
	// mangled audit record cannot be reconstructed from anywhere else.
	//
	// The destinations [OpenAuditWriter] returns are all *os.File, which today
	// does hold a per-file write lock across the whole write (internal/poll's
	// FD.Write), so those in particular would survive without this. That is a
	// property of what main happens to pass, not of what this type accepts, and
	// it is not what the guarantee should rest on.
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

// OpenAuditWriter resolves a [Config.Audit] destination to a writer and a close
// function.
//
// It lives here rather than in the process's main so that main stays a shell
// that wires things together, and so that the file mode below — append, create,
// owner-only — is decided next to the thing that decides what goes in the file.
func OpenAuditWriter(destination string) (io.Writer, func() error, error) {
	noClose := func() error { return nil }
	switch destination {
	case AuditStdout:
		return os.Stdout, noClose, nil
	case AuditStderr:
		return os.Stderr, noClose, nil
	}
	// Appended rather than truncated: an audit stream that starts empty on every
	// restart cannot answer a question about yesterday. 0600 because the
	// statements in it are a description of somebody else's schema.
	f, err := os.OpenFile(destination, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		// The path is the operator's own and is named back to them, because a
		// server that will not start has to say what it could not open.
		return nil, nil, fmt.Errorf("mcp: open the audit destination %q: %w", destination, err)
	}
	return f, f.Close, nil
}

// Record writes one event.
//
// Every field is written on every event, including the empty ones, so that a
// consumer can rely on the shape instead of on which fields a particular
// outcome happens to fill. The exception is Pending, which is a list and is
// meaningless when empty.
func (a *Auditor) Record(e AuditEvent) {
	// Info rather than zerolog's level-less Log, so that an audit stream pointed
	// at the same file descriptor as the application log is still made of
	// well-formed records of the same shape. The stream field is what tells the
	// two apart when they do share a destination, which is the default.
	ev := a.log.Info().
		Str("stream", "audit").
		Str("tool", e.Tool).
		Str("identity", e.Identity).
		Str("alias", e.Alias).
		Str("engine", string(e.Engine)).
		Str("statement", e.Statement).
		Str("outcome", string(e.Outcome)).
		Str("verdict", string(e.Verdict)).
		Str("reason", string(e.Reason)).
		Str("rule_id", e.RuleID).
		Str("error_kind", string(e.ErrorKind)).
		Int("rows", e.Rows).
		Bool("truncated", e.Truncated).
		Dur("elapsed_ms", e.Elapsed)
	if len(e.Pending) > 0 {
		ev = ev.Strs("pending", e.Pending)
	}
	// The lock is taken around the write and not around the whole event, since
	// building it touches nothing shared. See [Auditor] for what it is for.
	a.mu.Lock()
	defer a.mu.Unlock()
	ev.Msg("tool call")
}
