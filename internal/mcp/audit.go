package mcp

import (
	"io"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
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
	// Tool is the tool that was called. Every tool is recorded, because an
	// enumeration of the configured connections, or of the databases behind one, is
	// also something the agent did.
	Tool string
	// Identity and Subject are the caller internal/auth admitted the request as:
	// Identity is their verified email address, Subject is Google's `sub` claim
	// for them.
	//
	// The comment that stood here promised that the objective which added
	// authentication would fill a field rather than change a schema. This pair is
	// what broke that promise, by one field, and it is worth saying why two are
	// needed. The subject is the stable one: it is opaque, it does not change when
	// the account behind it changes its address, and it is the only value here
	// that is guaranteed unique for this OAuth client, so it is what two records
	// months apart can be joined on. The email is the reconstructable one: it is
	// what a person reading an incident recognises, and what the allowlist is
	// written in terms of, so a stream carrying only subjects could not answer
	// "who did this" without being crossed against a directory that whoever is
	// reading may no longer have. Identity keeps its name rather than becoming
	// Email precisely because of the reader that older comment existed to protect:
	// a rename breaks every query already written against this stream.
	//
	// Both are empty when no identity reached the tool, which is a state no
	// deployed server can be in — see [Server.caller] for why that is recorded as
	// an absence rather than given a name.
	Identity string
	Subject  string

	Alias  string
	Engine gate.Engine
	// Statement is empty for the tools whose statement is not the agent's:
	// list_connections sends none, and list_databases and search_schema send
	// internal/db's own per-engine constants, which this package deliberately does
	// not hold copies of.
	// The tool name is what identifies what ran on those records.
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

type Auditor struct {
	shared *mcpserve.Auditor
}

func NewAuditor(w io.Writer) *Auditor {
	return &Auditor{shared: mcpserve.NewAuditor(w)}
}

// Record writes one event.
//
// Every field is written on every event, including the empty ones, so that a
// consumer can rely on the shape instead of on which fields a particular
// outcome happens to fill. The exception is Pending, which is a list and is
// meaningless when empty.
func (a *Auditor) Record(e AuditEvent) {
	a.shared.Record(e.Tool, e.Identity, e.Subject, func(ev *zerolog.Event) {
		ev.Str("alias", e.Alias).
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
			ev.Strs("pending", e.Pending)
		}
	})
}
