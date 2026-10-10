package mcpserve

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// AgentError carries exactly the text the agent may read, and nothing else.
//
// It exists because the SDK's typed handler turns a returned error into the
// tool result's content by calling Error() on it. Returning a connection layer's
// error directly would therefore put its Error() — the operator-facing rendering,
// which includes the engine's own words — into the agent's hands. Wrapping the
// agent-facing text in a type whose only string is that one makes the boundary a
// property of the type rather than of remembering.
type AgentError struct{ Message string }

func (e *AgentError) Error() string { return e.Message }

// Caller resolves the two identity fields of an audit event from the context the
// SDK handed this handler.
//
// internal/auth puts an [auth.Identity] on the request it admits and this reads
// it back out, which works only because the identity survives the SDK's
// dispatch between those two points — a property of Stateless: true rather than
// a documented contract, pinned by
// TestAnIdentitySetOnTheRequestContextSurvivesTheSDKsDispatchToTheToolHandler.
//
// There is no identity when the server was built with a nil Middleware. Every
// test of a binary's tools does that, and no deployment can: a binary refuses to
// start without authentication configured. Both fields then stay empty rather
// than carrying a word such as "unauthenticated", and the two are different
// claims to whoever reads the stream. A word sits in a field whose every other
// value is an email address, so it reads as a caller, and it satisfies any
// downstream check that asks only whether an identity was recorded — including
// this project's own "every query logged with its calling identity" — which is
// backwards for the one state where nobody was identified. An absence fails that
// check, which is the cheapest check anyone will write. What the operator needs
// instead of a sentinel is to be told, so the telling goes to the application
// log: a tool that ran for nobody is a defect in this process, and a defect
// belongs where the person debugging is looking rather than in the vocabulary of
// a stream whose worth is that its shape can be relied on.
func Caller(ctx context.Context, log zerolog.Logger, tool string) (email, subject string) {
	id, ok := auth.IdentityFrom(ctx)
	if !ok {
		log.Warn().
			Str("tool", tool).
			Msg("a tool call ran with no identity on its context: either no authentication middleware is installed or the identity did not survive the transport, and the audit record for this call names nobody")
		return "", ""
	}
	return id.Email, id.Subject
}
