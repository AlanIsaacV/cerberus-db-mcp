package mcp

import (
	"context"
	"errors"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// The tool names. There are two, and the list is closed for this objective:
// schema introspection is a later one, and there is deliberately no dry-run
// validator and nothing that reads or edits the gate's ruleset — a tool that
// could relax the rules is a tool an agent could use to relax them.
const (
	ToolListConnections = "list_connections"
	ToolExecuteQuery    = "execute_query"
)

// ListConnectionsInput is empty: listing takes no arguments. It exists as a type
// because the SDK derives the tool's input schema from it.
type ListConnectionsInput struct{}

// Connection is one configured database as the agent is allowed to see it.
//
// What is absent is the point. There is no host, no port, no database name and
// no username, because none of those is something the agent needs in order to
// name an alias, and every one of them is a fact about a third party's
// infrastructure that this process holds and the agent does not. The bounds are
// present for the opposite reason: an agent that does not know the row cap
// writes a query that hits it and reads a truncated answer as a complete one.
type Connection struct {
	Alias        string      `json:"alias" jsonschema:"the name to pass as execute_query's alias argument"`
	Engine       gate.Engine `json:"engine" jsonschema:"the SQL dialect this connection speaks: mysql, postgresql or sqlserver"`
	RowCap       int         `json:"row_cap" jsonschema:"the most rows one result can contain; a larger result is cut off and reported as truncated"`
	QueryTimeout string      `json:"query_timeout" jsonschema:"how long one statement may run before the server stops it, as a duration such as 20s"`
}

// ListConnectionsResult wraps the list in an object rather than being a bare
// []Connection, because the SDK derives this tool's output schema from this type
// and rejects a tool whose output schema is not of type "object". The wrapper is
// also what lets a later objective add a field beside connections without
// changing the shape of what an agent has already learned to read.
type ListConnectionsResult struct {
	Connections []Connection `json:"connections"`
}

// ExecuteQueryInput is execute_query's whole argument list.
//
// There is no row-limit argument and no timeout argument, and their absence is a
// decision rather than an omission: both bounds are server configuration, and an
// argument that could move one in either direction would be an argument that
// moves a safety property. An agent that wants fewer rows writes LIMIT or TOP in
// its own SQL, which the gate sees and approves like any other text.
type ExecuteQueryInput struct {
	Alias     string `json:"alias" jsonschema:"which configured connection to run against, as named by list_connections"`
	Statement string `json:"statement" jsonschema:"one read-only SQL statement in that connection's dialect; writes, DDL, permission changes and multiple statements are refused before they reach the database"`
}

// ExecuteQueryResult is what execute_query returns.
//
// It carries no echo of the alias or the statement. Both are in the request the
// agent just made, and this project's scarcest resource is the agent's context:
// a field repeated on every call for the rest of a session buys nothing.
type ExecuteQueryResult struct {
	Columns []string `json:"columns" jsonschema:"the column names, in the order the values appear in each row"`
	Rows    [][]any  `json:"rows" jsonschema:"one array of values per row, aligned with columns; a byte sequence that is not text appears as an object with a $base64 key"`
	// Truncated is a field of its own rather than something the agent infers from
	// the row count, because a result that is exactly the cap is not truncated and
	// an agent told otherwise pages forever.
	Truncated bool `json:"truncated" jsonschema:"true when the statement had more rows and the row cap stopped the read"`
	RowCap    int  `json:"row_cap" jsonschema:"the row cap that applied to this result"`
}

// internalFailure is what the agent is told when this layer produced an error
// that is not a *db.Error.
//
// Every error internal/db returns is two-sided by construction, so anything else
// arriving at this boundary is a defect in this package — and the one thing that
// must not happen while a defect is being diagnosed is a raw Go error string
// reaching the agent, because that is the path along which a DSN, a host or a
// wrapped driver message would travel. The agent gets a sentence that says
// nothing; the application log gets the error in full.
const internalFailure = "the server failed to complete the call"

// agentError carries exactly the text the agent may read, and nothing else.
//
// It exists because the SDK's typed handler turns a returned error into the
// tool result's content by calling Error() on it. Returning a *db.Error directly
// would therefore put [db.Error.Error] — the operator-facing rendering, which
// includes the engine's own words in Detail — into the agent's hands. Wrapping
// [db.Error.Agent] in a type whose only string is that one makes the boundary a
// property of the type rather than of remembering.
type agentError struct{ message string }

func (e *agentError) Error() string { return e.message }

// registerTools installs both tools on an SDK server.
//
// They go through the generic AddTool rather than (*Server).AddTool, and that is
// load-bearing rather than stylistic. The generic path turns an error returned
// by the handler into a CallToolResult with IsError set and the message as
// content, which a model can read and act on; the low-level handler turns the
// same error into a JSON-RPC protocol error, which the model never sees as
// content and cannot correct itself from. Almost every error this server
// produces is a refusal the agent is expected to respond to by writing different
// SQL, so which of the two paths is used decides whether the gate is a
// conversation or a wall.
func (s *Server) registerTools(srv *sdk.Server) {
	sdk.AddTool(srv, &sdk.Tool{
		Name:        ToolListConnections,
		Description: "List the databases this server can read, with the dialect each one speaks and the limits every query runs under. Call this first: execute_query only accepts an alias listed here.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.listConnections)

	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolExecuteQuery,
		Description: "Run one read-only SQL statement against one of the configured databases and return its rows. " +
			"The statement is checked before it is sent: anything that is not provably a single read — a write, DDL, a permission change, a second statement, a write hidden in a CTE, or a construct the checker does not recognise — is refused and never reaches the database. " +
			"Results are capped and the statement is stopped if it runs too long; call list_connections for the limits in force.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.executeQuery)
}

func (s *Server) listConnections(_ context.Context, _ *sdk.CallToolRequest, _ ListConnectionsInput) (*sdk.CallToolResult, *ListConnectionsResult, error) {
	started := time.Now()
	settings := s.executor.Settings()
	aliases := s.executor.Aliases()

	out := &ListConnectionsResult{Connections: make([]Connection, 0, len(aliases))}
	for _, a := range aliases {
		out.Connections = append(out.Connections, Connection{
			Alias:  a.Name,
			Engine: a.Engine,
			RowCap: settings.RowCap,
			// The duration is rendered rather than sent as a number of anything,
			// because "20s" needs no unit agreed in advance between this server and
			// whatever is reading it.
			QueryTimeout: settings.QueryTimeout.String(),
		})
	}

	// Listing is audited like a query is. It carries no statement and no verdict,
	// and it is recorded anyway: the log's question is what the agent did against
	// this server, and enumerating the connections is part of the answer.
	s.audit.Record(AuditEvent{
		Tool:    ToolListConnections,
		Outcome: OutcomeAllowed,
		Rows:    len(out.Connections),
		Elapsed: time.Since(started),
	})
	return nil, out, nil
}

func (s *Server) executeQuery(ctx context.Context, _ *sdk.CallToolRequest, in ExecuteQueryInput) (*sdk.CallToolResult, *ExecuteQueryResult, error) {
	started := time.Now()

	// The nil grant slice is the whole of this objective's approval story, and it
	// is the only call to Execute in this package. There is no configuration that
	// supplies a grant, no tool that requests one, and no path by which a
	// NeedsApproval verdict becomes an Allow — because the shape in which an agent
	// asks for a grant is the shape in which an agent approves itself, which is
	// what the gate exists to prevent. TestExecuteIsCalledOnceWithNoGrants checks
	// the literal below rather than trusting this comment.
	result, err := s.executor.Execute(ctx, in.Alias, in.Statement, nil)
	elapsed := time.Since(started)

	if err != nil {
		return nil, nil, s.refuseOrFail(in, elapsed, err)
	}

	s.audit.Record(AuditEvent{
		Tool:      ToolExecuteQuery,
		Alias:     result.Alias,
		Engine:    result.Engine,
		Statement: in.Statement,
		Outcome:   OutcomeAllowed,
		Verdict:   result.Decision.Verdict,
		Reason:    result.Decision.Reason,
		RuleID:    result.Decision.RuleID,
		Rows:      len(result.Rows),
		Truncated: result.Truncated,
		Elapsed:   elapsed,
	})

	return nil, &ExecuteQueryResult{
		Columns:   result.Columns,
		Rows:      jsonRows(result.Rows),
		Truncated: result.Truncated,
		RowCap:    result.RowCap,
	}, nil
}

// refuseOrFail audits a failed call and reduces its error to what the agent may
// read.
//
// Both halves happen here and in this order so that neither can be skipped: a
// call that produced no audit line is a call the log cannot account for, and
// that includes the calls nobody wanted to happen.
func (s *Server) refuseOrFail(in ExecuteQueryInput, elapsed time.Duration, err error) error {
	event := AuditEvent{
		Tool:      ToolExecuteQuery,
		Alias:     in.Alias,
		Statement: in.Statement,
		Outcome:   OutcomeFailed,
		Elapsed:   elapsed,
	}

	var dbErr *db.Error
	if !errors.As(err, &dbErr) {
		// Not a *db.Error, so this layer has a defect. The operator's side gets
		// everything; the agent's side gets a sentence with nothing in it.
		s.log.Error().Err(err).
			Str("tool", ToolExecuteQuery).
			Str("alias", in.Alias).
			Msg("a tool call failed with an error that did not come from internal/db")
		s.audit.Record(event)
		return &agentError{message: internalFailure}
	}

	event.Engine = dbErr.Engine
	event.ErrorKind = dbErr.Kind
	switch {
	case dbErr.Decision != nil:
		// The gate refused, so its own verdict is what happened and nothing was
		// sent anywhere.
		event.Outcome = OutcomeRefused
		event.Verdict = dbErr.Decision.Verdict
		event.Reason = dbErr.Decision.Reason
		event.RuleID = dbErr.Decision.RuleID
		event.Pending = dbErr.Decision.Pending
	case dbErr.Kind != db.KindUnknownAlias:
		// The gate is not in the error, but Execute's documented order is resolve
		// alias, then gate, then socket — so a failure that is neither a refusal
		// nor an unknown alias is one the gate had already allowed. Recording that
		// is what lets the audit stream answer "was this permitted" for every call
		// rather than only for the ones that succeeded.
		event.Verdict = gate.Allow
	}

	// The operator-facing rendering, which carries the engine's own words, goes to
	// the application log and only there.
	s.log.Warn().
		Str("tool", ToolExecuteQuery).
		Str("alias", in.Alias).
		Str("kind", string(dbErr.Kind)).
		Str("detail", dbErr.Error()).
		Msg("a tool call did not return rows")

	s.audit.Record(event)
	return &agentError{message: dbErr.Agent()}
}
