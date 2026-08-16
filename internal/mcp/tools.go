package mcp

import (
	"context"
	"errors"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// The tool names. There are five: search_schema is the deliberately narrow
// schema-introspection step below the database level, and describe_table is the
// bounded detail step once that search has found a table. There is still no dry-run
// validator and nothing that reads or edits the gate's ruleset — a tool that
// could relax the rules is a tool an agent could use to relax them.
const (
	ToolListConnections = "list_connections"
	ToolExecuteQuery    = "execute_query"
	ToolListDatabases   = "list_databases"
	ToolSearchSchema    = "search_schema"
	ToolDescribeTable   = "describe_table"
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

// ListDatabasesInput is list_databases' whole argument list: one alias.
//
// There is no pattern and no limit, for the reason written on [ExecuteQueryInput].
// The statement this tool runs is internal/db's own constant, and its whole safety
// property is that it is a constant — an argument that reached it would be an
// argument that moves what this process sends somebody else's server, and the
// answer is small enough that an agent can filter it itself.
type ListDatabasesInput struct {
	Alias string `json:"alias" jsonschema:"which configured connection to ask, named exactly as list_connections gives it; this is an alias and not a database name"`
}

// ListDatabasesResult is what list_databases returns.
//
// It wraps the list in an object for the reason [ListConnectionsResult] does: the
// SDK derives the output schema from this type and rejects a tool whose output
// schema is not of type "object".
//
// Truncated is carried for the reason it is carried on [ExecuteQueryResult] and on
// [Connection]: the row cap applies to this statement like any other, and an agent
// that is not told its list was cut off reads a partial answer as the complete set
// of databases — which is exactly the question it asked.
type ListDatabasesResult struct {
	Databases []string `json:"databases" jsonschema:"the database names this connection's login can see, with the engine's own system databases removed; a name here is not an alias"`
	Truncated bool     `json:"truncated" jsonschema:"true when the row cap stopped the read, so this list is incomplete"`
	RowCap    int      `json:"row_cap" jsonschema:"the row cap that applied to this result"`
}

// SearchSchemaInput is search_schema's whole argument list. pattern is a plain
// substring, not a LIKE expression: internal/db owns the wildcards and escapes
// LIKE metacharacters before it binds the value to its fixed catalog statement.
//
// There is no limit or object-type argument. The row cap is server configuration
// reported by list_connections, and a tool argument must not move a safety bound.
type SearchSchemaInput struct {
	Alias   string `json:"alias" jsonschema:"which configured connection to search, named exactly as list_connections gives it; this is an alias and not a database name"`
	Pattern string `json:"pattern" jsonschema:"a plain case-insensitive substring of a table or column name; do not use LIKE wildcard syntax because % and _ are literal characters"`
}

// DescribeTableInput is describe_table's whole argument list. Table names and
// schemas are data that internal/db binds to its fixed catalog reads, rather than
// text this layer combines with a statement. Schema stays optional because a table
// discovered without one must still be describable; an unqualified name can name
// one table in each schema, and internal/db returns every one that matches.
//
// There is no limit, object-type or detail selector. The row and byte bounds are
// server configuration, and the fixed answer is deliberately the complete set of
// detail an agent needs to form a useful read without creating a second surface
// that can move either safety property.
type DescribeTableInput struct {
	Alias  string `json:"alias" jsonschema:"which configured connection to describe, named exactly as list_connections gives it; this is an alias and not a database name"`
	Table  string `json:"table" jsonschema:"the exact table name to describe; it is matched literally"`
	Schema string `json:"schema,omitempty" jsonschema:"optional namespace that narrows the table: on mysql it is the database the alias is bound to; on postgresql and sqlserver it is a schema within that database; a name here is not an alias"`
}

// SchemaSearchColumn is the wire form of one matching column. It deliberately
// carries only metadata needed to recognise a column; connection configuration
// remains on the server side of this boundary.
type SchemaSearchColumn struct {
	Name     string `json:"name" jsonschema:"the matching column's name"`
	DataType string `json:"data_type" jsonschema:"the database's reported type for this column"`
	Nullable bool   `json:"nullable" jsonschema:"whether this column accepts NULL values"`
}

// SchemaSearchTable is one matching table. A table matched only by its own name
// has an empty Columns list, because no column name matched the substring —
// unless ColumnsTruncated says the byte budget cut that list off, which is the
// one other way an empty list can arise and the reason the field is on the wire
// at all. The two are the same JSON without it, and an agent that reads the
// budget's cut as "no column matched" acts on a claim this server never made.
//
// The schema description states what the value is on each engine rather than one
// word that is true on two of them. On MySQL a table's schema is the database the
// alias is bound to, so the field carries a database name there; on PostgreSQL
// and SQL Server it is a namespace inside that database. It carries the same
// "not an alias" marker as every other name this surface returns, for the reason
// [ListDatabasesResult] does: an agent that hands one to execute_query as its
// alias is told the alias is unknown.
type SchemaSearchTable struct {
	Schema           string               `json:"schema" jsonschema:"the namespace to qualify this table with inside the database the alias is bound to: on mysql that database's own name, on postgresql and sqlserver a schema within it; a name here is not an alias"`
	Table            string               `json:"table" jsonschema:"the matching table's name"`
	Columns          []SchemaSearchColumn `json:"columns" jsonschema:"the columns whose names match the substring; when top-level truncation is row_cap, an empty or short list can be incomplete regardless of columns_truncated"`
	ColumnsTruncated bool                 `json:"columns_truncated" jsonschema:"true when the byte budget stopped inside this table, so the columns listed here are only the beginning of the ones that matched and an empty list says nothing about this table's columns; search this table again with a longer or more specific substring to see the rest. When false, this entry was not cut by the byte budget; if top-level truncation is row_cap, do not treat its columns as complete"`
}

// SearchSchemaResult is the grouped catalog answer. Truncation names which of the
// two bounds cut it: the row cap on the flat catalog rows before internal/db
// groups them, or the byte budget on the grouped result. Under either one a
// returned table can hold only part of its matching columns and must not be
// treated as a complete table description. Which table that was is on the table
// itself, in [SchemaSearchTable.ColumnsTruncated], where the byte budget was the
// bound that bit.
//
// ByteBudget is reported for the reason RowCap is. It is the bound a short
// pattern actually runs into, and an agent told only that its answer was cut off
// cannot tell whether to narrow the pattern or to page.
type SearchSchemaResult struct {
	Tables     []SchemaSearchTable `json:"tables" jsonschema:"one entry per matching table, each with its matching columns"`
	Truncation db.Truncation       `json:"truncation" jsonschema:"which bound cut this answer: none means every matching catalog row and assembled entry fit; row_cap means the flat catalog read stopped before grouping; byte_budget means the assembled grouped answer ran out of room. Under either non-none value the tables listed are the beginning of what matched and a listed table can have only part of its matching column list; search again with a longer or more specific substring rather than paging"`
	RowCap     int                 `json:"row_cap" jsonschema:"the row cap that applied to the flat catalog rows before grouping"`
	ByteBudget int                 `json:"byte_budget" jsonschema:"the most bytes this result's tables may occupy; a broad pattern reaches this bound long before the row cap"`
}

// DescribeTableColumn is the wire form of one table column. As with a schema
// search result, it has no connection configuration: describing a table needs its
// shape, not the infrastructure where that shape was read.
type DescribeTableColumn struct {
	Name     string `json:"name" jsonschema:"the column's name"`
	DataType string `json:"data_type" jsonschema:"the database's reported type for this column"`
	Nullable bool   `json:"nullable" jsonschema:"whether this column accepts NULL values"`
}

// DescribeTableIndex is the portable part of an index an agent can use when it
// writes a read. The order of Columns is the catalog's key order: replacing it
// with a sorted list would turn a composite index into a different claim about
// which predicates can use it.
type DescribeTableIndex struct {
	Name    string   `json:"name" jsonschema:"the index's name"`
	Columns []string `json:"columns" jsonschema:"the index key columns in catalog key order"`
	Unique  bool     `json:"unique" jsonschema:"whether the index permits only one row for each complete key"`
}

// DescribedTable is one table the requested name matched. An unqualified name
// can match more than one PostgreSQL or SQL Server schema, so Schema remains on
// every entry rather than being repeated from the request. On MySQL it is the
// database the alias is bound to; in every engine it is a namespace name, not an
// alias that can be supplied wherever list_connections asks for one.
type DescribedTable struct {
	Schema           string                `json:"schema" jsonschema:"the namespace containing this table: on mysql the database the alias is bound to, on postgresql and sqlserver a schema within that database; a name here is not an alias"`
	Table            string                `json:"table" jsonschema:"the table's name"`
	Columns          []DescribeTableColumn `json:"columns" jsonschema:"the table's columns with their types and nullability, in catalog order; when top-level truncation is row_cap, an empty or short list can be incomplete regardless of columns_truncated"`
	ColumnsTruncated bool                  `json:"columns_truncated" jsonschema:"true when the byte budget stopped inside this table, so columns is only its beginning and an empty list says nothing about this table's visible columns. When false, this entry was not cut by the byte budget; if top-level truncation is row_cap, do not treat its columns as complete"`
	PrimaryKey       []string              `json:"primary_key" jsonschema:"the primary key columns in catalog key order"`
	Indexes          []DescribeTableIndex  `json:"indexes" jsonschema:"the table's secondary indexes, each with its key columns in catalog key order and uniqueness"`
}

// DescribeTableResult is the grouped catalog answer. The primary key and indexes
// are charged before columns in internal/db, so a bound never leaves an agent
// with a misleading partial key or index. Truncation still names the bound that
// cut the column list: row_cap means the catalog read stopped, byte_budget means
// the assembled answer ran out of room, and none means the description is whole.
type DescribeTableResult struct {
	Tables     []DescribedTable `json:"tables" jsonschema:"one entry per table matching the requested name and optional schema"`
	Truncation db.Truncation    `json:"truncation" jsonschema:"which bound cut this answer: none means the complete description fit; row_cap means the column catalog read stopped; byte_budget means the assembled answer ran out of room. Under either non-none value the returned tables and columns are only the beginning of the catalog result, but every returned primary_key and indexes list remains complete"`
	RowCap     int              `json:"row_cap" jsonschema:"the row cap that applied to each catalog read"`
	ByteBudget int              `json:"byte_budget" jsonschema:"the most bytes this result's table descriptions may occupy"`
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

// registerTools installs the five tools on an SDK server.
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

	// The description is doing one job above all others, and it is worth saying
	// which. This tool reports what exists on the server behind an alias, and on
	// PostgreSQL that is deliberately not the same set as what this server can read:
	// a cluster database that is not on its alias's configured list has no
	// connection and no alias of its own, because creating one after startup is a
	// later objective. An agent that reads a name here and hands it to execute_query
	// as an alias gets "no database is configured under that alias" — so the
	// description, and nothing else in this process, is what stops it trying. The
	// per-engine asymmetry is stated for the same reason: on MySQL and SQL Server a
	// name is something to qualify a table with on the same alias, and on PostgreSQL
	// it is something to ask an operator to configure.
	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolListDatabases,
		Description: "List the database names one configured connection's login can see, with that engine's own system databases removed. " +
			"It answers what exists on that server, which is not the same as what this server can read: a name returned here is not an alias, and passing one to execute_query as its alias is refused. " +
			"What a name is good for depends on the dialect list_connections reports for the alias. On mysql and sqlserver, qualify a table with it in a statement you run against this same alias — database.table, or database.schema.table. " +
			"On postgresql a connection can only read the database it was configured for, so a database that is not already its own entry in list_connections cannot be queried at all until an operator configures one; this tool is how you find out which those are, and which of them are worth asking for. " +
			"The list is capped like any other result and says so when the cap cut it off.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.listDatabases)

	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolSearchSchema,
		Description: "Find tables and columns in the one database an alias is bound to, by a plain case-insensitive substring; aliases not bound to one database are refused. " +
			"Pass an alias from list_connections and ordinary text such as archive or measure; do not write LIKE wildcards, because % and _ are searched literally. " +
			"Results are grouped by table, capped under the same server-configured row limit reported by list_connections, and bounded again by a byte budget so that no pattern can return the whole schema. If truncation is non-none, the tables listed are only the beginning of what matched and a listed table can have only part of its matching columns: search again with a longer or more specific substring rather than treating the answer as complete. " +
			"A table's own columns_truncated tells you which one that was, and an empty column list means no column matched only on a table where it is false.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.searchSchema)

	// The schema name in this tool's answer has the same alias-safety burden as
	// list_databases: it is useful to qualify a table, but it is not a configured
	// connection. Saying that here is what keeps a discovered namespace from being
	// handed back as an alias. The description also says why the short-answer
	// signal exists: columns may be cut, but the key and index detail never is.
	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolDescribeTable,
		Description: "Describe one table in the database an alias is bound to, including every column's type and nullability, the primary key, and the secondary indexes with their key columns and uniqueness. " +
			"Pass an alias from list_connections and an exact table name; leave schema out to receive every matching table, or pass a returned schema name to narrow the answer. A schema name is not an alias. " +
			"The answer is bounded by the server-configured row cap and byte budget, and truncation says which bound cut it. A short answer can contain only the beginning of the column list, while its primary key and indexes remain complete.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.describeTable)
}

// caller resolves the two identity fields of an audit event from the context the
// SDK handed this handler.
//
// internal/auth puts an [auth.Identity] on the request it admits and this reads
// it back out, which works only because the identity survives the SDK's
// dispatch between those two points — a property of Stateless: true rather than
// a documented contract, pinned by
// TestAnIdentitySetOnTheRequestContextSurvivesTheSDKsDispatchToTheToolHandler.
//
// There is no identity when the server was built with a nil Middleware. Every
// test in this package does that, and no deployment can: the binary refuses to
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
func (s *Server) caller(ctx context.Context, tool string) (email, subject string) {
	id, ok := auth.IdentityFrom(ctx)
	if !ok {
		s.log.Warn().
			Str("tool", tool).
			Msg("a tool call ran with no identity on its context: either no authentication middleware is installed or the identity did not survive the transport, and the audit record for this call names nobody")
		return "", ""
	}
	return id.Email, id.Subject
}

func (s *Server) listConnections(ctx context.Context, _ *sdk.CallToolRequest, _ ListConnectionsInput) (*sdk.CallToolResult, *ListConnectionsResult, error) {
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
	email, subject := s.caller(ctx, ToolListConnections)
	s.audit.Record(AuditEvent{
		Tool:     ToolListConnections,
		Identity: email,
		Subject:  subject,
		Outcome:  OutcomeAllowed,
		Rows:     len(out.Connections),
		Elapsed:  time.Since(started),
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
		return nil, nil, s.refuseOrFail(ctx, attempt{tool: ToolExecuteQuery, alias: in.Alias, statement: in.Statement}, elapsed, err)
	}

	email, subject := s.caller(ctx, ToolExecuteQuery)
	s.audit.Record(AuditEvent{
		Tool:      ToolExecuteQuery,
		Identity:  email,
		Subject:   subject,
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

func (s *Server) listDatabases(ctx context.Context, _ *sdk.CallToolRequest, in ListDatabasesInput) (*sdk.CallToolResult, *ListDatabasesResult, error) {
	started := time.Now()

	// This handler's entire safety argument is that it calls this and nothing else.
	// internal/db resolves the alias, asks the gate about its own discovery
	// statement, bounds the context and runs it inside the same read-only,
	// unconditionally-rolled-back transaction execute_query gets — so the gate is not
	// something this tool has to remember to consult, and there is no exemption to
	// widen. This package holds no SQL and no second path to a driver, and
	// TestListDatabasesIsOneCallThroughTheExecutorAndNothingElse checks that against
	// the source rather than trusting this comment.
	list, err := s.executor.ListDatabases(ctx, in.Alias)
	elapsed := time.Since(started)

	if err != nil {
		return nil, nil, s.refuseOrFail(ctx, attempt{tool: ToolListDatabases, alias: in.Alias}, elapsed, err)
	}

	email, subject := s.caller(ctx, ToolListDatabases)
	s.audit.Record(AuditEvent{
		Tool:     ToolListDatabases,
		Identity: email,
		Subject:  subject,
		Alias:    list.Alias,
		Engine:   list.Engine,
		Outcome:  OutcomeAllowed,
		// The gate's own decision on the discovery statement, recorded for the reason
		// execute_query's is: an audit line that cannot say why a statement was
		// permitted is an audit line that assumes it.
		Verdict: list.Decision.Verdict,
		Reason:  list.Decision.Reason,
		RuleID:  list.Decision.RuleID,
		// The count is what the agent was given, not what the statement returned: the
		// system databases were dropped before this point and are not something the
		// record needs to account for. Truncated is the statement's own fact and stays
		// true even when everything the cap cut off would have been excluded anyway.
		Rows:      len(list.Databases),
		Truncated: list.Truncated,
		Elapsed:   elapsed,
	})

	return nil, &ListDatabasesResult{
		Databases: list.Databases,
		Truncated: list.Truncated,
		RowCap:    list.RowCap,
	}, nil
}

func (s *Server) searchSchema(ctx context.Context, _ *sdk.CallToolRequest, in SearchSchemaInput) (*sdk.CallToolResult, *SearchSchemaResult, error) {
	started := time.Now()

	// As with list_databases, the fixed per-engine statement, gate validation,
	// bound pattern and read-only transaction all belong to internal/db. This
	// layer maps its already-grouped answer without holding SQL or regrouping it.
	search, err := s.executor.SearchSchema(ctx, in.Alias, in.Pattern)
	elapsed := time.Since(started)
	if err != nil {
		return nil, nil, s.refuseOrFail(ctx, attempt{tool: ToolSearchSchema, alias: in.Alias}, elapsed, err)
	}

	email, subject := s.caller(ctx, ToolSearchSchema)
	s.audit.Record(AuditEvent{
		Tool:      ToolSearchSchema,
		Identity:  email,
		Subject:   subject,
		Alias:     search.Alias,
		Engine:    search.Engine,
		Outcome:   OutcomeAllowed,
		Verdict:   search.Decision.Verdict,
		Reason:    search.Decision.Reason,
		RuleID:    search.Decision.RuleID,
		Rows:      len(search.Tables),
		Truncated: search.Truncation != db.NoTruncation,
		Elapsed:   elapsed,
	})

	tables := make([]SchemaSearchTable, len(search.Tables))
	for i, table := range search.Tables {
		columns := make([]SchemaSearchColumn, len(table.Columns))
		for j, column := range table.Columns {
			// Keep the MCP value boundary uniform even though this fixed API presently
			// supplies primitive metadata. A future driver representation must pass
			// through the same conversion as every execute_query value.
			columns[j] = SchemaSearchColumn{
				Name:     jsonValue(column.Name).(string),
				DataType: jsonValue(column.DataType).(string),
				Nullable: jsonValue(column.Nullable).(bool),
			}
		}
		tables[i] = SchemaSearchTable{
			Schema:  jsonValue(table.Schema).(string),
			Table:   jsonValue(table.Table).(string),
			Columns: columns,
			// Not a driver value, so not something jsonValue has anything to say about:
			// internal/db computed it about its own budget, as it did Truncated below.
			ColumnsTruncated: table.ColumnsTruncated,
		}
	}

	// A nil *CallToolResult with a typed value makes the SDK emit the value twice:
	// once as structured content and once as a duplicate JSON text block. That
	// doubling is deliberate here — it is what the MCP spec asks of a tool with
	// structured output, and a client that ignores structuredContent would
	// otherwise receive an empty result — and internal/db's byte budget is set at
	// half the ceiling this surface is graded against because of it.
	return nil, &SearchSchemaResult{
		Tables:     tables,
		Truncation: search.Truncation,
		RowCap:     search.RowCap,
		ByteBudget: search.ByteBudget,
	}, nil
}

func (s *Server) describeTable(ctx context.Context, _ *sdk.CallToolRequest, in DescribeTableInput) (*sdk.CallToolResult, *DescribeTableResult, error) {
	started := time.Now()

	// As with search_schema, internal/db owns the fixed per-engine catalog reads,
	// their gate validation and the bounded read-only transactions. This handler
	// therefore has one execution path and maps the already-bounded answer without
	// holding a second spelling of a statement or a second error path.
	description, err := s.executor.DescribeTable(ctx, in.Alias, in.Table, in.Schema)
	elapsed := time.Since(started)
	if err != nil {
		return nil, nil, s.refuseOrFail(ctx, attempt{tool: ToolDescribeTable, alias: in.Alias}, elapsed, err)
	}

	email, subject := s.caller(ctx, ToolDescribeTable)
	s.audit.Record(AuditEvent{
		Tool:      ToolDescribeTable,
		Identity:  email,
		Subject:   subject,
		Alias:     description.Alias,
		Engine:    description.Engine,
		Outcome:   OutcomeAllowed,
		Verdict:   description.Decision.Verdict,
		Reason:    description.Decision.Reason,
		RuleID:    description.Decision.RuleID,
		Rows:      len(description.Tables),
		Truncated: description.Truncation != db.NoTruncation,
		Elapsed:   elapsed,
	})

	tables := make([]DescribedTable, len(description.Tables))
	for i, table := range description.Tables {
		columns := make([]DescribeTableColumn, len(table.Columns))
		for j, column := range table.Columns {
			// These catalog values use the same conversion boundary as query rows,
			// even though the current result types make every value primitive. A
			// driver representation must not get a second path to the wire merely
			// because it arrived through a metadata read.
			columns[j] = DescribeTableColumn{
				Name:     jsonValue(column.Name).(string),
				DataType: jsonValue(column.DataType).(string),
				Nullable: jsonValue(column.Nullable).(bool),
			}
		}
		primaryKey := make([]string, len(table.PrimaryKey))
		for j, column := range table.PrimaryKey {
			primaryKey[j] = jsonValue(column).(string)
		}
		indexes := make([]DescribeTableIndex, len(table.Indexes))
		for j, index := range table.Indexes {
			columns := make([]string, len(index.Columns))
			for k, column := range index.Columns {
				columns[k] = jsonValue(column).(string)
			}
			indexes[j] = DescribeTableIndex{
				Name:    jsonValue(index.Name).(string),
				Columns: columns,
				Unique:  jsonValue(index.Unique).(bool),
			}
		}
		tables[i] = DescribedTable{
			Schema:           jsonValue(table.Schema).(string),
			Table:            jsonValue(table.Table).(string),
			Columns:          columns,
			ColumnsTruncated: jsonValue(table.ColumnsTruncated).(bool),
			PrimaryKey:       primaryKey,
			Indexes:          indexes,
		}
	}

	// The SDK emits this typed value both as structured content and as a JSON text
	// block. Keeping that doubled rendering here, as search_schema does, is why
	// internal/db charges this result against the same half-wire byte budget.
	return nil, &DescribeTableResult{
		Tables:     tables,
		Truncation: description.Truncation,
		RowCap:     description.RowCap,
		ByteBudget: description.ByteBudget,
	}, nil
}

// attempt is what [Server.refuseOrFail] has to know about the call that failed.
//
// It exists so that list_databases, search_schema and describe_table share one
// reduction from a *db.Error to what the agent may read, instead of the next tool
// getting a copy.
// That reduction is the credential guarantee at this boundary, and two copies of it
// are two places for the next tool to diverge from — see the ADR behind
// [agentError].
type attempt struct {
	tool  string
	alias string
	// statement is the agent's own SQL, and it is empty for list_databases,
	// search_schema and describe_table: those tools' statements are internal/db's
	// per-engine constants, which this package does not hold and must not hold
	// second spellings of just to fill a field. The tool name says exactly which
	// statement ran.
	statement string
}

// refuseOrFail audits a failed call and reduces its error to what the agent may
// read.
//
// Both halves happen here and in this order so that neither can be skipped: a
// call that produced no audit line is a call the log cannot account for, and
// that includes the calls nobody wanted to happen.
//
// It takes the handler's ctx for one reason: the caller's identity is on it, and
// a refusal is the audit line that most needs to say who submitted the
// statement, since nothing else in this process recorded that it was attempted.
func (s *Server) refuseOrFail(ctx context.Context, call attempt, elapsed time.Duration, err error) error {
	email, subject := s.caller(ctx, call.tool)
	event := AuditEvent{
		Tool:      call.tool,
		Identity:  email,
		Subject:   subject,
		Alias:     call.alias,
		Statement: call.statement,
		Outcome:   OutcomeFailed,
		Elapsed:   elapsed,
	}

	var dbErr *db.Error
	if !errors.As(err, &dbErr) {
		// Not a *db.Error, so this layer has a defect. The operator's side gets
		// everything; the agent's side gets a sentence with nothing in it.
		s.log.Error().Err(err).
			Str("tool", call.tool).
			Str("alias", call.alias).
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
		Str("tool", call.tool).
		Str("alias", call.alias).
		Str("kind", string(dbErr.Kind)).
		Str("detail", dbErr.Error()).
		Msg("a tool call did not return rows")

	s.audit.Record(event)
	return &agentError{message: dbErr.Agent()}
}
