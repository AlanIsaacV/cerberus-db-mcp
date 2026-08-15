// Package db opens, configures and executes exactly one gate-approved read
// statement against MySQL, PostgreSQL or SQL Server.
//
// This is where three of this project's four guarantees are actually enforced,
// and not one of them can be enforced by looking at the statement text:
//
//   - Blast radius. The gate cannot tell pg_sleep(1) from pg_sleep(999999), and
//     an unbounded WITH RECURSIVE is a magnitude rather than a name. So every
//     execution carries a server-side time bound, a lock bound and a row cap,
//     and the row cap is applied by stopping the iteration rather than by
//     rewriting the statement.
//   - Containment. T-SQL has no read-only transaction, so on SQL Server the gate
//     is the only preventive layer that will ever exist and an unconditionally
//     rolled-back transaction is the only containment layer. Every execution on
//     every engine runs inside one, and this package contains no commit.
//   - Credential invisibility. The process holds the password in memory whatever
//     we do, so a credential store would buy nothing. The only path by which a
//     credential can actually reach the agent is an error message, because an
//     engine error is the one thing that carries a host, a username or a DSN
//     outward. Every error crossing this boundary is therefore two-sided: see
//     [Error].
//
// The package has no dependency on the MCP SDK, on HTTP or on any transport, and
// it owns no logger. It returns what would be logged — alias, engine, verdict,
// row count and elapsed time on the way out, and a two-sided [Error] on the way
// in — and leaves what to record to its caller.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// conn is one alias's pool. The interface is small on purpose: everything that
// differs between the three engines — DSN assembly, session mitigations,
// transaction options, which driver decodes the rows — is settled inside the
// per-engine file, and what crosses back is engine-neutral.
//
// It deliberately does not expose a "begin a transaction" operation. If it did,
// a caller inside this package could run a statement outside one.
type conn interface {
	spec() AliasSpec
	// query runs an already-gated statement inside a read-only,
	// unconditionally-rolled-back transaction and returns at most rowCap rows.
	query(ctx context.Context, statement string, rowCap int, args ...any) (*rowSet, error)
	close()
}

// Executor is the package's entry point: the alias registry, the gate, and the
// bounds every execution runs under.
//
// It holds the gate itself rather than trusting its caller to have validated
// already. That is what makes "refused before a connection is used" a property
// of this type instead of a convention someone can forget to follow — and the
// order inside [Executor.Execute] is the whole of the argument, so it is worth
// reading there.
type Executor struct {
	gate     *gate.Gate
	settings Settings
	conns    map[string]conn
	order    []string
}

// Alias is what the registry will say about a connection out loud. It is name
// and engine and nothing else: the host, the port, the database name and the
// user are all things an error is forbidden to carry, so a listing must not
// carry them either.
type Alias struct {
	Name   string      `json:"name"`
	Engine gate.Engine `json:"engine"`
}

// ErrNoGate reports a nil gate. It is a sentinel rather than a panic because
// this is the one construction mistake that would leave every guarantee in this
// package unenforced, and an error at startup is easier to notice in a deploy
// log than a stack trace.
var ErrNoGate = errors.New("no gate was supplied")

// New builds an executor over an already-parsed configuration.
//
// No connection is made here and nothing is pinged. Reachability is not a
// configuration property: a third-party server behind a VPN is unreachable for
// reasons that have nothing to do with whether this process is configured
// correctly, and a server that refuses to start when the VPN is down is a server
// that cannot be deployed. A bad password or an unreachable host therefore
// surfaces on the first query, as a [KindUnavailable] error, which is exactly
// where an operator can act on it.
func New(g *gate.Gate, cfg *Config) (*Executor, error) {
	if g == nil {
		return nil, fmt.Errorf("db: new executor: %w", ErrNoGate)
	}
	if cfg == nil || len(cfg.Aliases) == 0 {
		return nil, fmt.Errorf("db: new executor: %w", ErrNoAliases)
	}
	// Before the loop below, because the loop is where a driver would read the
	// file. It is here rather than in [LoadConfigFrom] so that it holds for a
	// caller who built a [Config] by hand as well as for one who loaded it.
	if err := refuseForeignConfiguration(cfg.Aliases); err != nil {
		return nil, err
	}
	e := &Executor{
		gate:     g,
		settings: cfg.Settings,
		conns:    make(map[string]conn, len(cfg.Aliases)),
	}
	for _, spec := range cfg.Aliases {
		c, err := openConn(spec, cfg.Settings)
		if err != nil {
			e.Close()
			return nil, err
		}
		e.conns[spec.Alias] = c
		e.order = append(e.order, spec.Alias)
	}
	return e, nil
}

// Open builds an executor from the process environment. It is [LoadConfig]
// followed by [New], and it is the constructor a server's startup path wants: a
// misconfigured alias fails here, before anything is listening.
func Open(g *gate.Gate) (*Executor, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return New(g, cfg)
}

func openConn(spec AliasSpec, s Settings) (conn, error) {
	switch spec.Engine {
	case gate.PostgreSQL:
		return openPostgres(spec, s)
	case gate.MySQL:
		return openMySQL(spec, s)
	case gate.SQLServer:
		return openSQLServer(spec, s)
	default:
		// Unreachable through [LoadConfigFrom], which parses the engine through
		// gate.ParseEngine. It is here because "unreachable" is a claim about
		// today's callers and this is the one place a fourth engine would have to
		// be wired in.
		return nil, fmt.Errorf("db: alias %q: engine %q has no driver: %w", spec.Alias, spec.Engine, ErrInvalidVariable)
	}
}

// Aliases lists the configured connections in the order they were declared.
func (e *Executor) Aliases() []Alias {
	out := make([]Alias, 0, len(e.order))
	for _, name := range e.order {
		out = append(out, Alias{Name: name, Engine: e.conns[name].spec().Engine})
	}
	return out
}

// Settings returns the bounds in force, so a caller can tell the agent what the
// row cap and the time limit are without holding a second copy of them.
func (e *Executor) Settings() Settings { return e.settings }

// Close releases every pool. It is safe to call while executions are in flight,
// and safe to call twice.
//
// It deliberately leaves e.conns and e.order alone. Both are written once, in
// [New], and are then immutable for the object's lifetime — which is what makes
// [Executor.Execute] and [Executor.Aliases] safe to call from many goroutines
// without a mutex. Emptying them here instead would be a concurrent map write
// against every in-flight call, and this executor exists to serve concurrent
// tool calls that shutdown will overlap; that is a hard runtime crash rather
// than a race a test might tolerate missing.
//
// A query that arrives after Close therefore reaches a closed pool rather than
// an empty registry. Both drivers report that from the point where a transaction
// is begun — pgxpool returns "closed pool" and database/sql returns
// "sql: database is closed" — and both are wrapped in errNoSession by the
// per-engine withTx, so the caller is told the database is unavailable. That is
// the honest answer for a process that is shutting down.
func (e *Executor) Close() {
	for _, name := range e.order {
		if c, ok := e.conns[name]; ok {
			c.close()
		}
	}
}

// Execute validates one statement and, if the gate allows it, runs it.
//
// The order of the first three steps is the acceptance criterion, not an
// implementation detail:
//
//  1. Resolve the alias. This is a map lookup. It has to come first because the
//     gate's rules are per-dialect and the alias is what says which dialect.
//  2. Ask the gate. Nothing above has touched a socket, so a refusal here is a
//     refusal before any connection was borrowed and before any DSN was
//     assembled. The verdict returned is the gate's own, unedited.
//  3. Only then bound the context and borrow a connection.
//
// A statement the gate refuses therefore costs one map lookup and one pure
// function call, which also means an agent cannot use refused statements to make
// this process open connections.
func (e *Executor) Execute(ctx context.Context, alias, statement string, grants []gate.Grant) (*Result, error) {
	c, ok := e.conns[alias]
	if !ok {
		return nil, &Error{Op: "execute", Alias: alias, Kind: KindUnknownAlias}
	}
	spec := c.spec()

	decision := e.gate.Validate(spec.Engine, statement, grants)
	if decision.Verdict != gate.Allow {
		return nil, refusalError("execute", spec, decision)
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.settings.statementDeadline(spec.Engine))
	defer cancel()

	rows, err := c.query(ctx, statement, e.settings.RowCap)
	if err != nil {
		return nil, executionError(ctx, "execute", spec, err)
	}
	return &Result{
		Alias:     alias,
		Engine:    spec.Engine,
		Decision:  decision,
		Columns:   rows.columns,
		Rows:      rows.rows,
		Truncated: rows.truncated,
		RowCap:    e.settings.RowCap,
		Elapsed:   time.Since(started),
	}, nil
}

// ListDatabases reports the databases an alias's login can reach, by running one
// fixed per-engine metadata statement on that alias's existing connection.
//
// It is [Executor.Execute] with the statement chosen here instead of by the agent,
// and it keeps every step of it deliberately: the alias is resolved first, the gate
// is asked before any connection is borrowed, the same context deadline applies, the
// same row cap applies, and the statement runs inside the same read-only
// transaction that is rolled back on every exit path. Running it around the gate
// instead would create an exemption — a statement this process executes that no rule
// had to allow — and the value of there being no such thing is worth more than the
// two calls it saves.
//
// It opens no connection, caches nothing, and takes no argument but the alias. A
// pattern or a limit would be a second input to a statement whose whole safety
// property is that it is a constant, and the answer is small enough that filtering
// it is the caller's business.
//
// The gate is asked with no grants and never with any. The statement is this
// package's own constant, so a verdict other than Allow does not mean a caller needs
// approval for something — it means the ruleset overlay removed a rule the baseline
// has, which is an operator's mistake to hear about rather than an agent's request
// to escalate.
func (e *Executor) ListDatabases(ctx context.Context, alias string) (*DatabaseList, error) {
	c, ok := e.conns[alias]
	if !ok {
		return nil, &Error{Op: "list-databases", Alias: alias, Kind: KindUnknownAlias}
	}
	spec := c.spec()

	d, ok := discoveryFor(spec.Engine)
	if !ok {
		// Unreachable for the same reason [openConn]'s default is, and here for the
		// same reason: this is where a fourth engine has to be given a statement, and
		// a missing one must not become an empty list of databases.
		return nil, &Error{Op: "list-databases", Alias: alias, Engine: spec.Engine, Kind: KindInternal,
			Detail: "no discovery statement is defined for this engine"}
	}

	decision := e.gate.Validate(spec.Engine, d.statement, nil)
	if decision.Verdict != gate.Allow {
		return nil, refusalError("list-databases", spec, decision)
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.settings.statementDeadline(spec.Engine))
	defer cancel()

	rows, err := c.query(ctx, d.statement, e.settings.RowCap)
	if err != nil {
		return nil, executionError(ctx, "list-databases", spec, err)
	}
	return &DatabaseList{
		Alias:     alias,
		Engine:    spec.Engine,
		Decision:  decision,
		Databases: d.names(rows.rows),
		Truncated: rows.truncated,
		RowCap:    e.settings.RowCap,
		Elapsed:   time.Since(started),
	}, nil
}

// SearchSchema finds tables and columns in the one database the selected alias
// is bound to. Like [Executor.ListDatabases], it validates its fixed statement
// before borrowing a connection and applies the ordinary deadline and row cap.
//
// pattern is deliberately a plain substring, rather than a caller-controlled
// LIKE expression. It is trimmed and must contain at least two characters; the
// bound pattern is then constructed in schemaPattern, which escapes LIKE's
// metacharacters before adding the two wildcards this package owns.
func (e *Executor) SearchSchema(ctx context.Context, alias, pattern string) (*SchemaSearch, error) {
	c, ok := e.conns[alias]
	if !ok {
		return nil, &Error{Op: "search-schema", Alias: alias, Kind: KindUnknownAlias}
	}
	spec := c.spec()

	s, ok := schemaSearchFor(spec.Engine)
	if !ok {
		return nil, &Error{Op: "search-schema", Alias: alias, Engine: spec.Engine, Kind: KindInternal,
			Detail: "no schema search statement is defined for this engine"}
	}

	decision := e.gate.Validate(spec.Engine, s.statement, nil)
	if decision.Verdict != gate.Allow {
		return nil, refusalError("search-schema", spec, decision)
	}
	// Validate the fixed statement before this configuration refusal so every
	// search statement follows the mandatory gate path; both checks precede a
	// connection borrow.
	if spec.Database == "" {
		return nil, &Error{Op: "search-schema", Alias: alias, Engine: spec.Engine, Kind: KindInvalidArgument,
			Detail: "search_schema requires the alias to be bound to one configured database"}
	}

	boundPattern, ok := schemaPattern(pattern)
	if !ok {
		// This is an input refusal, not a driver failure. Detail is only
		// available to the operator.
		return nil, &Error{Op: "search-schema", Alias: alias, Engine: spec.Engine, Kind: KindInvalidArgument,
			Detail: "pattern must contain at least two non-space characters"}
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.settings.statementDeadline(spec.Engine))
	defer cancel()

	rows, err := c.query(ctx, s.statement, e.settings.RowCap, boundPattern)
	if err != nil {
		return nil, executionError(ctx, "search-schema", spec, err)
	}
	return &SchemaSearch{
		Alias:     alias,
		Engine:    spec.Engine,
		Decision:  decision,
		Tables:    schemaTables(rows.rows),
		Truncated: rows.truncated,
		RowCap:    e.settings.RowCap,
		Elapsed:   time.Since(started),
	}, nil
}
