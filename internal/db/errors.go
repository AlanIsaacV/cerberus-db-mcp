package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// Kind classifies an execution failure into one of a fixed, closed set of
// classes. It is the hinge of this package's credential guarantee: the agent
// never receives a driver's words, it receives the sentence [Kind] selects, and
// the set of sentences is enumerated in this file where it can be read whole.
//
// Why an allowlist and not a scrubber. A scrubber runs a pattern over the
// driver's message and hopes the pattern covers it. It fails silently the first
// time an engine emits a shape nobody anticipated — a new error format, a
// localised message, a host name in a field the pattern did not know about — and
// it fails in the direction of disclosure. Selecting from a fixed set fails in
// the other direction: an unrecognised error becomes [KindInternal], which says
// nothing at all, and the detail survives on the operator-facing side where the
// person debugging it can see it.
type Kind string

const (
	// KindRefused is the gate's terminal no. It is the one class whose
	// agent-facing text is not a fixed sentence: it carries the gate's own
	// verdict and reason, which is safe precisely because the gate is pure — its
	// Decision is a function of the statement the agent itself submitted and of
	// the ruleset, and it has never seen a credential.
	KindRefused Kind = "refused"
	// KindNeedsApproval is the gate's escalation. The agent is told which rule
	// IDs a human would have to grant.
	KindNeedsApproval Kind = "needs-approval"
	// KindUnknownAlias means no connection is configured under that name.
	KindUnknownAlias Kind = "unknown-alias"
	// KindUnavailable covers everything that stopped us reaching a working
	// session: DNS, dial, TLS, login. All four collapse into one class on
	// purpose. Distinguishing "no such host" from "wrong password" tells the
	// agent whether a credential it cannot see is valid, which is a fact about
	// the credential.
	KindUnavailable Kind = "database-unavailable"
	// KindTimeout means the statement exceeded its time bound and was stopped.
	KindTimeout Kind = "timeout"
	// KindLockTimeout means the statement waited for a lock longer than the
	// bound allows. It is separate from KindTimeout because it is the one
	// failure the agent can usefully act on by reading less at once.
	KindLockTimeout Kind = "lock-timeout"
	// KindPermissionDenied means the account cannot see that object. It is worth
	// distinguishing from KindObjectNotFound: an agent navigating a schema needs
	// to know the difference between "not there" and "not yours".
	KindPermissionDenied Kind = "permission-denied"
	// KindInvalidStatement means the engine rejected the SQL. The engine's own
	// text is withheld even here, where it is almost certainly harmless, because
	// "almost certainly" is not the standard this package holds itself to.
	KindInvalidStatement Kind = "invalid-statement"
	// KindObjectNotFound means the statement named a table, view or column the
	// engine does not have.
	KindObjectNotFound Kind = "object-not-found"
	// KindReadOnlyTransaction means the engine refused a write inside our
	// read-only transaction. Reaching the agent means something got past the
	// gate, so it is a class the operator should treat as an alarm.
	KindReadOnlyTransaction Kind = "read-only-transaction"
	// KindCancelled means the caller's context was cancelled, which in practice
	// means the agent's client hung up.
	KindCancelled Kind = "cancelled"
	// KindInternal is the collapse target: an error this package did not
	// recognise. It says nothing to the agent by design.
	KindInternal Kind = "internal"
)

// The sentinels callers assert against with errors.Is. Every [Kind] has exactly
// one, and the correspondence is checked by a test — a Kind with no sentinel
// would be a class nobody can match on.
var (
	ErrRefused              = errors.New("the statement is not provably a read")
	ErrNeedsApproval        = errors.New("the statement needs human approval")
	ErrUnknownAlias         = errors.New("no database is configured under that alias")
	ErrUnavailable          = errors.New("the database could not be reached")
	ErrTimeout              = errors.New("the statement exceeded its time bound")
	ErrLockTimeout          = errors.New("the statement waited too long for a lock")
	ErrPermissionDenied     = errors.New("the account may not read that")
	ErrInvalidStatement     = errors.New("the engine rejected the statement")
	ErrObjectNotFound       = errors.New("the statement names something the database does not have")
	ErrReadOnlyTransaction  = errors.New("the transaction is read-only and the engine refused a write")
	ErrCancelled            = errors.New("the call was cancelled")
	ErrInternalDatabaseFail = errors.New("the database call failed")
)

var kindSentinels = map[Kind]error{
	KindRefused:             ErrRefused,
	KindNeedsApproval:       ErrNeedsApproval,
	KindUnknownAlias:        ErrUnknownAlias,
	KindUnavailable:         ErrUnavailable,
	KindTimeout:             ErrTimeout,
	KindLockTimeout:         ErrLockTimeout,
	KindPermissionDenied:    ErrPermissionDenied,
	KindInvalidStatement:    ErrInvalidStatement,
	KindObjectNotFound:      ErrObjectNotFound,
	KindReadOnlyTransaction: ErrReadOnlyTransaction,
	KindCancelled:           ErrCancelled,
	KindInternal:            ErrInternalDatabaseFail,
}

// agentMessages is the allowlist. Every sentence an agent can be told about a
// failed execution is here, in full, as a constant. Nothing in this map is
// composed from an engine's bytes, a DSN or an [AliasSpec], which is what makes
// the credential guarantee a property of the code rather than of a test.
var agentMessages = map[Kind]string{
	KindRefused:             "the statement was refused because it is not provably a read",
	KindNeedsApproval:       "the statement cannot be run until a human grants the listed rules",
	KindUnknownAlias:        "no database is configured under that alias",
	KindUnavailable:         "the database is not reachable right now",
	KindTimeout:             "the statement was stopped for exceeding its time limit; read less at once",
	KindLockTimeout:         "the statement waited too long for a lock and was stopped; the data is in use by someone else",
	KindPermissionDenied:    "the read-only account used for this connection may not read that object",
	KindInvalidStatement:    "the database rejected the statement as invalid",
	KindObjectNotFound:      "the statement names a table, view or column this database does not have",
	KindReadOnlyTransaction: "the database refused the statement because the connection is read-only",
	KindCancelled:           "the call was cancelled before it finished",
	KindInternal:            "the database call failed",
}

// Error is the only failure this package hands to a caller, and it is two-sided
// on purpose.
//
// Why this is a struct when the rest of the repository uses bare sentinels. A
// sentinel can carry one thing: identity. This error has to carry two texts that
// must never be confused — one for the operator's log, which should hold
// everything the engine said, and one for the agent, which must hold nothing the
// agent could not already have known. Encoding that as two sentinels, or as a
// convention about which fields a caller may format, puts the guarantee in the
// caller's hands. As a type it is in the type's hands: [Error.Agent] cannot
// return the driver's words because it does not consult them, and
// [Error.Error] — the method every logger reaches for — is the operator's side.
//
// The one thing that is scrubbed rather than selected is the password, and it is
// scrubbed on *both* sides. The threat model does not require it: logs are not
// agent-visible. It is done anyway because the cost is one string replacement
// and the failure it prevents is unrecoverable.
type Error struct {
	// Op is the verb that failed, for the operator's log: "open", "execute".
	Op string
	// Alias names the connection. It is not a secret — the agent chose it.
	Alias string
	// Engine is the dialect the statement was gated and run under.
	Engine gate.Engine
	// Kind is the class, and the only thing that selects the agent's message.
	Kind Kind
	// Decision is the gate's verdict, present for [KindRefused] and
	// [KindNeedsApproval] and nil otherwise.
	Decision *gate.Decision
	// Detail is the operator-facing text: whatever the engine or the driver
	// actually said, with the password removed. It is never shown to the agent.
	Detail string

	// cause is the driver's own error, kept so that this package's tests can
	// assert on an engine's SQLSTATE or error number rather than on its message
	// text. It is unexported deliberately: exporting it would hand a caller the
	// driver's error, and therefore its message, which is the one object this
	// type exists to keep away from the agent. [Error.Unwrap] returns the
	// sentinel instead, so errors.Is asks about the class and cannot accidentally
	// reach the engine's words.
	cause error
}

// Error is the operator-facing rendering. It includes Detail, because an
// operator who cannot see the engine's own words cannot debug a VPN, a
// certificate or a permission.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("db: ")
	b.WriteString(e.Op)
	if e.Alias != "" {
		fmt.Fprintf(&b, " on alias %q", e.Alias)
	}
	fmt.Fprintf(&b, ": %s: %s", e.Kind, e.Unwrap())
	if e.Decision != nil && e.Decision.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Decision.Detail)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Detail)
	}
	return b.String()
}

// Unwrap returns the sentinel for this error's [Kind], so that callers assert
// with errors.Is rather than by matching text.
func (e *Error) Unwrap() error {
	if sentinel, ok := kindSentinels[e.Kind]; ok {
		return sentinel
	}
	return ErrInternalDatabaseFail
}

// Agent is the agent-facing rendering: a sentence chosen from [agentMessages] by
// [Error.Kind], plus the gate's own reason when the gate is what refused.
//
// It never consults [Error.Detail]. That is the whole mechanism, and it is why
// there is no list of patterns to keep up to date: a host name cannot appear in
// this string because no code path puts one there.
func (e *Error) Agent() string {
	msg, ok := agentMessages[e.Kind]
	if !ok {
		msg = agentMessages[KindInternal]
	}
	if e.Decision == nil {
		return msg
	}
	// The gate's reason and rule ID are added because a refusal the agent cannot
	// understand is a refusal it will retry verbatim. They are safe for the
	// reason given on [KindRefused].
	var b strings.Builder
	b.WriteString(msg)
	fmt.Fprintf(&b, " (%s", e.Decision.Reason)
	if e.Decision.RuleID != "" {
		fmt.Fprintf(&b, ", rule %s", e.Decision.RuleID)
	}
	if len(e.Decision.Pending) > 0 {
		fmt.Fprintf(&b, ", pending %s", strings.Join(e.Decision.Pending, " "))
	}
	b.WriteString(")")
	if e.Decision.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Decision.Detail)
	}
	return b.String()
}

// refusalError turns a non-Allow verdict into an [Error]. The decision is copied
// so that the caller cannot reach the gate's own value through the pointer.
func refusalError(spec AliasSpec, d gate.Decision) *Error {
	kind := KindRefused
	if d.Verdict == gate.NeedsApproval {
		kind = KindNeedsApproval
	}
	return &Error{Op: "execute", Alias: spec.Alias, Engine: spec.Engine, Kind: kind, Decision: &d}
}

// openError is the failure of opening an alias's pool. Every engine's open path
// builds the same error, and it is one function rather than four literals
// because scrub is the part that must not be forgotten: a driver's complaint
// about a connection string is the one error that has the password in it by
// construction.
func openError(spec AliasSpec, err error) *Error {
	return &Error{
		Op:     "open",
		Alias:  spec.Alias,
		Engine: spec.Engine,
		Kind:   KindUnavailable,
		Detail: scrub(spec, err.Error()),
	}
}

// executionError classifies a driver or engine error and builds the two-sided
// error for it. ctx is consulted because a driver's own words for "the caller
// gave up" differ per driver while the context's do not.
func executionError(ctx context.Context, op string, spec AliasSpec, err error) *Error {
	return &Error{
		Op:     op,
		Alias:  spec.Alias,
		Engine: spec.Engine,
		Kind:   classify(ctx, err),
		Detail: scrub(spec, err.Error()),
		cause:  err,
	}
}

// scrub removes the alias's password from a string. It is the only text
// transformation in this file, it runs on the operator-facing side only, and it
// is not load-bearing for the agent guarantee — see [Error].
func scrub(spec AliasSpec, s string) string {
	pw := spec.Password.reveal()
	if pw == "" {
		return s
	}
	return strings.ReplaceAll(s, pw, redacted)
}

// classify maps an error to its [Kind] from the engine's own machine-readable
// code, never from its message text. A code is a stable contract; a message is
// not, and matching on messages is how an allowlist quietly becomes a
// best-effort guess.
func classify(ctx context.Context, err error) Kind {
	if err == nil {
		return KindInternal
	}

	// Ahead of the context, and it is the only class that is. A read-only
	// violation is the one [Kind] this package calls an alarm: it means a write
	// reached the engine, which means something got past the gate. Losing that
	// signal to a deadline that happened to expire in the same instant would lose
	// the only evidence the operator gets. It is safe to test first because it is
	// the one class that cannot also be a spelling of "stopped at the bound" — no
	// engine reports a timeout as a refused write — so unlike the classes below it
	// costs the context nothing to check ahead of it. This is not a general
	// ordering rule; every other class stays anchored on the context for the reason
	// given there.
	if isReadOnlyViolation(err) {
		return KindReadOnlyTransaction
	}

	// The context is checked next, and it decides on its own state rather than on
	// what the error turned out to be. A driver reports an expired deadline in its
	// own vocabulary — sometimes as the context error, sometimes as a cancellation,
	// sometimes as a torn-down connection surfacing as "unexpected EOF", sometimes
	// as an engine-side abort that arrived just before the deadline — and which one
	// the caller happens to see must not decide what the agent is told. Anchoring
	// on the context's own state is the only version of this check that does not
	// have to enumerate those spellings, and enumerating them is how a caller that
	// timed out ends up being told the call failed for an unknown reason.
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return KindTimeout
	case ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return KindTimeout
	case errors.Is(err, context.Canceled):
		// Reached only with a context that is not past its deadline, so this is a
		// caller that hung up rather than a bound that expired.
		return KindCancelled
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return classifyPostgres(pgErr)
	}
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return classifyMySQL(myErr)
	}
	var msErr mssql.Error
	if errors.As(err, &msErr) {
		return classifySQLServer(msErr)
	}
	if isConnectionLost(err) {
		return KindUnavailable
	}
	return KindInternal
}

// The two codes that mean the engine's own read-only enforcement refused a
// write. They are named rather than written inline because they are the only
// codes this file matches in two places — here and in the per-engine tables
// below — and a copy of a magic number is how the two quietly stop agreeing.
//
// SQL Server has no member here because it has no read-only transaction to
// violate; see msConn.withTx.
const (
	pgReadOnlySQLTransaction = "25006" // read_only_sql_transaction
	mysqlReadOnlyTransaction = 1792    // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
)

// isReadOnlyViolation reports whether the engine refused a write because our
// transaction is read-only. It is matched on the code and not on the message for
// the reason given on [classify], and it is scoped to exactly these two codes:
// widening it to anything that merely resembles a write refusal would put a class
// ahead of the context check that could also be a timeout.
func isReadOnlyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgReadOnlySQLTransaction
	}
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == mysqlReadOnlyTransaction
	}
	return false
}

// isConnectionLost covers the errors that mean "there is no working session",
// whether because one was never established or because the one we had went away.
func isConnectionLost(err error) bool {
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, errNoSession) ||
		errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, mysqldriver.ErrInvalidConn) ||
		errors.Is(err, net.ErrClosed)
}

// errNoSession marks every failure that happened before a statement was sent: no
// route, no socket, a rejected login, a TLS handshake that did not complete, a
// pool that could not hand out a connection.
//
// It exists so that this whole class can be classified structurally rather than
// by recognising each way it can be spelled. The alternative is a growing list of
// typed checks — net.Error, x509 verification failures, each driver's own
// connect error, and then the ones that are neither typed nor documented, like a
// certificate Go's x509 refuses to parse — and every gap in that list collapses
// to [KindInternal] and tells the agent nothing. Where the failure happened is
// something this package knows for certain; what the failure was called is not.
var errNoSession = errors.New("no session could be established")

// errNoResultSet is returned when a statement the gate allowed produced no
// result set at all. The gate only allows reads, so a statement that returns
// nothing to read means either the gate let something through or the driver lost
// the session — both of which are worth their own error rather than an empty
// success.
//
// It is deliberately not part of [isConnectionLost]. "The gate let a non-read
// through" is a defect in this process, not a fact about the network, and
// classifying it as [KindUnavailable] would tell the agent the database is
// unreachable and put database-unavailable in the operator's log for a database
// that answered. It falls through to [KindInternal], which says nothing to the
// agent and leaves the condition in Detail where the operator can see it.
var errNoResultSet = errors.New("the statement returned no result set")

// classifyPostgres maps a SQLSTATE. Only the classes this project can actually
// provoke are listed; everything else collapses, which is the intended
// behaviour and not an omission.
func classifyPostgres(e *pgconn.PgError) Kind {
	switch e.Code {
	case "57014": // query_canceled — what statement_timeout raises
		return KindTimeout
	case "55P03": // lock_not_available — what lock_timeout raises
		return KindLockTimeout
	case pgReadOnlySQLTransaction:
		return KindReadOnlyTransaction
	case "42501": // insufficient_privilege
		return KindPermissionDenied
	case "42P01", "42703", "42P02", "3F000", "42883": // undefined table, column, parameter, schema, function
		return KindObjectNotFound
	case "42601", "42P18", "42804", "22P02": // syntax_error and the "your SQL is wrong" neighbours
		return KindInvalidStatement
	}
	switch {
	case strings.HasPrefix(e.Code, "08"), // connection exception
		strings.HasPrefix(e.Code, "28"), // invalid authorization specification
		e.Code == "3D000",               // invalid_catalog_name — no such database
		e.Code == "53300":               // too_many_connections
		return KindUnavailable
	case strings.HasPrefix(e.Code, "42"):
		return KindInvalidStatement
	}
	return KindInternal
}

// classifyMySQL maps a server error number.
func classifyMySQL(e *mysqldriver.MySQLError) Kind {
	switch e.Number {
	case 3024, 1907:
		// 3024 is ER_QUERY_TIMEOUT, what max_execution_time raises on MySQL 8.
		// 1907 is the number this objective's findings record for the same
		// condition, from the optimizer-hints documentation. Both are mapped
		// because a superset costs nothing here and picking one would mean
		// deciding, on no evidence, which document is wrong.
		return KindTimeout
	case 1205: // ER_LOCK_WAIT_TIMEOUT
		return KindLockTimeout
	case 1213: // ER_LOCK_DEADLOCK — our session was chosen as the victim
		return KindLockTimeout
	case mysqlReadOnlyTransaction:
		return KindReadOnlyTransaction
	case 1142, 1143, 1370: // table, column and routine access denied
		return KindPermissionDenied
	case 1146, 1054, 1109, 1305: // unknown table, column, table in scope, function
		return KindObjectNotFound
	case 1064, 1149: // ER_PARSE_ERROR and its sibling
		return KindInvalidStatement
	case 1045, 1044, 1049, 1130, 1040, 1226, 2002, 2003, 2005, 2006:
		// Access denied, unknown database, host not allowed, too many
		// connections, resource limits, and the client-side "can't connect"
		// numbers. All of them mean there is no session to run in, and none of
		// them is distinguished for the agent.
		return KindUnavailable
	case 1317, 1927: // ER_QUERY_INTERRUPTED, ER_CONNECTION_KILLED
		return KindTimeout
	}
	return KindInternal
}

// classifySQLServer maps a server error number. This is the engine with no
// read-only transaction, so it is also the engine where an unexpected class is
// most worth collapsing rather than guessing at.
func classifySQLServer(e mssql.Error) Kind {
	switch e.Number {
	case 1222: // Lock request time out period exceeded — what SET LOCK_TIMEOUT raises
		return KindLockTimeout
	case 1205: // deadlock victim
		return KindLockTimeout
	case 208, 207, 4104, 1087: // invalid object name, invalid column name, multi-part id, undeclared table variable
		return KindObjectNotFound
	case 229, 230, 262, 300, 297: // SELECT/EXECUTE permission denied and friends
		return KindPermissionDenied
	case 102, 156, 105, 103, 137, 8180: // syntax errors and unclosed literals
		return KindInvalidStatement
	case 18456, 18452, 4060, 40615, 233, 10054, 10061, 40613, 49918, 49919, 49920:
		// Login failed, cannot open database, and the transport and
		// throttling numbers a remote instance produces. One class.
		return KindUnavailable
	case 3960, 3961: // snapshot isolation update conflict
		return KindInvalidStatement
	}
	return KindInternal
}
