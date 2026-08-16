package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"

	mssql "github.com/microsoft/go-mssqldb"
)

// msConn is a SQL Server alias, behind database/sql.
//
// This is the engine the whole project is shaped around, and it is the one with
// the least to work with:
//
//   - There is no read-only transaction. BeginTx with opts.ReadOnly does not
//     ignore the request, it returns an error, so asking for one is not even a
//     no-op. The gate is the only preventive layer, and the rollback below is the
//     only containment layer — it reverts rather than prevents.
//   - There is no statement-level server-side time bound. LOCK_TIMEOUT bounds
//     waiting for a lock and nothing else. The context deadline is the time bound
//     here, and unlike MySQL it works: on expiry the session disappears from
//     sys.dm_exec_sessions within a fraction of a second and the connection is
//     discarded rather than returned to the pool.
//   - Statements stack with no punctuation at all. "SELECT 1 SELECT 2", one
//     space, returns two result sets. Nothing in the driver's parameter list
//     suppresses the second one. That is measured, not inferred, and it is why the
//     gate's single-statement rule is load-bearing on exactly the engine that has
//     no second line of defence.
type msConn struct {
	alias AliasSpec
	pool  *sql.DB
}

func openSQLServer(spec AliasSpec, s Settings) (*msConn, error) {
	connector, err := mssql.NewConnector(sqlServerDSN(spec, s))
	if err != nil {
		return nil, openError(spec, err)
	}

	// SessionInitSQL is run by Conn.ResetSession, which database/sql calls on
	// every checkout from the pool, and by Connector.Connect right after
	// connecting. Both matter: the first means a reused connection cannot have
	// lost its mitigations, and the second means a fresh one never runs without
	// them. Issuing these by hand before each query would put the same statements
	// on the wire but would depend on every future call site remembering to.
	connector.SessionInitSQL = sessionInitSQL(s)

	pool := sql.OpenDB(connector)
	applyPoolLimits(pool, s)
	return &msConn{alias: spec, pool: pool}, nil
}

// sessionInitSQL is every mitigation SQL Server gets, and each line is here
// because of something it prevents against a third party's production server.
//
//   - LOCK_TIMEOUT: our read waits this long for a lock and then gives up. Its
//     default is -1, wait forever. Without it a read of ours can sit behind
//     someone else's transaction indefinitely, which is how a read-only tool
//     ends up in a DBA's blocking chain. It has no connection-string parameter,
//     so it has to be a statement.
//   - READ UNCOMMITTED: our reads take no shared locks, so they cannot block
//     anyone else's writes. This is the mitigation that matters most on this
//     engine and it is applied here only — MySQL and PostgreSQL are MVCC, where a
//     plain read takes no shared locks anyway and the isolation change would buy
//     nothing while changing what the agent sees. The cost is real and accepted:
//     the agent may read a row that is later rolled back. For a tool whose job is
//     understanding a schema, a dirty read is a far smaller harm than a blocked
//     production user.
//   - DEADLOCK_PRIORITY LOW: if our session and a real user's session are ever
//     both candidates, ours is the one the server kills.
//   - ARITHABORT ON is deliberately not set, and neither is anything else that
//     changes how the server plans or executes the agent's query. Every line here
//     is about what our session may do to others.
func sessionInitSQL(s Settings) string {
	return fmt.Sprintf(
		"SET LOCK_TIMEOUT %d; SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; SET DEADLOCK_PRIORITY LOW;",
		milliseconds(s.LockTimeout),
	)
}

// sqlServerDSN assembles the connection URL. net/url does the escaping, so a
// password containing an at sign or a slash survives, and the string is returned
// rather than stored.
func sqlServerDSN(spec AliasSpec, s Settings) string {
	q := url.Values{}
	// Empty is a configuration an operator may choose here: the driver then leaves
	// the choice to the login's own default database and a qualified otherdb.dbo.tbl
	// still reads. That is what an alias with no CERBERUS_DB_<ALIAS>_DATABASES means
	// on this engine.
	q.Set("database", spec.Database)
	q.Set("app name", applicationName)
	q.Set("dial timeout", strconv.FormatInt(seconds(s.ConnectTimeout), 10))
	// "connection timeout" is deliberately absent. It is the kind of omission the
	// next person adds back as obviously missing, so: the driver parses it into
	// msdsn.Config.ConnTimeout — whose own field comment reads
	// "// Use context for timeouts." — and then wraps the socket as
	// newTimeoutConn(conn, p.ConnTimeout), which resets SetDeadline(now + timeout)
	// on every Read and every Write for the whole life of the connection, not just
	// while connecting.
	//
	// On this engine, the one with no server-side statement bound, that would
	// silently make the effective statement bound ConnectTimeout instead of
	// QueryTimeout. Worse, the failure arrives as an "i/o timeout", which is a
	// net.Error, and classify sends a net.Error to KindUnavailable — so a read that
	// was merely slow would tell the agent the database is unreachable.
	//
	// Connecting is bounded by "dial timeout" above, which is a separate driver
	// field, so nothing is lost. Evidence: msdsn/conn_str.go:143,469-476,
	// tds.go:1175 and net.go:21-39 in microsoft/go-mssqldb v1.10.0.

	// The driver retries a failed connection by default. A retry against a
	// third-party server reached over a VPN doubles the time before the caller
	// hears about a problem, and the caller has its own deadline.
	q.Set("disableretry", "true")

	switch spec.TLS {
	case TLSDisable:
		// The last resort, and it is not the workaround for a certificate the client
		// does not trust — TLSRequireInsecure below is that. Against the SQL Server
		// this project is verified on, the server's own sys.dm_exec_connections
		// reports encrypt_option = FALSE for a connection opened this way and TRUE
		// for a require-insecure one, so on that instance choosing this mode does put
		// the login packet, credential included, on the wire without TLS.
		//
		// The distinction that matters, because "disable" and the driver's default
		// are not the same mode: under "disable" no tls.Config is built at all
		// (msdsn/conn_str.go:340,351) and prelogin advertises ENCRYPT_NOT_SUP
		// (session.go:38-39), so a server that does not itself insist on encryption
		// answers in kind and the handshake is skipped entirely (tds.go:1224). The
		// objective's finding that the handshake always happens and only reverts to
		// plaintext after login describes EncryptionOff — "optional", what the driver
		// uses when encrypt is absent — where that revert is explicit
		// (tds.go:1262-1266). It was read as covering "disable"; it does not.
		//
		// What "disable" does against a server that does require encryption is not
		// measured here, and the answer is not the same: that path finds TLSConfig
		// nil and builds one with full verification, which is the one thing this
		// mode is usually reached for to avoid.
		q.Set("encrypt", "disable")
	case TLSRequire:
		q.Set("encrypt", "true")
	case TLSRequireInsecure:
		q.Set("encrypt", "true")
		q.Set("trustservercertificate", "true")
	}

	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(spec.User, spec.Password.reveal()),
		Host:     net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port)),
		RawQuery: q.Encode(),
	}
	return u.String()
}

// sqlServerDatabases is the fixed statement [Executor.ListDatabases] runs on this
// engine.
//
// HAS_DBACCESS(name) = 1 is the obvious predicate and it is deliberately not here.
// Measured against the baseline ruleset as it stands, the statement carrying it
// comes back needs-approval on rule function:has_dbaccess — the gate does not have
// HAS_DBACCESS on its safe-function allowlist — which would make this package's own
// constant an escalation an operator has to grant. The rule for that situation is
// that the statement changes and the ruleset does not, so it did.
//
// Little is lost, because sys.databases is already filtered by metadata visibility:
// a login sees master and tempdb plus the databases it owns or holds a permission
// in, which is close to the set HAS_DBACCESS would have kept. What survives the
// change is that a database whose name is visible but whose access has been revoked
// can still appear in the list, and the agent finds that out by being refused when
// it asks for something in it.
const sqlServerDatabases = "SELECT name FROM sys.databases ORDER BY name"

// sqlServerSchemaSearch is the fixed, current-database catalog query for
// [Executor.SearchSchema]. sys.tables, sys.columns and sys.types have no
// database-qualified name here, so the query cannot reach a second database on
// the same login. @p1 is reusable in T-SQL; the CTE still keeps the pattern
// transformation and both match reasons visibly in one place.
//
// The two match reasons are CASE WHEN … THEN 1 ELSE 0 END and not the bare LIKE
// the other two engines use, because T-SQL has no boolean data type a column can
// carry: LIKE there is a predicate, legal in WHERE and in CASE, and a syntax
// error in a select list. PostgreSQL returns a real boolean and MySQL an integer,
// so only this engine needs the wrapping — and only this engine has no fixture
// and no CI to catch it, which is why it is written down here. The integer 1/0
// this produces is decoded by the same schemaBool that takes the other two
// engines' representations.
//
// This statement and the three describe statements below have executed against a
// real SQL Server and are valid T-SQL exactly as shipped — but once, by hand, over
// a VPN, against a single instance holding tens of tables in one schema. Nothing
// there came near the byte budget, and nothing repeats the run: the tests that did
// it skip unless CERBERUS_TEST_SQLSERVER_ALIAS names a configured alias, so what
// grades a change to any of these four by default is still the gate's unit tests.
const sqlServerSchemaSearch = "WITH pattern AS (SELECT LOWER(@p1) AS value) SELECT s.name, t.name, c.name, ty.name, c.is_nullable, CASE WHEN LOWER(t.name) LIKE pattern.value ESCAPE '!' THEN 1 ELSE 0 END AS table_name_matched, CASE WHEN LOWER(c.name) LIKE pattern.value ESCAPE '!' THEN 1 ELSE 0 END AS column_name_matched FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.columns AS c ON c.object_id = t.object_id JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id JOIN pattern ON 1 = 1 WHERE LOWER(t.name) LIKE pattern.value ESCAPE '!' OR LOWER(c.name) LIKE pattern.value ESCAPE '!' ORDER BY s.name, t.name, c.name"

// sqlServerDescribeColumns reads sys.* rather than information_schema for the
// same privilege-filtering reason as PostgreSQL. It has not executed in CI: the
// third-party SQL Server is intentionally not part of the fixture matrix.
//
// The by-hand run sent only the schema-qualified form. The unqualified one is not
// a second statement: the schema arrives as @p2 and the target.schema_name = ”
// branch chooses between them, so what stayed untested there is an argument value
// rather than any SQL these three describe statements have not already run.
const sqlServerDescribeColumns = "WITH target AS (SELECT @p1 AS table_name, @p2 AS schema_name) SELECT s.name, t.name, c.name, ty.name, c.is_nullable FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.columns AS c ON c.object_id = t.object_id JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id JOIN target ON 1 = 1 WHERE t.name = target.table_name AND (target.schema_name = '' OR s.name = target.schema_name) ORDER BY s.name, t.name, c.column_id"

// sqlServerDescribePrimaryKey orders by key_ordinal rather than by column name
// because a composite key sorted any other way is a different key. The ordinal
// itself is not selected; it only has to reach the ORDER BY.
const sqlServerDescribePrimaryKey = "WITH target AS (SELECT @p1 AS table_name, @p2 AS schema_name) SELECT s.name, t.name, c.name FROM sys.key_constraints AS k JOIN sys.tables AS t ON t.object_id = k.parent_object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.index_columns AS ic ON ic.object_id = t.object_id AND ic.index_id = k.unique_index_id JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = ic.column_id JOIN target ON 1 = 1 WHERE k.type = 'PK' AND ic.key_ordinal > 0 AND t.name = target.table_name AND (target.schema_name = '' OR s.name = target.schema_name) ORDER BY s.name, t.name, ic.key_ordinal"

// sqlServerDescribeIndexes selects the BIT is_unique, which reaches Go unchanged,
// unlike MySQL's inverted non_unique value.
const sqlServerDescribeIndexes = "WITH target AS (SELECT @p1 AS table_name, @p2 AS schema_name) SELECT s.name, t.name, i.name, c.name, i.is_unique FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = ic.column_id JOIN target ON 1 = 1 WHERE i.is_primary_key = 0 AND ic.key_ordinal > 0 AND t.name = target.table_name AND (target.schema_name = '' OR s.name = target.schema_name) ORDER BY s.name, t.name, i.name, ic.key_ordinal"

// sqlServerSystemDatabases are the four databases every instance has and nobody
// asks an agent to explore.
var sqlServerSystemDatabases = []string{"master", "model", "msdb", "tempdb"}

func (c *msConn) spec() AliasSpec { return c.alias }

func (c *msConn) close() { _ = c.pool.Close() }

func (c *msConn) query(ctx context.Context, statement string, rowCap int, args ...any) (*rowSet, error) {
	var out *rowSet
	err := c.withTx(ctx, txReadOnly, func(tx *sql.Tx) error {
		// Byte-identical to what the gate approved. On this engine that is not a
		// stylistic commitment: appending anything to the text — even a semicolon —
		// would be appending to a batch that executes whatever follows.
		rows, err := tx.QueryContext(ctx, statement, args...)
		if err != nil {
			return err
		}
		out, err = collectSQLRows(rows, rowCap)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// withTx runs fn inside a transaction that is rolled back on every exit path.
//
// The txMode argument is accepted and ignored, and the asymmetry is the point:
// on the other two engines it chooses between a read-only and a writable
// transaction, and here there is only one kind. sql.TxOptions.ReadOnly cannot be
// set at all — the driver returns "read-only transactions are not supported"
// rather than ignoring it — so this is the engine where a write that got past the
// gate would reach the table and be undone, instead of being refused.
//
// The isolation level is passed as well as being set in SessionInitSQL. The
// driver maps it to a real TDS isolation value with no extra round trip, and the
// redundancy means the mitigation survives someone emptying SessionInitSQL.
func (c *msConn) withTx(ctx context.Context, mode txMode, fn func(*sql.Tx) error) error {
	return c.withTxOn(ctx, c.pool, mode, fn)
}

// withTxOn is withTx against a caller-chosen connection. See [txBeginner]. On
// this engine it is what makes the containment test meaningful: a #temp table
// exists only on the session that created it, so a rollback can only be observed
// from that same session.
func (c *msConn) withTxOn(ctx context.Context, on txBeginner, _ txMode, fn func(*sql.Tx) error) error {
	return runSQLTx(ctx, on, &sql.TxOptions{Isolation: sql.LevelReadUncommitted}, fn)
}
