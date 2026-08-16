package db

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// myConn is a MySQL alias, behind database/sql.
type myConn struct {
	alias AliasSpec
	pool  *sql.DB
}

// serverBound says whether a MySQL connection carries the server-side time
// bound. The zero value carries it.
//
// It exists for one test and no other caller. The claim that a session
// max_execution_time is what stops a runaway query — rather than the context
// deadline, which measurably does not — is only proven by a test that removes the
// bound and shows the same query surviving. Without [boundOmitted] that test
// cannot be written, and the bound is then something we believe rather than
// something we know.
//
// No non-test file in this package names boundOmitted, and a test asserts that.
type serverBound int

const (
	boundEnforced serverBound = iota
	boundOmitted
)

func openMySQL(spec AliasSpec, s Settings) (*myConn, error) {
	pool, err := openMySQLPool(spec, s, boundEnforced)
	if err != nil {
		return nil, err
	}
	return &myConn{alias: spec, pool: pool}, nil
}

func openMySQLPool(spec AliasSpec, s Settings, bound serverBound) (*sql.DB, error) {
	connector, err := mysqldriver.NewConnector(mysqlConfig(spec, s, bound))
	if err != nil {
		return nil, openError(spec, err)
	}
	pool := sql.OpenDB(connector)
	applyPoolLimits(pool, s)
	return pool, nil
}

// applyPoolLimits is shared by the two database/sql engines. The idle count
// matches the maximum because the pool's purpose is to avoid a handshake per
// call against a server across a VPN, and a lifetime is set because a
// long-lived connection through a tunnel outlives the tunnel.
func applyPoolLimits(pool *sql.DB, s Settings) {
	pool.SetMaxOpenConns(s.MaxConns)
	pool.SetMaxIdleConns(s.MaxConns)
	pool.SetConnMaxLifetime(30 * time.Minute)
	pool.SetConnMaxIdleTime(5 * time.Minute)
}

// mysqlConfig assembles the driver configuration.
//
// The session variables are the important part of this function, and the reason
// they are here rather than in a post-connect hook is that the driver applies
// Params as a single SET on connect, before any query of ours can run. There is
// no window.
//
//   - max_execution_time is the whole of MySQL's timeout guarantee. A context
//     deadline does not stop a MySQL query: measured, the caller gets "context
//     deadline exceeded" at the bound while information_schema.processlist still
//     shows the query running, and it only disappears when it finishes on its
//     own — the driver's cancellation path closes the TCP socket and never sends
//     KILL QUERY. Without this variable, "no query can exceed a time bound" is
//     simply false on this engine.
//
//     Its documented limitation is stated here because it is a limitation and not
//     a detail: it applies to top-level SELECT only. A read that is not a
//     top-level SELECT is bounded by the context deadline, which on this engine
//     means the caller stops waiting rather than the query stopping.
//
//   - innodb_lock_wait_timeout and lock_wait_timeout bound waiting for a row lock
//     and for a metadata lock respectively. The second matters more than it
//     looks: its default is 31536000 seconds, MySQL's one-year "no timeout"
//     sentinel, so an unset lock_wait_timeout means a read blocked behind
//     someone's DDL waits effectively forever.
//
//   - transaction_isolation is left alone. MySQL is MVCC and a plain read takes
//     no shared locks, so READ UNCOMMITTED would buy nothing and would change
//     what the agent sees.
func mysqlConfig(spec AliasSpec, s Settings, bound serverBound) *mysqldriver.Config {
	cfg := mysqldriver.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
	// An empty DBName is a configuration an operator may choose here: the connection
	// opens with no default schema and a qualified otherdb.table still reads. That is
	// what an alias with no CERBERUS_DB_<ALIAS>_DATABASES means on this engine.
	cfg.DBName = spec.Database
	cfg.User = spec.User
	cfg.Passwd = spec.Password.reveal()
	cfg.Timeout = s.ConnectTimeout
	// DATETIME and friends arrive as time.Time rather than as a byte string, so
	// that a result set means the same thing whichever engine produced it.
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	// False is already the default. It is written out because it is the setting
	// that would let a second statement execute on this engine, and stating it
	// means any change to it appears in a diff as a line somebody added rather
	// than as a default somebody relied on.
	cfg.MultiStatements = false
	// Also the default, and kept because this service's connections sit idle in a
	// pool across a link that drops: a stale connection detected on checkout is a
	// reconnect, and one not detected is an error the agent sees for no reason of
	// its own.
	cfg.CheckConnLiveness = true
	cfg.Params = map[string]string{
		"innodb_lock_wait_timeout": strconv.FormatInt(seconds(s.LockTimeout), 10),
		"lock_wait_timeout":        strconv.FormatInt(seconds(s.LockTimeout), 10),
	}
	if bound == boundEnforced {
		cfg.Params["max_execution_time"] = strconv.FormatInt(milliseconds(s.QueryTimeout), 10)
	}

	switch spec.TLS {
	case TLSDisable:
		cfg.TLSConfig = "false"
	case TLSRequire:
		cfg.TLSConfig = "true"
	case TLSRequireInsecure:
		cfg.TLSConfig = "skip-verify"
	}

	// FormatDSN is not called and no DSN string is built: sql.OpenDB over a
	// Connector takes the typed config directly, so the password never becomes
	// part of a string that something could log. NewConnector normalises and
	// validates the config, which is where a bad TLS name or address is caught.
	return cfg
}

// mysqlDatabases is the fixed statement [Executor.ListDatabases] runs on this
// engine. It is the shortest text that answers the question, and the gate allows
// SHOW on MySQL and on no other engine (rule read-show).
//
// One property of it is worth knowing before reading a result: SHOW DATABASES
// reports the schemas the login has some privilege on and silently omits the rest,
// with no error and no indication that anything was filtered. So an account with no
// grants and a server with no databases produce the same empty answer here, and
// there is no error for this package to surface — the distinction does not exist on
// the wire.
const mysqlDatabases = "SHOW DATABASES"

// mysqlSchemaSearch is the fixed catalog query for [Executor.SearchSchema].
// DATABASE() ties information_schema to the database selected by this alias's
// connection, so a login that can see other schemas cannot search across them.
// The CTE binds MySQL's positional ? once and reuses it for both match reasons.
const mysqlSchemaSearch = "WITH pattern AS (SELECT LOWER(?) AS value) SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.is_nullable = 'YES' AS is_nullable, LOWER(c.table_name) LIKE pattern.value ESCAPE '!' AS table_name_matched, LOWER(c.column_name) LIKE pattern.value ESCAPE '!' AS column_name_matched FROM information_schema.columns AS c JOIN information_schema.tables AS t ON t.table_schema = c.table_schema AND t.table_name = c.table_name JOIN pattern ON 1 = 1 WHERE c.table_schema = DATABASE() AND t.table_type = 'BASE TABLE' AND (LOWER(c.table_name) LIKE pattern.value ESCAPE '!' OR LOWER(c.column_name) LIKE pattern.value ESCAPE '!') ORDER BY c.table_schema, c.table_name, c.column_name"

// mysqlDescribeColumns remains on information_schema because MySQL has no
// unfiltered catalog equivalent. DATABASE() still confines the answer to the
// database the alias was explicitly configured to reach.
const mysqlDescribeColumns = "WITH target AS (SELECT ? AS table_name, ? AS schema_name) SELECT c.table_schema, c.table_name, c.column_name, c.column_type, c.is_nullable = 'YES' AS is_nullable FROM information_schema.columns AS c JOIN target ON 1 = 1 WHERE c.table_schema = DATABASE() AND c.table_name = target.table_name AND (target.schema_name = '' OR c.table_schema = target.schema_name) ORDER BY c.table_schema, c.table_name, c.ordinal_position"

// mysqlDescribePrimaryKey uses ordinal_position because it is the catalog's
// statement of a composite key's order, not an order the caller may reconstruct.
const mysqlDescribePrimaryKey = "WITH target AS (SELECT ? AS table_name, ? AS schema_name) SELECT k.table_schema, k.table_name, k.column_name FROM information_schema.key_column_usage AS k JOIN target ON 1 = 1 WHERE k.table_schema = DATABASE() AND k.table_name = target.table_name AND k.constraint_name = 'PRIMARY' AND (target.schema_name = '' OR k.table_schema = target.schema_name) ORDER BY k.table_schema, k.table_name, k.ordinal_position"

// mysqlDescribeIndexes keeps non_unique raw so the Go boundary can invert its
// MySQL-specific polarity and reject every spelling other than the known 0/1.
const mysqlDescribeIndexes = "WITH target AS (SELECT ? AS table_name, ? AS schema_name) SELECT s.table_schema, s.table_name, s.index_name, s.column_name, s.non_unique FROM information_schema.statistics AS s JOIN target ON 1 = 1 WHERE s.table_schema = DATABASE() AND s.table_name = target.table_name AND s.index_name <> 'PRIMARY' AND (target.schema_name = '' OR s.table_schema = target.schema_name) ORDER BY s.table_schema, s.table_name, s.index_name, s.seq_in_index"

// mysqlSystemDatabases are the schemas MySQL keeps for itself. They are excluded
// because an agent asked to understand somebody's data model has no use for the
// server's own bookkeeping, and four names of noise in a list is four names of
// context spent.
var mysqlSystemDatabases = []string{"information_schema", "mysql", "performance_schema", "sys"}

func (c *myConn) spec() AliasSpec { return c.alias }

func (c *myConn) close() { _ = c.pool.Close() }

func (c *myConn) query(ctx context.Context, statement string, rowCap int, args ...any) (*rowSet, error) {
	var out *rowSet
	err := c.withTx(ctx, txReadOnly, func(tx *sql.Tx) error {
		// Byte-identical to what the gate approved.
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
// MySQL is the other engine that enforces read-only itself. The driver turns
// opts.ReadOnly into START TRANSACTION READ ONLY, and the server then refuses a
// write inside it with error 1792 — its refusal, not ours, which is the point of
// asking for it as well as gating the text.
func (c *myConn) withTx(ctx context.Context, mode txMode, fn func(*sql.Tx) error) error {
	return runSQLTx(ctx, c.pool, &sql.TxOptions{ReadOnly: mode == txReadOnly}, fn)
}
