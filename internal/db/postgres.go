package db

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgConn is a PostgreSQL alias. It is the one engine here that does not go
// through database/sql: pgx's own pool gives a per-connection setup hook and its
// own transaction options, and giving those up to have one code path was
// considered and rejected.
type pgConn struct {
	alias AliasSpec
	pool  *pgxpool.Pool
}

func openPostgres(spec AliasSpec, s Settings) (*pgConn, error) {
	cfg, err := postgresConfig(spec, s)
	if err != nil {
		return nil, err
	}
	// pgxpool keeps this context for its background health checks, so it must
	// outlive any request. Handing it a caller's context would silently stop the
	// pool maintaining itself the moment that caller returned.
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, openError(spec, err)
	}
	return &pgConn{alias: spec, pool: pool}, nil
}

// postgresConfig builds the pool configuration for one alias. It is separate
// from [openPostgres] so that what this package hands pgx can be asserted
// without a server, which is the only way to test the environment neutralisation
// below: its failure mode is a setting silently arriving from outside, and a
// setting that arrived is indistinguishable from one we chose unless something
// looks at the config.
func postgresConfig(spec AliasSpec, s Settings) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(postgresURL(spec))
	if err != nil {
		// The connection string is not in the wrapped error's text: pgx redacts
		// the password from a ParseConfigError, and scrub removes it again in case
		// a future version stops.
		return nil, openError(spec, err)
	}

	// pgx follows libpq: every recognised PG* variable is merged underneath the
	// connection string, so anything the string does not say is answered by the
	// environment (pgconn/config.go:356). That is right for a psql-shaped tool and
	// wrong here, where the topology comes from our own variable family and nowhere
	// else. Everything from here to the end of the function is that
	// neutralisation, and it has to be exhaustive: a setting that arrived from
	// outside looks exactly like one we chose.
	//
	// Reassigned from the spec, so PGHOST, PGPORT, PGDATABASE, PGUSER and
	// PGPASSWORD cannot decide where we connect or as whom:
	cfg.ConnConfig.Host = spec.Host
	cfg.ConnConfig.Port = uint16(spec.Port)
	cfg.ConnConfig.Database = spec.Database
	cfg.ConnConfig.User = spec.User
	cfg.ConnConfig.Password = spec.Password.reveal()
	cfg.ConnConfig.ConnectTimeout = s.ConnectTimeout
	// PGCONNECT_TIMEOUT does not only set ConnectTimeout: pgx also installs a
	// dialer carrying it (pgconn/config.go:565-571), which assigning
	// ConnectTimeout does not replace. The dialer is therefore rebuilt with ours;
	// this is what pgx itself would have built for a connect_timeout of ours.
	cfg.ConnConfig.DialFunc = (&net.Dialer{Timeout: s.ConnectTimeout}).DialContext

	// The map is replaced rather than added to. Everything pgx does not recognise
	// as a connection parameter becomes a runtime parameter and travels in the
	// startup packet, so PGOPTIONS and PGTZ arrive here as "options" and
	// "timezone". PGOPTIONS is the one that matters: with
	// PGOPTIONS=-c statement_timeout=0 the server receives that and our
	// statement_timeout in the same packet, and which one wins is map iteration
	// order.
	//
	// The bounds are startup-packet runtime parameters rather than statements
	// issued from a post-connect hook. Both work — pgx has AfterConnect and it was
	// measured doing this correctly — but a runtime parameter is part of the
	// handshake, so there is no window in which a connection exists without its
	// bounds, and no failure mode where the hook errored and the pool retried
	// without them.
	//
	// statement_timeout is the bound that makes the timeout guarantee true on this
	// engine independently of the client: the server aborts at the bound whatever
	// the client is doing, where a context deadline is the client aborting and
	// hoping the server notices. idle_in_transaction_session_timeout bounds a
	// transaction abandoned mid-flight by a dropped connection, which would
	// otherwise keep whatever it holds until the server notices the socket is
	// gone — it is what stops one of our transactions blocking someone else's
	// vacuum.
	cfg.ConnConfig.RuntimeParams = map[string]string{
		"statement_timeout":                   strconv.FormatInt(milliseconds(s.QueryTimeout), 10),
		"lock_timeout":                        strconv.FormatInt(milliseconds(s.LockTimeout), 10),
		"idle_in_transaction_session_timeout": strconv.FormatInt(milliseconds(s.QueryTimeout+s.TimeoutGrace), 10),
		"application_name":                    applicationName,
	}

	// Transport security is settled in [postgresURL], where the connection string
	// answers every ssl* key so that PGSSLMODE and PGSSLROOTCERT cannot, and where
	// passfile is answered for the same reason.
	//
	// One thing is not reachable from here: PGSERVICE, if it is set, makes pgx read
	// a service file during ParseConfig, and no connection-string value prevents
	// that — pgx tests for the key's presence and the environment can only add it.
	// Nothing from the file survives, because the connection string outranks it in
	// the same merge and every field it could reach is reassigned above, but the
	// read itself happens and a missing file makes ParseConfig fail. That is closed
	// at startup instead, by refusing to run at all: see
	// [refuseForeignConfiguration].

	cfg.MaxConns = int32(s.MaxConns)
	// Nothing is connected at construction: MinConns and MinIdleConns are zero,
	// so the pool's background goroutine has no idle resources to create. That is
	// what lets a misconfigured or unreachable alias be a query-time error rather
	// than a startup failure.
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	return cfg, nil
}

// applicationName is what all three engines will show in their own session
// views. Against a third-party production server it is the difference between
// the DBA seeing a query they can attribute and seeing an anonymous connection
// they have to hunt down.
const applicationName = "cerberus-db-mcp"

// postgresURL assembles the connection string. It is built with net/url so that
// a password containing a colon, an at sign or a percent survives, and it is
// returned rather than stored: nothing in this package holds a DSN, so nothing
// can print one.
//
// Every key that pgx would otherwise let the environment answer is written,
// including the ones this package has no use for, and that is the point rather
// than noise. pgx merges the environment underneath the connection string, so a
// key we leave out is a key PGSSLMODE, PGSSLROOTCERT, PGSSLCERT, PGSSLKEY,
// PGSSLPASSWORD, PGSSLSNI, PGSSLNEGOTIATION or PGPASSFILE gets to answer. Written
// empty, the environment loses and pgx computes the same tls.Config it would
// compute on a machine with none of them set. sslmode is spelled out for
// TLSDefault too — "prefer" is pgx's own default, so behaviour is unchanged and it
// is now ours rather than inherited.
//
// passfile is in that list because it is the second variable that makes pgx read
// a file, and unlike the service file this one can be closed here: pgx calls
// ReadPassfile unconditionally, on PGPASSFILE or on ~/.pgpass by default
// (pgconn/config.go:486, pgconn/defaults.go:24), and answers the password from it
// whenever the connection string left one empty. Written empty the open fails and
// pgx ignores it, so no file is read. It cannot change which password is used
// while a per-alias password is required and non-empty; it is written so that no
// file is opened at all, which is what criterion 1 actually says.
func postgresURL(spec AliasSpec) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(spec.User, spec.Password.reveal()),
		Host:   net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port)),
		Path:   "/" + spec.Database,
	}
	q := url.Values{}
	switch spec.TLS {
	case TLSDisable:
		q.Set("sslmode", "disable")
	case TLSRequire:
		q.Set("sslmode", "verify-full")
	case TLSRequireInsecure:
		// libpq's "require" encrypts and does not verify, which is precisely what
		// this mode promises. verify-ca and verify-full are the verifying ones.
		q.Set("sslmode", "require")
	default:
		q.Set("sslmode", "prefer")
	}
	for _, inherited := range []string{"sslrootcert", "sslcert", "sslkey", "sslpassword", "sslsni", "sslnegotiation", "passfile"} {
		q.Set(inherited, "")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// postgresDatabases is the fixed statement [Executor.ListDatabases] runs on this
// engine.
//
// The two predicates are in the statement rather than on the exclusion list
// because neither is a name. datistemplate covers template0 and template1 without
// naming them, which matters on a cluster carrying templates of its own, and
// datallowconn is the one part of "can this login use it" that is a property of the
// database: a database with datallowconn false refuses every connection including
// ours, so listing it would offer the agent something no configuration could reach.
//
// It is not filtered by privilege, and that is a limitation rather than an
// oversight. pg_database is readable by everyone, so the rows come back whether or
// not this login could connect to them; the predicate that would fix it,
// has_database_privilege, is not on the gate's safe-function allowlist and this
// objective does not widen that list. The result can therefore be longer than what
// the login can open, and the honest report of that is the connection failing when
// somebody configures one.
const postgresDatabases = "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname"

// postgresSchemaSearch is the fixed, current-database catalog query for
// [Executor.SearchSchema]. Its CTE lets the positional parameter be bound once
// even though both table and column names are compared to it.
const postgresSchemaSearch = "WITH pattern AS (SELECT $1 AS value) SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.is_nullable = 'YES' AS is_nullable, c.table_name ILIKE pattern.value ESCAPE '!' AS table_name_matched, c.column_name ILIKE pattern.value ESCAPE '!' AS column_name_matched FROM information_schema.columns AS c JOIN information_schema.tables AS t ON t.table_schema = c.table_schema AND t.table_name = c.table_name JOIN pattern ON true WHERE t.table_type = 'BASE TABLE' AND c.table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND c.table_schema NOT LIKE 'pg_temp_%' AND c.table_schema NOT LIKE 'pg_toast_temp_%' AND (c.table_name ILIKE pattern.value ESCAPE '!' OR c.column_name ILIKE pattern.value ESCAPE '!') ORDER BY c.table_schema, c.table_name, c.column_name"

// postgresSystemDatabases are the databases a cluster creates for itself.
//
// The two templates are named as well as being excluded by datistemplate above,
// which is not redundant for free: datistemplate is a flag an operator can clear,
// and a cleared flag on template1 would put a database nobody means to read into an
// agent's list. postgres is the one entry here that is a judgement rather than a
// fact — it is a real database somebody may genuinely use — and it is excluded
// because on a cluster nobody has customised it exists only as a place to connect
// to.
var postgresSystemDatabases = []string{"postgres", "template0", "template1"}

func (c *pgConn) spec() AliasSpec { return c.alias }

func (c *pgConn) close() { c.pool.Close() }

func (c *pgConn) query(ctx context.Context, statement string, rowCap int, args ...any) (*rowSet, error) {
	var out *rowSet
	err := c.withTx(ctx, txReadOnly, func(ctx context.Context, tx pgx.Tx) error {
		// statement is passed through untouched. It is the exact bytes the gate
		// approved, and any edit — a LIMIT, a comment, a wrapping subquery —
		// would make the validated text and the executed text two different
		// things.
		rows, err := tx.Query(ctx, statement, args...)
		if err != nil {
			return err
		}
		out, err = collectPgRows(rows, rowCap)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// withTx runs fn inside a transaction and rolls it back on every exit path.
//
// PostgreSQL is one of the two engines that enforces read-only itself: inside a
// transaction begun with pgx.ReadOnly the server refuses INSERT, UPDATE, DELETE,
// every CREATE, GRANT and TRUNCATE with SQLSTATE 25006. That refusal comes from
// the server, which is what makes it worth having in addition to the gate — it
// holds even if the gate is wrong.
//
// Repeatable read is asked for so that a statement reading many tables sees one
// consistent snapshot. On an MVCC engine that costs no locks; it is not a
// concurrency mitigation, it is a correctness one, and it is why READ UNCOMMITTED
// is applied to SQL Server only.
func (c *pgConn) withTx(ctx context.Context, mode txMode, fn func(context.Context, pgx.Tx) error) error {
	// Written as "anything that is not read-only" rather than as a test against
	// the writable constant, so that the read-only branch is what an unrecognised
	// mode falls into and so that this file never names the lever.
	access := pgx.ReadOnly
	if mode != txReadOnly {
		access = pgx.ReadWrite
	}
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: access,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", errNoSession, err)
	}
	defer func() {
		// A rollback on the caller's context is not a rollback when the caller's
		// context is why we are here. WithoutCancel keeps the connection's
		// identity and drops the expired deadline.
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		// The error is dropped for the reasons set out on runSQLTx: pgx closes the
		// connection when the context expires, and a closed connection has no
		// transaction left to abort. There is no commit in this package.
		_ = tx.Rollback(rollbackCtx)
	}()
	return fn(ctx, tx)
}

// collectPgRows is the pgx counterpart of collectSQLRows, and stops one row past
// the cap for the same reason. pgx decodes to Go types itself, so there is no
// scan destination to prepare.
func collectPgRows(rows pgx.Rows, rowCap int) (*rowSet, error) {
	defer rows.Close()

	out := &rowSet{rows: make([][]any, 0, min(rowCap, 64))}
	for rows.Next() {
		if len(out.rows) == rowCap {
			out.truncated = true
			break
		}
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		for i := range values {
			values[i] = normalise(values[i])
		}
		out.rows = append(out.rows, values)
	}
	// pgx defers a query's error to the iteration: Query itself returns a Rows
	// even for a statement the server rejected, and the rejection surfaces here.
	// So nothing may be concluded from the shape of the result before this
	// check — reading the field descriptions first would report "no result set"
	// for every failed query and hide the reason.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fields := rows.FieldDescriptions()
	if len(fields) == 0 {
		// See collectSQLRows: a read with no result set is a contradiction, not an
		// empty answer.
		return nil, errNoResultSet
	}
	out.columns = make([]string, len(fields))
	for i, f := range fields {
		out.columns[i] = f.Name
	}
	return out, nil
}
