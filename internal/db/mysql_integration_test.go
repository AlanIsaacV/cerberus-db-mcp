//go:build integration

package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// mySlowRead is a read the gate allows and MySQL cannot finish quickly: a
// three-way cartesian product over information_schema.
//
// SELECT SLEEP(n) would be the obvious choice and is wrong twice. The gate
// refuses SLEEP terminally, so it cannot go through the production entry point;
// and measured against MySQL 8.4, max_execution_time interrupting a SLEEP does
// not raise an error at all — SLEEP simply returns 1 early. A statement that
// reports success is no evidence that a bound was enforced. A genuine scan does
// raise the error, which is what the criterion is about.
const mySlowReadMarker = "cerberus-mysql-timeout-probe"

func mySlowRead(marker string) string {
	return "SELECT count(*) /* " + marker + " */ FROM information_schema.columns a," +
		" information_schema.columns b, information_schema.columns c"
}

// myObserver is a second pool to the same server, built from the same alias spec.
// See [pgObserver] for why the observation has to come from somewhere else.
func myObserver(t *testing.T, spec AliasSpec, s Settings) *sql.DB {
	t.Helper()
	pool, err := openMySQLPool(spec, s, boundEnforced)
	if err != nil {
		t.Fatalf("observer pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// myRunningCount counts the sessions still executing a statement carrying marker,
// excluding the observer's own query — which contains the marker too, since it is
// searching for it.
func myRunningCount(t *testing.T, obs *sql.DB, marker string) int {
	t.Helper()
	var n int
	err := obs.QueryRow(
		"SELECT count(*) FROM information_schema.processlist WHERE info LIKE ? AND id <> CONNECTION_ID()",
		"%"+marker+"%").Scan(&n)
	if err != nil {
		t.Fatalf("read information_schema.processlist: %v", err)
	}
	return n
}

// TestMySQLSessionCarriesItsBounds asserts the session mitigations from the
// server's own view rather than from the fact that the driver was asked to set
// them.
func TestMySQLSessionCarriesItsBounds(t *testing.T) {
	h := setUp(t, gate.MySQL)

	res, err := h.Execute(context.Background(), h.alias,
		"SELECT @@max_execution_time AS met, @@innodb_lock_wait_timeout AS ilwt, @@lock_wait_timeout AS lwt", nil)
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	got := map[string]any{}
	for i, name := range res.Columns {
		got[name] = res.Rows[0][i]
	}
	// MySQL's unsigned system variables arrive as uint64, so the comparison goes
	// through a widening step rather than a type assertion. That the values keep
	// their driver types is deliberate — see [normalise], which converts only the
	// one representation an agent cannot use.
	for _, tt := range []struct {
		variable string
		column   string
		want     int64
	}{
		{"@@max_execution_time", "met", milliseconds(h.Settings().QueryTimeout)},
		{"@@innodb_lock_wait_timeout", "ilwt", seconds(h.Settings().LockTimeout)},
		// This default is 31536000 — a year, MySQL's "no timeout" sentinel — so it
		// is the bound where an unset value looks harmless and is not.
		{"@@lock_wait_timeout", "lwt", seconds(h.Settings().LockTimeout)},
	} {
		v, ok := asInt64(got[tt.column])
		if !ok {
			t.Errorf("%s came back as %#v, which is not a number", tt.variable, got[tt.column])
			continue
		}
		if v != tt.want {
			t.Errorf("%s = %d, want %d", tt.variable, v, tt.want)
		}
	}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int32:
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

// TestMySQLTransactionIsReadOnlyAsTheEngineUnderstandsIt is acceptance criterion 4
// for MySQL. The refusal is the server's own error number for a write inside
// START TRANSACTION READ ONLY.
func TestMySQLTransactionIsReadOnlyAsTheEngineUnderstandsIt(t *testing.T) {
	h := setUp(t, gate.MySQL)
	c, _ := h.connFor(h.alias)
	my := c.(*myConn)
	obs := myObserver(t, h.spec, h.Settings())
	ctx := context.Background()

	const table = "cerberus_readonly_probe"
	if _, err := obs.ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
		t.Fatalf("drop probe table: %v", err)
	}
	if _, err := obs.ExecContext(ctx, "CREATE TABLE "+table+" (marker varchar(64))"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() { _, _ = obs.Exec("DROP TABLE IF EXISTS " + table) })

	// Deliberately past the gate: the engine's own enforcement is what is under
	// test, and the gate would never let a write get this far.
	err := my.withTx(ctx, txReadOnly, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES ('should-not-arrive')")
		return err
	})
	var myErr *mysqldriver.MySQLError
	if !errors.As(err, &myErr) {
		t.Fatalf("the write inside a read-only transaction returned %v, want a MySQL error", err)
	}
	if myErr.Number != 1792 {
		t.Errorf("error number = %d, want 1792 (ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION)", myErr.Number)
	}

	// And the same write in a writable transaction is refused by nothing but the
	// rollback, which is what the containment test relies on.
	if err := my.withTx(ctx, txWritable, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES ('rolled-back')")
		return err
	}); err != nil {
		t.Fatalf("the writable probe could not write, so the containment test would prove nothing: %v", err)
	}
	var n int
	if err := obs.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows survived a writable transaction that was rolled back", n)
	}
}

// TestMySQLContainmentOnEveryExitPath is acceptance criterion 3 for MySQL. See
// [txMode] for why the transaction is writable.
func TestMySQLContainmentOnEveryExitPath(t *testing.T) {
	h := setUp(t, gate.MySQL)
	c, _ := h.connFor(h.alias)
	my := c.(*myConn)
	obs := myObserver(t, h.spec, h.Settings())
	ctx := context.Background()

	const table = "cerberus_containment_probe"
	if _, err := obs.ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
		t.Fatalf("drop probe table: %v", err)
	}
	if _, err := obs.ExecContext(ctx, "CREATE TABLE "+table+" (marker varchar(64))"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() { _, _ = obs.Exec("DROP TABLE IF EXISTS " + table) })

	// The control: a committed row does survive in this table, so "nothing
	// survived" below means the rollback and not a broken insert.
	if _, err := obs.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES ('committed-by-the-observer')"); err != nil {
		t.Fatalf("the observer cannot write to the probe table: %v", err)
	}
	var control int
	if err := obs.QueryRow("SELECT count(*) FROM " + table).Scan(&control); err != nil || control != 1 {
		t.Fatalf("the probe table does not keep committed rows (count=%d, err=%v)", control, err)
	}

	rowCount := func(t *testing.T, marker string) int {
		t.Helper()
		var n int
		if err := obs.QueryRow("SELECT count(*) FROM "+table+" WHERE marker = ?", marker).Scan(&n); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		return n
	}

	for _, tt := range []struct {
		name   string
		panics bool
		run    func(t *testing.T, marker string) error
	}{
		{
			name: "success",
			run: func(t *testing.T, marker string) error {
				return my.withTx(ctx, txWritable, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES (?)", marker)
					return err
				})
			},
		},
		{
			name: "an engine error after the write",
			run: func(t *testing.T, marker string) error {
				err := my.withTx(ctx, txWritable, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES (?)", marker); err != nil {
						return err
					}
					_, err := tx.ExecContext(ctx, "SELECT * FROM cerberus_no_such_table")
					return err
				})
				if err == nil {
					t.Fatal("the deliberately broken statement succeeded")
				}
				return nil
			},
		},
		{
			name: "a timeout after the write",
			run: func(t *testing.T, marker string) error {
				timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				err := my.withTx(timeoutCtx, txWritable, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(timeoutCtx, "INSERT INTO "+table+" (marker) VALUES (?)", marker); err != nil {
						return err
					}
					var n int
					return tx.QueryRowContext(timeoutCtx, mySlowRead("containment-timeout")).Scan(&n)
				})
				if err == nil {
					t.Fatal("the query outlived its deadline without error")
				}
				return nil
			},
		},
		{
			name:   "a panic after the write",
			panics: true,
			run: func(t *testing.T, marker string) error {
				return my.withTx(ctx, txWritable, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (marker) VALUES (?)", marker); err != nil {
						return err
					}
					panic("a bug in the middle of a transaction")
				})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			marker := "probe-" + tt.name
			runAndRecover(t, tt.panics, func() error { return tt.run(t, marker) })
			if n := rowCount(t, marker); n != 0 {
				t.Errorf("%d rows survived the %s path: the transaction was not rolled back", n, tt.name)
			}
		})
	}
}

// TestMySQLTimeoutIsEnforcedByTheServerAndNotByTheContext is acceptance criterion
// 6 for MySQL, and it is the most load-bearing test in this package.
//
// The claim being pinned is not "queries time out". It is that on this engine the
// context deadline does not stop the query, so the session bound is what does. A
// test that only showed the bounded case passing would be satisfied by either
// mechanism and would tell us nothing. So the same statement runs twice — once
// with the bound and once without — and the difference between the two is the
// evidence.
func TestMySQLTimeoutIsEnforcedByTheServerAndNotByTheContext(t *testing.T) {
	h := setUp(t, gate.MySQL)
	obs := myObserver(t, h.spec, h.Settings())
	settings := h.Settings()

	t.Run("with the session bound, the server aborts the statement", func(t *testing.T) {
		started := time.Now()
		_, err := h.Execute(context.Background(), h.alias, mySlowRead(mySlowReadMarker), nil)
		elapsed := time.Since(started)

		var dbErr *Error
		if !errors.As(err, &dbErr) {
			t.Fatalf("Execute() = %v, want a *db.Error", err)
		}
		if dbErr.Kind != KindTimeout {
			t.Fatalf("Kind = %q, want a timeout (detail: %s)", dbErr.Kind, dbErr.Detail)
		}
		var myErr *mysqldriver.MySQLError
		if !errors.As(dbErr.cause, &myErr) {
			t.Fatalf("the timeout did not come from the server: %v", dbErr.cause)
		}
		// 3024 is ER_QUERY_TIMEOUT, what MySQL 8.4 raises for max_execution_time.
		// This objective's findings record 1907 for the same condition, from the
		// optimizer-hints documentation; both are accepted here so that the test
		// pins the behaviour rather than the number, and the discrepancy is
		// reported rather than quietly resolved.
		if myErr.Number != 3024 && myErr.Number != 1907 {
			t.Errorf("error number = %d, want 3024 (or the 1907 the findings record)", myErr.Number)
		}
		if deadline := settings.QueryTimeout + settings.TimeoutGrace; elapsed >= deadline {
			t.Errorf("the call took %v, at or past the context deadline of %v: the server did not stop it first", elapsed, deadline)
		}
		// Absent from the server's own view, within the bound.
		for deadline := time.Now().Add(settings.QueryTimeout); ; {
			if myRunningCount(t, obs, mySlowReadMarker) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the aborted statement is still running on the server")
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("without the session bound, the context deadline does not stop it", func(t *testing.T) {
		// The whole point of [boundOmitted]. This pool is identical to the
		// production one except that max_execution_time is not set.
		unbounded, err := openMySQLPool(h.spec, settings, boundOmitted)
		if err != nil {
			t.Fatalf("open the unbounded pool: %v", err)
		}
		defer func() { _ = unbounded.Close() }()

		const marker = "cerberus-mysql-unbounded-probe"
		ctx, cancel := context.WithTimeout(context.Background(), settings.QueryTimeout)
		started := time.Now()
		var n int
		err = unbounded.QueryRowContext(ctx, mySlowRead(marker)).Scan(&n)
		cancel()

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("QueryRowContext() = %v, want context.DeadlineExceeded", err)
		}
		// This is the measurement the whole design rests on: the caller has already
		// given up and the server is still working.
		if running := myRunningCount(t, obs, marker); running == 0 {
			t.Fatalf("the query stopped when the context expired at %v, which contradicts the finding this layer is built on", time.Since(started))
		}

		// Left alone it would run to completion with nobody waiting for it. The
		// test cleans up after itself the only way MySQL offers, which is also the
		// mechanism this design chose not to rely on: a KILL from another session.
		killRunning(t, obs, marker)
	})
}

func killRunning(t *testing.T, obs *sql.DB, marker string) {
	t.Helper()
	rows, err := obs.Query(
		"SELECT id FROM information_schema.processlist WHERE info LIKE ? AND id <> CONNECTION_ID()",
		"%"+marker+"%")
	if err != nil {
		t.Fatalf("list runaway queries: %v", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan process id: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list runaway queries: %v", err)
	}
	_ = rows.Close()
	for _, id := range ids {
		if _, err := obs.Exec("KILL QUERY " + strconv.FormatInt(id, 10)); err != nil {
			t.Logf("kill query %d: %v", id, err)
		}
	}
}

// TestMySQLReceivesTheStatementByteForByte is acceptance criterion 7's
// byte-identity half against MySQL's general_log, which records the statement the
// server received. The log needs `--general-log=1 --log-output=TABLE`, which
// deploy/compose.test.yaml sets, and SELECT on mysql.general_log, which
// deploy/mysql-init grants.
func TestMySQLReceivesTheStatementByteForByte(t *testing.T) {
	h := setUp(t, gate.MySQL)
	obs := myObserver(t, h.spec, h.Settings())

	var logOutput string
	if err := obs.QueryRow("SELECT @@log_output").Scan(&logOutput); err != nil {
		t.Fatalf("read @@log_output: %v", err)
	}
	var generalLog int64
	if err := obs.QueryRow("SELECT @@general_log").Scan(&generalLog); err != nil {
		t.Fatalf("read @@general_log: %v", err)
	}
	if generalLog != 1 || logOutput != "TABLE" {
		t.Skipf("this server has general_log=%d and log_output=%q; start it with --general-log=1 --log-output=TABLE (see deploy/compose.test.yaml)", generalLog, logOutput)
	}

	// Every lexical trap a rewriting layer would trip over, in MySQL's dialect:
	// a block comment holding a semicolon and a DROP, a backslash escape, doubled
	// quotes and non-ASCII text.
	statement := "SELECT 1 /* cerberus-identity ; DROP TABLE x */ AS n, 'a''b\\n; sélect — ünïcode' AS lit"
	if _, err := h.Execute(context.Background(), h.alias, statement, nil); err != nil {
		t.Fatalf("Execute() = %v", err)
	}

	var seen string
	err := obs.QueryRow(
		`SELECT convert(argument using utf8mb4) FROM mysql.general_log
		 WHERE command_type = 'Query' AND argument LIKE ?
		 ORDER BY event_time DESC LIMIT 1`, "%cerberus-identity%").Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("the general log has no record of the statement")
	}
	if err != nil {
		t.Fatalf("read mysql.general_log: %v", err)
	}
	if seen != statement {
		t.Errorf("the server received a different statement:\n got %q\nwant %q", seen, statement)
	}
}

// TestTheDriverReceivesTheStatementUnchanged is acceptance criterion 7's
// in-process byte-identity half: what the statement looks like at the moment
// database/sql hands it to the driver.
//
// The recorder below is an interposer, not a fake. It sits between database/sql
// and the real MySQL driver, records the query text, and delegates every call —
// so the connection, the transaction and the result are all the engine's, and the
// only thing added is a witness at the boundary. A test against a mock driver
// would prove that the mock received what the mock was sent; this proves what the
// server was sent, and MySQL's general_log then independently confirms the same
// bytes arrived.
func TestTheDriverReceivesTheStatementUnchanged(t *testing.T) {
	h := setUp(t, gate.MySQL)

	inner, err := mysqldriver.NewConnector(mysqlConfig(h.spec, h.Settings(), boundEnforced))
	if err != nil {
		t.Fatalf("build the real connector: %v", err)
	}
	rec := &recordingConnector{inner: inner}
	pool := sql.OpenDB(rec)
	defer func() { _ = pool.Close() }()
	applyPoolLimits(pool, h.Settings())

	// The production query path, with the interposed connector underneath it.
	my := &myConn{alias: h.spec, pool: pool}
	statement := "SELECT 1 /* cerberus-in-process ; DROP TABLE x */ AS n, 'a''b\\n; sélect — ünïcode' AS lit"
	if _, err := my.query(context.Background(), statement, h.Settings().RowCap); err != nil {
		t.Fatalf("query() = %v", err)
	}

	queries := rec.recorded()
	if len(queries) == 0 {
		t.Fatal("the driver was handed no query at all")
	}
	var found bool
	for _, q := range queries {
		if q == statement {
			found = true
		}
	}
	if !found {
		t.Errorf("the driver was handed %q, want the statement byte for byte:\n%q", queries, statement)
	}
}

// recordingConnector wraps a real driver.Connector and records the query text of
// every statement database/sql sends through it.
type recordingConnector struct {
	inner driver.Connector

	mu      sync.Mutex
	queries []string
}

func (c *recordingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	inner, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &recordingConn{inner: inner, rec: c}, nil
}

func (c *recordingConnector) Driver() driver.Driver { return c.inner.Driver() }

func (c *recordingConnector) record(query string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = append(c.queries, query)
}

func (c *recordingConnector) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.queries...)
}

// recordingConn delegates every interface database/sql looks for on a connection.
// The MySQL driver implements all of them; a type assertion that failed would mean
// the driver changed shape, which is worth an error rather than a silent fallback
// to a path this test is not watching.
type recordingConn struct {
	inner driver.Conn
	rec   *recordingConnector
}

func (c *recordingConn) Prepare(query string) (driver.Stmt, error) {
	c.rec.record(query)
	return c.inner.Prepare(query)
}

func (c *recordingConn) Close() error { return c.inner.Close() }

func (c *recordingConn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *recordingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	inner, ok := c.inner.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("the mysql driver no longer implements ConnBeginTx")
	}
	return inner.BeginTx(ctx, opts)
}

func (c *recordingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	c.rec.record(query)
	inner, ok := c.inner.(driver.ConnPrepareContext)
	if !ok {
		return nil, errors.New("the mysql driver no longer implements ConnPrepareContext")
	}
	return inner.PrepareContext(ctx, query)
}

func (c *recordingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.rec.record(query)
	inner, ok := c.inner.(driver.QueryerContext)
	if !ok {
		return nil, errors.New("the mysql driver no longer implements QueryerContext")
	}
	return inner.QueryContext(ctx, query, args)
}

func (c *recordingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.rec.record(query)
	inner, ok := c.inner.(driver.ExecerContext)
	if !ok {
		return nil, errors.New("the mysql driver no longer implements ExecerContext")
	}
	return inner.ExecContext(ctx, query, args)
}

func (c *recordingConn) ResetSession(ctx context.Context) error {
	if inner, ok := c.inner.(driver.SessionResetter); ok {
		return inner.ResetSession(ctx)
	}
	return nil
}

func (c *recordingConn) IsValid() bool {
	if inner, ok := c.inner.(driver.Validator); ok {
		return inner.IsValid()
	}
	return true
}
