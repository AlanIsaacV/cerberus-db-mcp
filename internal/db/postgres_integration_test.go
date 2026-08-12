//go:build integration

package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// pgObserver is a second connection to the same server, built from the same alias
// spec and therefore carrying no assumption about where that server is.
//
// It exists because most of this file's assertions cannot be made from inside the
// connection under test: whether a backend is still running, whether a row
// survived a rollback and what text the server received are all facts about the
// server, and asking the session under test about itself would be asking the
// suspect for an alibi. The observer deliberately does not go through this
// package's pool, so it carries none of the bounds being tested.
func pgObserver(t *testing.T, spec AliasSpec) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, postgresURL(spec))
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = conn.Close(closeCtx)
	})
	return conn
}

// pgSlowRead is a read the gate allows and the server cannot finish: a cartesian
// product of two large series, counted.
//
// Its shape is forced by the constraints this project put itself under. The
// obvious slow read is pg_sleep, and the gate refuses it terminally — a
// forbidden function, not an escalatable unknown one — so it cannot be used
// through the production entry point at all. What is left is magnitude, which is
// precisely the thing the gate cannot see and this layer exists to bound. So the
// timeout test's subject is also the best illustration of why the timeout exists.
func pgSlowRead(marker string) string {
	return "SELECT count(*) /* " + marker + " */ FROM generate_series(1, 200000) a, generate_series(1, 200000) b"
}

// TestPostgresTransactionIsReadOnlyAsTheEngineUnderstandsIt is acceptance
// criterion 4 for PostgreSQL. Both halves are asked of the server: the setting is
// read back from inside the executor's own transaction, and the refusal is the
// server's own SQLSTATE rather than a message this package produced.
func TestPostgresTransactionIsReadOnlyAsTheEngineUnderstandsIt(t *testing.T) {
	h := setUp(t, gate.PostgreSQL)
	c, _ := h.connFor(h.alias)
	pg := c.(*pgConn)
	ctx := context.Background()

	t.Run("the session says it is read-only and bounded", func(t *testing.T) {
		var readOnly, isolation, statementTimeout, lockTimeout, idleInTx string
		err := pg.withTx(ctx, txReadOnly, func(ctx context.Context, tx pgx.Tx) error {
			for _, q := range []struct {
				sql string
				dst *string
			}{
				{"SHOW transaction_read_only", &readOnly},
				{"SHOW transaction_isolation", &isolation},
				{"SHOW statement_timeout", &statementTimeout},
				{"SHOW lock_timeout", &lockTimeout},
				{"SHOW idle_in_transaction_session_timeout", &idleInTx},
			} {
				if err := tx.QueryRow(ctx, q.sql).Scan(q.dst); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("read the session's own view: %v", err)
		}
		if readOnly != "on" {
			t.Errorf("transaction_read_only = %q, want on", readOnly)
		}
		if isolation != "repeatable read" {
			t.Errorf("transaction_isolation = %q, want repeatable read", isolation)
		}
		// The bounds are asserted from the server's view rather than from the fact
		// that we put them in the connection string.
		for _, tt := range []struct {
			name string
			got  string
		}{
			{"statement_timeout", statementTimeout},
			{"lock_timeout", lockTimeout},
			{"idle_in_transaction_session_timeout", idleInTx},
		} {
			if tt.got == "" || tt.got == "0" {
				t.Errorf("%s = %q, so the server is enforcing no bound", tt.name, tt.got)
			}
		}
	})

	t.Run("the server refuses a write inside it", func(t *testing.T) {
		// Deliberately past the gate: what is under test is the engine's
		// enforcement, and with the gate in the way no write would ever arrive.
		err := pg.withTx(ctx, txReadOnly, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "CREATE TABLE cerberus_should_not_exist (id int)")
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("Exec() = %v, want a PostgreSQL error", err)
		}
		if pgErr.Code != "25006" {
			t.Errorf("SQLSTATE = %q, want 25006 (read_only_sql_transaction)", pgErr.Code)
		}
	})
}

// TestPostgresContainmentOnEveryExitPath is acceptance criterion 3 for
// PostgreSQL. The transaction is writable here for the reason set out on
// [txMode]: with the engine's read-only enforcement in the way, no write reaches
// the table and the rollback is never the thing that contained it. Writable, the
// rollback is the only thing standing between the insert and the table — which is
// the situation SQL Server is in permanently.
func TestPostgresContainmentOnEveryExitPath(t *testing.T) {
	h := setUp(t, gate.PostgreSQL)
	c, _ := h.connFor(h.alias)
	pg := c.(*pgConn)
	obs := pgObserver(t, h.spec)
	ctx := context.Background()

	const table = "cerberus_containment_probe"
	if _, err := obs.Exec(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
		t.Fatalf("drop probe table: %v", err)
	}
	if _, err := obs.Exec(ctx, "CREATE TABLE "+table+" (marker text)"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = obs.Exec(cleanCtx, "DROP TABLE IF EXISTS "+table)
	})

	// The control for the whole test: the write has to be one the engine would
	// otherwise have kept. Without this, "nothing survived" could just mean the
	// insert never worked.
	if _, err := obs.Exec(ctx, "INSERT INTO "+table+" (marker) VALUES ('committed-by-the-observer')"); err != nil {
		t.Fatalf("the observer cannot write to the probe table, so this test proves nothing: %v", err)
	}
	var control int
	if err := obs.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&control); err != nil || control != 1 {
		t.Fatalf("the probe table does not keep committed rows (count=%d, err=%v)", control, err)
	}

	rowCount := func(t *testing.T, marker string) int {
		t.Helper()
		var n int
		if err := obs.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE marker = $1", marker).Scan(&n); err != nil {
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
				return pg.withTx(ctx, txWritable, func(ctx context.Context, tx pgx.Tx) error {
					_, err := tx.Exec(ctx, "INSERT INTO "+table+" (marker) VALUES ($1)", marker)
					return err
				})
			},
		},
		{
			name: "an engine error after the write",
			run: func(t *testing.T, marker string) error {
				err := pg.withTx(ctx, txWritable, func(ctx context.Context, tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (marker) VALUES ($1)", marker); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, "SELECT * FROM cerberus_no_such_table")
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
				err := pg.withTx(timeoutCtx, txWritable, func(ctx context.Context, tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (marker) VALUES ($1)", marker); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, pgSlowRead("containment-timeout"))
					return err
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
				return pg.withTx(ctx, txWritable, func(ctx context.Context, tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (marker) VALUES ($1)", marker); err != nil {
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

// runAndRecover calls fn, requiring a panic to escape it when one is expected and
// requiring none when it is not. A panic must reach the caller: swallowing it
// here would hide a bug from the server that owns this package, and the rollback
// is a deferred call rather than a recover precisely so that containment does not
// depend on catching anything.
func runAndRecover(t *testing.T, wantPanic bool, fn func() error) {
	t.Helper()
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		if err := fn(); err != nil {
			t.Fatalf("the probe failed before it could be contained: %v", err)
		}
	}()
	if panicked != wantPanic {
		t.Fatalf("panicked = %v, want %v", panicked, wantPanic)
	}
}

// TestPostgresTimeoutIsEnforcedByTheServer is acceptance criterion 6 for
// PostgreSQL: the abort carries the server's own statement_timeout SQLSTATE, it
// happens before our context deadline could have caused it, and the backend is
// gone from a second connection's view of pg_stat_activity.
func TestPostgresTimeoutIsEnforcedByTheServer(t *testing.T) {
	h := setUp(t, gate.PostgreSQL)
	obs := pgObserver(t, h.spec)
	const marker = "cerberus-timeout-probe"

	started := time.Now()
	_, err := h.Execute(context.Background(), h.alias, pgSlowRead(marker), nil)
	elapsed := time.Since(started)

	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("Execute() = %v, want a *db.Error", err)
	}
	if dbErr.Kind != KindTimeout {
		t.Fatalf("Kind = %q, want a timeout (detail: %s)", dbErr.Kind, dbErr.Detail)
	}
	// The server is what stopped it, not our context: statement_timeout raises
	// 57014, and it is set to expire before the context deadline by design.
	var pgErr *pgconn.PgError
	if !errors.As(dbErr.cause, &pgErr) {
		t.Fatalf("the timeout did not come from the server: %v", dbErr.cause)
	}
	if pgErr.Code != "57014" {
		t.Errorf("SQLSTATE = %q, want 57014 (query_canceled, which statement_timeout raises)", pgErr.Code)
	}
	if deadline := h.Settings().QueryTimeout + h.Settings().TimeoutGrace; elapsed >= deadline {
		t.Errorf("the call took %v, at or past the context deadline of %v: the server did not stop it first", elapsed, deadline)
	}

	assertPgBackendGone(t, obs, marker)
}

func assertPgBackendGone(t *testing.T, obs *pgx.Conn, marker string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		err := obs.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity
			 WHERE query LIKE '%' || $1 || '%' AND pid <> pg_backend_pid() AND state = 'active'`,
			marker).Scan(&n)
		if err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backends are still running the timed-out statement", n)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestPostgresReceivesTheStatementByteForByte is acceptance criterion 7's
// byte-identity half on this engine, taken from the server's own record of what
// it received rather than from our report of what we sent. The statement carries
// every lexical trap a rewriting layer would trip over: a block comment holding a
// semicolon and a DROP, a doubled quote, and non-ASCII text.
func TestPostgresReceivesTheStatementByteForByte(t *testing.T) {
	h := setUp(t, gate.PostgreSQL)
	obs := pgObserver(t, h.spec)

	const marker = "cerberus-identity"
	statement := "SELECT count(*) /* " + marker + " ; DROP TABLE x */, 'a''b; sélect — ünïcode' AS lit" +
		" FROM generate_series(1, 200000) a, generate_series(1, 200000) b"

	done := make(chan struct{})
	go func() {
		defer close(done)
		// It will be stopped by statement_timeout; what matters is what the server
		// saw while it ran.
		_, _ = h.Execute(context.Background(), h.alias, statement, nil)
	}()

	var seen string
	deadline := time.Now().Add(15 * time.Second)
	for seen == "" && time.Now().Before(deadline) {
		err := obs.QueryRow(context.Background(),
			`SELECT coalesce(max(query), '') FROM pg_stat_activity
			 WHERE query LIKE '%' || $1 || '%' AND pid <> pg_backend_pid()`, marker).Scan(&seen)
		if err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if seen == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	<-done

	if seen == "" {
		t.Fatal("the statement was never observed running, so nothing was compared")
	}
	if seen != statement {
		t.Errorf("the server received a different statement:\n got %q\nwant %q", seen, statement)
	}
}
