//go:build integration

package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// msSlowStatement is the statement used to provoke a timeout against a real SQL
// Server. It is deliberately not a read.
//
// The draft carries an open question about which statement is safe to use as a
// slow read against a third party's production server, and the honest answer is
// that no slow *read* is safe: every construct that would make one — a cartesian
// join, a full scan — is exactly what this layer exists to prevent, and running it
// would put load on someone else's box to prove that we do not put load on
// someone else's box. WAITFOR DELAY takes no locks, reads no page and burns no
// CPU; it occupies one session and nothing else. It cannot go through the
// executor, because the gate refuses it and should, so this test reaches past the
// gate to the driver.
//
// CERBERUS_TEST_MSSQL_SLOW_STATEMENT overrides it for an instance where even that
// is unwelcome.
func msSlowStatement() string {
	if s := os.Getenv("CERBERUS_TEST_MSSQL_SLOW_STATEMENT"); s != "" {
		return s
	}
	return "WAITFOR DELAY '00:00:30'"
}

// msPinnedSession takes one connection out of the pool and keeps it, so that
// session-scoped facts — the session's isolation level, its LOCK_TIMEOUT, whether
// a #temp table survived — can be asked of the session they belong to.
//
// It checks the connection out, uses it, returns it and checks out again, because
// acceptance criterion 5 asks specifically for a connection obtained after a prior
// checkout: SessionInitSQL runs from ResetSession, and only a reused connection
// exercises that path rather than the one Connect takes.
func msPinnedSession(t *testing.T, ms *msConn) (*sql.Conn, int) {
	t.Helper()
	ctx := context.Background()

	// First checkout, used and returned. Its SPID is remembered so the test can
	// say whether the second checkout is the same physical connection.
	first, err := ms.pool.Conn(ctx)
	if err != nil {
		t.Fatalf("first checkout: %v", err)
	}
	var firstSPID int
	if err := first.QueryRowContext(ctx, "SELECT @@SPID").Scan(&firstSPID); err != nil {
		t.Fatalf("read @@SPID: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("return the first connection: %v", err)
	}

	for attempt := 0; attempt < 5; attempt++ {
		conn, err := ms.pool.Conn(ctx)
		if err != nil {
			t.Fatalf("second checkout: %v", err)
		}
		var spid int
		if err := conn.QueryRowContext(ctx, "SELECT @@SPID").Scan(&spid); err != nil {
			t.Fatalf("read @@SPID: %v", err)
		}
		if spid == firstSPID {
			t.Cleanup(func() { _ = conn.Close() })
			return conn, spid
		}
		_ = conn.Close()
	}
	t.Fatal("the pool never handed back a connection it had already used, so the ResetSession path cannot be exercised")
	return nil, 0
}

// TestSQLServerSessionCarriesItsMitigations is acceptance criterion 5. Both facts
// are read from the server's own view of the session, on a connection the pool has
// handed out before — so what is under test is SessionInitSQL running on reuse and
// not merely on first connect.
func TestSQLServerSessionCarriesItsMitigations(t *testing.T) {
	h := setUp(t, gate.SQLServer)
	c, _ := h.connFor(h.alias)
	ms := c.(*msConn)
	conn, spid := msPinnedSession(t, ms)
	ctx := context.Background()

	var isolation int
	err := conn.QueryRowContext(ctx,
		"SELECT transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID").Scan(&isolation)
	if err != nil {
		t.Fatalf("read sys.dm_exec_sessions for session %d: %v", spid, err)
	}
	// 1 is READ UNCOMMITTED in the server's own encoding.
	if isolation != 1 {
		t.Errorf("transaction_isolation_level = %d, want 1 (READ UNCOMMITTED)", isolation)
	}

	var lockTimeout int
	if err := conn.QueryRowContext(ctx, "SELECT @@LOCK_TIMEOUT").Scan(&lockTimeout); err != nil {
		t.Fatalf("read @@LOCK_TIMEOUT: %v", err)
	}
	want := int(milliseconds(h.Settings().LockTimeout))
	if lockTimeout != want {
		// -1 is the default and means "wait forever", which is the failure this
		// mitigation exists to prevent.
		t.Errorf("@@LOCK_TIMEOUT = %d, want %d", lockTimeout, want)
	}

	// And inside the executor's own transaction, which asks for the isolation
	// level a second time through TxOptions.
	err = ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
		var inTx int
		if err := tx.QueryRowContext(ctx,
			"SELECT transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID").Scan(&inTx); err != nil {
			return err
		}
		if inTx != 1 {
			t.Errorf("inside the transaction, transaction_isolation_level = %d, want 1", inTx)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read the isolation level inside the transaction: %v", err)
	}
}

// TestSQLServerContainmentOnEveryExitPath is acceptance criterion 3 for SQL
// Server, and the engine where it matters most: there is no read-only transaction
// here, so the rollback is not a second line of defence, it is the only one.
//
// The write goes into a session-scoped temporary table. That is what makes the
// test safe to run against a production server owned by somebody else: #temp
// belongs to our session and to nothing the third party can see, and it is
// destroyed with the session even if everything else fails.
func TestSQLServerContainmentOnEveryExitPath(t *testing.T) {
	h := setUp(t, gate.SQLServer)
	c, _ := h.connFor(h.alias)
	ms := c.(*msConn)

	for _, tt := range []struct {
		name   string
		panics bool
		run    func(t *testing.T, ctx context.Context, conn *sql.Conn) error
	}{
		{
			name: "success",
			run: func(t *testing.T, ctx context.Context, conn *sql.Conn) error {
				return ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "SELECT 1 AS marker INTO #cerberus_containment_probe")
					return err
				})
			},
		},
		{
			name: "an engine error after the write",
			run: func(t *testing.T, ctx context.Context, conn *sql.Conn) error {
				err := ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(ctx, "SELECT 1 AS marker INTO #cerberus_containment_probe"); err != nil {
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
			run: func(t *testing.T, ctx context.Context, conn *sql.Conn) error {
				timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				err := ms.withTxOn(timeoutCtx, conn, txReadOnly, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(timeoutCtx, "SELECT 1 AS marker INTO #cerberus_containment_probe"); err != nil {
						return err
					}
					_, err := tx.ExecContext(timeoutCtx, msSlowStatement())
					return err
				})
				if err == nil {
					t.Fatal("the statement outlived its deadline without error")
				}
				return nil
			},
		},
		{
			name:   "a panic after the write",
			panics: true,
			run: func(t *testing.T, ctx context.Context, conn *sql.Conn) error {
				return ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
					if _, err := tx.ExecContext(ctx, "SELECT 1 AS marker INTO #cerberus_containment_probe"); err != nil {
						return err
					}
					panic("a bug in the middle of a transaction")
				})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			conn, err := ms.pool.Conn(ctx)
			if err != nil {
				t.Fatalf("pin a connection: %v", err)
			}
			defer func() { _ = conn.Close() }()

			// The control: on this session, the write does land when it is not
			// rolled back. Without it, "the table is gone" could mean SELECT INTO
			// never worked.
			if _, err := conn.ExecContext(ctx, "SELECT 1 AS marker INTO #cerberus_control_probe"); err != nil {
				t.Fatalf("the control write failed, so this test proves nothing: %v", err)
			}
			if id := msTempObjectID(t, ctx, conn, "#cerberus_control_probe"); id == 0 {
				t.Fatal("the control temporary table does not exist after a write outside any transaction")
			}

			runAndRecover(t, tt.panics, func() error { return tt.run(t, ctx, conn) })

			// A dead connection is itself proof: a #temp table cannot outlive the
			// session that owns it, so if the session is gone the table is gone.
			var probeID int64
			err = conn.QueryRowContext(ctx,
				"SELECT ISNULL(OBJECT_ID('tempdb..#cerberus_containment_probe'), 0)").Scan(&probeID)
			if err != nil {
				// The probe failing is only evidence if it failed because the session
				// is gone, and that has to be established rather than assumed — this
				// is the branch the timeout path takes, which is the one path where
				// the rollback is the only thing between a write and the table, on the
				// one engine where it is the only containment layer at all. A probe we
				// cannot account for must fail the test: a test that cannot tell "the
				// session died, so the table died with it" from "something else went
				// wrong" has established nothing, and saying so is the only honest
				// outcome.
				//
				// A pinned *sql.Conn is never silently replaced, so if this second
				// query answers, the session is alive and the probe's failure has
				// another cause.
				var alive int
				aliveErr := conn.QueryRowContext(ctx, "SELECT 1").Scan(&alive)
				if aliveErr == nil {
					t.Fatalf("the containment probe failed on the %s path (%v) but the session is still alive, so whether the temporary table survived is unknown", tt.name, err)
				}
				t.Logf("the %s path took the torn-down-session branch: the probe failed (%v) and the session is gone (%v), so the temporary table cannot have survived", tt.name, err, aliveErr)
				return
			}
			if probeID != 0 {
				t.Errorf("the temporary table survived the %s path: the transaction was not rolled back", tt.name)
			}
		})
	}
}

func msTempObjectID(t *testing.T, ctx context.Context, conn *sql.Conn, name string) int64 {
	t.Helper()
	var id int64
	if err := conn.QueryRowContext(ctx, "SELECT ISNULL(OBJECT_ID('tempdb..'+@p1), 0)", name).Scan(&id); err != nil {
		t.Fatalf("read OBJECT_ID for %s: %v", name, err)
	}
	return id
}

// TestSQLServerTimeoutDiscardsTheSession is acceptance criterion 6 for SQL
// Server. This engine has no statement-level server-side bound — LOCK_TIMEOUT
// bounds waiting for a lock and nothing else — so the context deadline is the
// whole time bound, and discarding the connection is the whole of what makes it a
// bound on the server rather than only on us. What has to be shown is that the
// session is torn down and not merely abandoned.
//
// The observation that carries that claim is the timed-out session's absence from
// sys.dm_exec_sessions, seen from a second connection. @@SPID on the next call
// carries nothing on its own, and this is why: session ids are reused, and on
// this instance the pool's next connection was handed the timed-out session's own
// id. So "same id" and "different id" are both consistent with discard, and
// neither can fail if the driver ever stopped discarding — a connection returned
// to the pool alive would answer with its own id and look like proof. The id is
// therefore reported and not asserted.
func TestSQLServerTimeoutDiscardsTheSession(t *testing.T) {
	h := setUp(t, gate.SQLServer)
	c, _ := h.connFor(h.alias)
	ms := c.(*msConn)
	ctx := context.Background()

	// Asked first, before anything that can return, because it decides which of
	// the two observations below this run makes. Asked afterwards it sits behind a
	// return that fires on a perfectly ordinary outcome, and the falsifiable half
	// of the test is skipped on every green run without saying so.
	var canSeeSessions bool
	if err := ms.pool.QueryRowContext(ctx,
		"SELECT CONVERT(bit, ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE'), 0))").Scan(&canSeeSessions); err != nil {
		t.Fatalf("check VIEW SERVER STATE: %v", err)
	}

	// The observing connection is pinned before the timeout and held across it, so
	// that the absence check runs on a session which is neither the timed-out one
	// nor a later one that inherited its id. Asking "is session N gone?" through
	// the pool cannot work: the pool may open a connection that the server gives
	// id N, and that connection sees itself.
	var observer *sql.Conn
	var observerSPID int
	if canSeeSessions {
		if ceiling := h.Settings().MaxConns; ceiling < 2 {
			t.Fatalf("CERBERUS_DB_MAX_CONNS is %d: this test holds one connection while a second one times out", ceiling)
		}
		var err error
		observer, err = ms.pool.Conn(ctx)
		if err != nil {
			t.Fatalf("pin the observing connection: %v", err)
		}
		defer func() { _ = observer.Close() }()
		if err := observer.QueryRowContext(ctx, "SELECT @@SPID").Scan(&observerSPID); err != nil {
			t.Fatalf("read the observing session's @@SPID: %v", err)
		}
	}

	// The session that runs the statement identifies itself from inside the
	// transaction. Reading a SPID from the pool beforehand would not do: the pool
	// need not hand the same connection back, and the whole question is what
	// happened to the one that timed out.
	var ranOn int
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	started := time.Now()
	err := ms.withTx(timeoutCtx, txReadOnly, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(timeoutCtx, "SELECT @@SPID").Scan(&ranOn); err != nil {
			return err
		}
		_, err := tx.ExecContext(timeoutCtx, msSlowStatement())
		return err
	})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("the slow statement finished within the deadline, so nothing was timed out")
	}
	if ranOn == 0 {
		t.Fatalf("the transaction never reported its session: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the call took %v to give up on a 3s deadline", elapsed)
	}
	if canSeeSessions && observerSPID == ranOn {
		t.Fatalf("the statement ran on session %d, the id of the connection pinned to watch it, which the server does not give to two live sessions", ranOn)
	}

	if !canSeeSessions {
		// The reduction acceptance criterion 6 explicitly permits, and all that is
		// left when the server's own view is limited to the caller's own session:
		// sys.dm_exec_sessions answers nothing about another SPID whether or not it
		// is gone. It establishes less than the check below, and the log says which
		// of the two a green run made and what it did not settle.
		var after int
		if err := ms.pool.QueryRowContext(ctx, "SELECT @@SPID").Scan(&after); err != nil {
			t.Fatalf("read @@SPID after the timeout: %v", err)
		}
		t.Logf("the account lacks VIEW SERVER STATE, so this run rests on connection discard alone: the statement ran on session %d and the next call was given session %d. That does not distinguish a new session reusing the id from the timed-out session handed back alive", ranOn, after)
		return
	}

	// The falsifiable half. A connection whose BeginTx context expired and which
	// went back to the pool instead of being discarded would keep its session, and
	// this loop would run out its deadline on it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := observer.QueryRowContext(ctx,
			"SELECT count(*) FROM sys.dm_exec_sessions WHERE session_id = @p1", ranOn).Scan(&n); err != nil {
			t.Fatalf("read sys.dm_exec_sessions from session %d: %v", observerSPID, err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %d is still on the server %v after its statement timed out, so its connection was not discarded", ranOn, time.Since(started))
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Read only now. The pool opens this connection on demand, and opening it any
	// earlier lets the server hand it the very id the loop above is waiting to see
	// disappear.
	var after int
	if err := ms.pool.QueryRowContext(ctx, "SELECT @@SPID").Scan(&after); err != nil {
		t.Fatalf("read @@SPID after the timeout: %v", err)
	}
	if after == ranOn {
		t.Logf("session %d is absent from sys.dm_exec_sessions, observed from session %d; the pool's next connection was then given id %d again, a new session on a reused id — which is why the id is no evidence either way", ranOn, observerSPID, after)
	} else {
		t.Logf("session %d is absent from sys.dm_exec_sessions, observed from session %d; the pool's next connection was given session %d", ranOn, observerSPID, after)
	}
}

// TestSQLServerStacksStatementsWithNoPunctuation is acceptance criterion 9, and it
// is a regression test for an engine fact rather than for our code.
//
// The gate's single-statement rule carries the whole weight of "no second
// statement" on the one engine with no read-only transaction, and it does so
// because T-SQL executes a batch: two SELECTs separated by one space are two
// statements, with no semicolon and no punctuation of any kind. That was reasoned
// from Microsoft's documentation while the gate was built and left unverified
// because verifying it needs a database. This is where it is verified — and where
// it stays verified, so that a future driver version that quietly changed it could
// not do so unnoticed.
//
// Both statements are trivial reads and touch nothing.
func TestSQLServerStacksStatementsWithNoPunctuation(t *testing.T) {
	h := setUp(t, gate.SQLServer)
	c, _ := h.connFor(h.alias)
	ms := c.(*msConn)
	ctx := context.Background()

	const stacked = "SELECT 1 SELECT 2"

	t.Run("the engine really does execute both", func(t *testing.T) {
		// Deliberately past the executor and straight at the driver: the point is
		// what TDS does, not what we do about it.
		rows, err := ms.pool.QueryContext(ctx, stacked)
		if err != nil {
			t.Fatalf("QueryContext() = %v", err)
		}
		defer func() { _ = rows.Close() }()

		// Each result set is read to its end before asking for the next one. This
		// driver's NextResultSet reports io.EOF unless the token stream has already
		// reached the following result set's metadata, so an undrained cursor looks
		// exactly like a statement that produced one result set — which is the
		// answer this test exists to distinguish from the truth.
		var sets [][]int
		for {
			var values []int
			for rows.Next() {
				var v int
				if err := rows.Scan(&v); err != nil {
					t.Fatalf("scan result set %d: %v", len(sets)+1, err)
				}
				values = append(values, v)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("read result set %d: %v", len(sets)+1, err)
			}
			sets = append(sets, values)
			if !rows.NextResultSet() {
				break
			}
		}

		if len(sets) != 2 {
			t.Fatalf("got %d result sets (%v), want 2: this engine no longer executes two whitespace-separated statements as two statements, which is the fact the gate's single-statement rule is carrying", len(sets), sets)
		}
		if len(sets[0]) != 1 || sets[0][0] != 1 || len(sets[1]) != 1 || sets[1][0] != 2 {
			t.Errorf("result sets = %v, want [[1] [2]]", sets)
		}
	})

	t.Run("and the executor refuses that same text", func(t *testing.T) {
		_, err := h.Execute(ctx, h.alias, stacked, nil)
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("Execute() = %v, want the gate's refusal", err)
		}
		var dbErr *Error
		if !errors.As(err, &dbErr) {
			t.Fatalf("Execute() = %v, want a *db.Error", err)
		}
		if dbErr.Decision == nil || dbErr.Decision.Reason != "multiple-statements" {
			t.Errorf("the refusal reason is %+v, want multiple-statements", dbErr.Decision)
		}
		if dbErr.Detail != "" {
			t.Errorf("the refusal carries a driver detail, so it reached a connection: %s", dbErr.Detail)
		}
	})
}
