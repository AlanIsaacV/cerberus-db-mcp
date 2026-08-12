package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// Result is what a successful execution returns. It is engine-neutral: no
// driver type appears in it, no cursor stays open behind it, and it carries
// everything a caller needs to write one audit line without asking this package
// for anything else.
type Result struct {
	Alias  string
	Engine gate.Engine
	// Decision is the gate's Allow, including any grants it consumed. An audit
	// line without it cannot say why the statement was permitted.
	Decision gate.Decision
	Columns  []string
	// Rows holds the values as the driver decoded them, with one normalisation:
	// see [normalise].
	Rows [][]any
	// Truncated reports that the statement had more rows to give and the cap
	// stopped the iteration. It is a separate field rather than an inference from
	// len(Rows) == RowCap, because a result that happens to be exactly the cap is
	// not truncated and telling the agent otherwise would make it re-query
	// forever.
	Truncated bool
	// RowCap is the cap that applied, so the caller can say what it was.
	RowCap int
	// Elapsed is wall-clock time for the execution, transaction included.
	Elapsed time.Duration
}

// rowSet is the per-engine layer's output: the same three facts, without the
// bookkeeping the executor adds.
type rowSet struct {
	columns   []string
	rows      [][]any
	truncated bool
}

// txMode says whether the transaction wrapping an execution may write.
//
// The zero value is the read-only one, and that is not a stylistic choice. This
// type exists because the containment guarantee — an unconditional rollback —
// cannot be tested on PostgreSQL or MySQL through the production path: there the
// engine's own read-only transaction refuses the write before the rollback is
// ever the thing standing in its way. Testing containment needs a transaction
// that permits the write and rolls it back anyway, which is exactly the
// situation SQL Server is in permanently.
//
// So [txWritable] exists for that test and for nothing else. It is unexported,
// no non-test file in this package names it, and a test asserts that — see
// TestTestOnlyLeversAreTestOnly.
type txMode int

const (
	txReadOnly txMode = iota
	txWritable
)

// rollbackTimeout bounds the rollback issued on the way out of an execution.
// It is short and it is separate from the statement's own deadline because the
// most important rollback is the one that follows a timeout, and by then the
// caller's context is already expired — a rollback issued on a dead context is
// not a rollback.
const rollbackTimeout = 5 * time.Second

// txBeginner is whatever a transaction can be started on. Both *sql.DB and
// *sql.Conn satisfy it, and the second is why the interface exists: a session
// setting and a session-scoped temporary table are only observable on the
// connection that carries them, so a test that has to confirm either one needs
// the transaction to run on a connection it pinned — while still running through
// this function, so that the rollback discipline under test is the real one and
// not a copy of it.
type txBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// runSQLTx runs fn inside a transaction on a database/sql pool and rolls that
// transaction back on every exit path, including a panic.
//
// Both engines behind database/sql share this. The rollback is a plain defer
// with no error handling, and the reasons it can be ignored are worth stating
// because they look like a swallowed error:
//
//   - On success there is nothing to commit. This layer never commits. Rollback
//     returning nil or sql.ErrTxDone are the same outcome to us.
//   - On timeout database/sql has already rolled the transaction back itself: it
//     watches the context passed to BeginTx and discards the connection when it
//     expires. Our Rollback then returns sql.ErrTxDone, which is the correct
//     state, not a failure.
//   - When the connection is gone, the server aborts the transaction because the
//     session ended. That is the containment that actually holds on a torn-down
//     link, and no ROLLBACK we could send would improve on it.
//
// What must not happen is a commit, and the only way to guarantee that is for
// no commit to exist anywhere in this package.
func runSQLTx(ctx context.Context, on txBeginner, opts *sql.TxOptions, fn func(*sql.Tx) error) error {
	tx, err := on.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoSession, err)
	}
	defer func() { _ = tx.Rollback() }()
	return fn(tx)
}

// collectSQLRows drains at most cap rows from a database/sql cursor and reports
// whether there were more.
//
// It asks the cursor for one row beyond the cap. That extra row is what makes
// truncation observable without a second query and without a COUNT — and it is
// read and then dropped, never returned. The alternative, comparing the row
// count to the cap, cannot tell a result of exactly cap rows from a truncated
// one.
//
// The cursor is closed without draining. That is the only row-limiting mechanism
// available: no driver of the three offers a server-side row cap that leaves the
// statement alone, and every mechanism that would — TOP, LIMIT, SET ROWCOUNT —
// works by changing the text. A changed statement is a statement the gate did
// not approve, so it is not on the table.
func collectSQLRows(rows *sql.Rows, rowCap int) (*rowSet, error) {
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &rowSet{columns: columns, rows: make([][]any, 0, min(rowCap, 64))}
	scan := make([]any, len(columns))
	holders := make([]any, len(columns))
	for i := range scan {
		scan[i] = &holders[i]
	}
	for rows.Next() {
		if len(out.rows) == rowCap {
			out.truncated = true
			break
		}
		if err := rows.Scan(scan...); err != nil {
			return nil, err
		}
		row := make([]any, len(columns))
		for i := range holders {
			row[i] = normalise(holders[i])
		}
		out.rows = append(out.rows, row)
	}
	// rows.Err is consulted even when the cap stopped the loop: Next returning
	// false and Next never being asked again are different states, and only the
	// first can hide an engine-side abort.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out.columns) == 0 {
		// The gate only allows reads, so a statement that produced no result set
		// means either something got past it or the session went away mid-flight.
		// Both deserve an error rather than an empty success that an agent would
		// read as "the table is empty". The check comes after rows.Err so that a
		// failed query reports why it failed rather than reporting its shape.
		return nil, errNoResultSet
	}
	return out, nil
}

// normalise turns a []byte whose contents are valid UTF-8 into a string, and
// copies one that is not so that the driver may reuse its buffer.
//
// It is applied to every value from all three engines: [collectSQLRows] runs it
// on the MySQL and SQL Server paths and [collectPgRows] runs it on the pgx path.
// What it does therefore differs by engine, and the second half of that is a
// known cost rather than an oversight:
//
//   - On MySQL it is the reason the conversion exists. That driver returns every
//     column as []byte, numbers and text alike, so a whole result set would
//     otherwise arrive at the agent as base64 — unreadable, several times larger,
//     and context is this project's scarce resource.
//   - On PostgreSQL and SQL Server a []byte is a genuine bytea or
//     varbinary/image, because both drivers decode everything else to a typed Go
//     value. Such a column is rendered to the agent as text whenever its bytes
//     happen to be valid UTF-8, and as base64 when they happen not to be — so the
//     same column can change representation between two calls depending on the
//     rows returned.
//
// Whether binary should reach an agent as text at all is a decision for the
// repository owner and is recorded as an open question; the behaviour is left
// exactly as it is until that is answered.
func normalise(v any) any {
	if b, ok := v.([]byte); ok {
		if utf8.Valid(b) {
			return string(b)
		}
		// A copy, because the driver is free to reuse its buffer once the cursor
		// advances.
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	return v
}
