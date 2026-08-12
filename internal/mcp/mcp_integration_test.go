//go:build integration

// The integration tests here run the whole transport against the real engines in
// deploy/compose.test.yaml, through the SDK's real client over real HTTP. They
// follow internal/db's conventions exactly — the same build tag, the same
// environment-only configuration, the same require-engines variable — because a
// second set of conventions for the same containers is a second set of ways for a
// run to be green while testing nothing.
//
// SQL Server is absent for the reason it is absent there: no arm64 image exists,
// and this repository has already accepted that gap. Its path through this layer
// is engine-neutral — the same Executor.Execute and the same db.Result — so what
// is untested is the driver below, not the code above.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// testedEngines are the engines with containers. See the file comment for why
// SQL Server is not among them.
func testedEngines() []gate.Engine { return []gate.Engine{gate.PostgreSQL, gate.MySQL} }

// requireEnginesVar names the engines a run insists on, comma-separated, in the
// same spelling CERBERUS_DB_<ALIAS>_ENGINE uses.
//
// It is internal/db's variable and it is honoured here for its reason: every skip
// below is individually right — no configuration, no alias for the engine, a
// configured alias that cannot be reached — and together they mean a typo in a
// CERBERUS_DB_* variable name produces exit 0 with nothing asserted. CI names the
// engines it has containers for, and a typo then fails the job instead of passing
// it.
const requireEnginesVar = "CERBERUS_TEST_REQUIRE_ENGINES"

func engineIsRequired(t *testing.T, engine gate.Engine) bool {
	t.Helper()
	for _, name := range strings.Split(os.Getenv(requireEnginesVar), ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		required, err := gate.ParseEngine(name)
		if err != nil {
			// A misspelled engine here would require nothing, which is precisely the
			// silence this variable exists to break.
			t.Fatalf("%s names %q, which is not one of %v", requireEnginesVar, name, gate.Engines())
		}
		if required == engine {
			return true
		}
	}
	return false
}

func skipOrFail(t *testing.T, required bool, engine gate.Engine, reason string) {
	t.Helper()
	if required {
		t.Fatalf("%s names %s, so this is a failure and not a skip: %s", requireEnginesVar, engine, reason)
	}
	t.Skip(reason)
}

// engineHarness is one engine's alias reached through the whole stack: real
// pools, real gate, real HTTP, real MCP client.
type engineHarness struct {
	*harness
	spec     db.AliasSpec
	alias    string
	settings db.Settings
}

// liveConfig loads the CERBERUS_DB_* configuration and finds the spec for one
// engine, skipping when the environment has none.
func liveConfig(t *testing.T, engine gate.Engine) (*db.Config, db.AliasSpec) {
	t.Helper()
	// Asked here rather than only on a skip path, so a misspelled engine name in
	// CERBERUS_TEST_REQUIRE_ENGINES is caught on a run where nothing skips.
	required := engineIsRequired(t, engine)
	neutraliseForeignVariables(t)

	cfg, err := db.LoadConfig()
	if err != nil {
		skipOrFail(t, required, engine, fmt.Sprintf("no usable CERBERUS_DB_* configuration in the environment (%v); see .env.example and deploy/compose.test.yaml", err))
	}
	for _, spec := range cfg.Aliases {
		if spec.Engine == engine {
			return cfg, spec
		}
	}
	skipOrFail(t, required, engine, fmt.Sprintf("no %s alias is configured; set CERBERUS_DB_ALIASES and the CERBERUS_DB_<ALIAS>_* family for a %s server", engine, engine))
	return nil, db.AliasSpec{}
}

// executorFor builds the executor for one configuration, reachability checked.
func executorFor(t *testing.T, cfg *db.Config, engine gate.Engine, alias string) *db.Executor {
	t.Helper()
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	e, err := db.New(g, cfg)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(e.Close)

	// A configured alias that cannot be reached is a skip and not a failure,
	// unless the run insisted on this engine.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := e.Execute(ctx, alias, "SELECT 1", nil); err != nil {
		if errors.Is(err, db.ErrUnavailable) {
			skipOrFail(t, engineIsRequired(t, engine), engine, fmt.Sprintf("alias %q (%s) is configured but not reachable: %v", alias, engine, err))
		}
		t.Fatalf("the configured %s alias %q rejected SELECT 1: %v", engine, alias, err)
	}
	return e
}

// setUpEngine is the whole stack over one engine's real alias.
func setUpEngine(t *testing.T, engine gate.Engine) engineHarness {
	t.Helper()
	cfg, spec := liveConfig(t, engine)
	e := executorFor(t, cfg, engine, spec.Alias)
	return engineHarness{
		harness:  connect(t, e),
		spec:     spec,
		alias:    spec.Alias,
		settings: cfg.Settings,
	}
}

// brokenAliasHarness is the same stack over a deliberately broken spec, so that
// a connection-level failure can be provoked without disturbing the working
// alias.
func brokenAliasHarness(t *testing.T, spec db.AliasSpec, settings db.Settings) engineHarness {
	t.Helper()
	neutraliseForeignVariables(t)
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	// Short bounds: this alias is meant to fail at the socket and there is no
	// reason for the suite to wait out a full connect timeout.
	settings.ConnectTimeout = 5 * time.Second
	settings.QueryTimeout = 5 * time.Second
	e, err := db.New(g, &db.Config{Settings: settings, Aliases: []db.AliasSpec{spec}})
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(e.Close)
	return engineHarness{harness: connect(t, e), spec: spec, alias: spec.Alias, settings: settings}
}

// query runs execute_query and fails the test if it was not allowed.
func (h engineHarness) query(t *testing.T, statement string) map[string]any {
	t.Helper()
	res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": statement})
	if res.IsError {
		t.Fatalf("execute_query(%s) failed: %s", statement, resultText(t, res))
	}
	out, ok := structured(t, res).(map[string]any)
	if !ok {
		t.Fatalf("execute_query returned no structured content: %+v", res)
	}
	return out
}

// assertAgentMessage checks that the client was told exactly internal/db's fixed
// sentence for one of the acceptable kinds, and nothing else.
//
// The expectation is read out of internal/db itself rather than transcribed, so
// this test cannot drift from the allowlist it is checking. What it adds is that
// the sentence is what actually crossed the wire, and that none of the alias's
// own configured values came with it.
//
// More than one kind is accepted where the class genuinely is not determined
// here: a connect that runs out of time is classified by internal/db from the
// context's own state, which it does deliberately and in preference to
// recognising each driver's spelling of a deadline — so an unreachable host is a
// timeout or an unavailable database depending on which bound expired first.
// Which of the two it is is that package's business; what this test is for is
// that the agent got one of its fixed sentences and nothing else.
func (h engineHarness) assertAgentMessage(t *testing.T, res *sdk.CallToolResult, kinds ...db.Kind) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("the call succeeded; want a %v failure", kinds)
	}
	text := resultText(t, res)

	var acceptable []string
	matched := false
	for _, kind := range kinds {
		want := (&db.Error{Kind: kind}).Agent()
		acceptable = append(acceptable, want)
		if text == want {
			matched = true
		}
	}
	if !matched {
		t.Errorf("the client was told %q, want one of internal/db's fixed messages for %v: %q", text, kinds, acceptable)
	}
	h.assertNothingAboutTheConnection(t, text)

	// The operator's side must not be empty, or the sanitisation was a discard
	// rather than a translation.
	logged := false
	for _, kind := range kinds {
		if strings.Contains(h.appLog.String(), string(kind)) {
			logged = true
		}
	}
	if !logged {
		t.Errorf("the application log does not record a %v failure:\n%s", kinds, h.appLog.String())
	}
}

// assertNothingAboutTheConnection checks by value rather than by pattern, so a
// value nobody thought to look for is still caught.
func (h engineHarness) assertNothingAboutTheConnection(t *testing.T, text string) {
	t.Helper()
	// The criterion names the database and the user as two separate things that
	// must not reach the agent, and each is checked here as a substring — so a
	// fixture that spells them alike, or spells one inside the other, quietly
	// turns two checks into one check wearing two labels. It would still fail on a
	// leak of either; what it could no longer do is say which of the two leaked,
	// which is the whole difference between the criterion and half of it. The
	// fixture that satisfies this is deploy/compose.test.yaml, deploy/*-init and
	// the integration job's env block, which name the database and the user
	// differently on purpose.
	if strings.Contains(h.spec.Database, h.spec.User) || strings.Contains(h.spec.User, h.spec.Database) {
		t.Fatalf("the fixture's database name (%q) and user name (%q) overlap, so this test cannot tell a leak of one from a leak of the other; give them unrelated values in deploy/compose.test.yaml and .github/workflows/ci.yml",
			h.spec.Database, h.spec.User)
	}
	for label, value := range map[string]string{
		"the host":          h.spec.Host,
		"the port":          strconv.Itoa(h.spec.Port),
		"the database name": h.spec.Database,
		"the username":      h.spec.User,
		"the password":      string(h.spec.Password),
	} {
		if value == "" {
			continue
		}
		if strings.Contains(text, value) {
			t.Errorf("the client-visible text contains %s (%q): %q", label, value, text)
		}
	}
}

// TestExecuteQueryReturnsRowsFromRealEngines is acceptance criterion 2.
//
// The same expectation holds on both engines, which is not obvious and is worth
// stating: go-sql-driver decodes MySQL's integer and float columns to Go types
// even on the text protocol (packets.go:869-897) and leaves the rest as bytes,
// so an integer arrives here as a number and a string arrives as bytes that
// internal/db's normalise has already turned into a string. PostgreSQL gets to
// the same two Go types by a different route.
func TestExecuteQueryReturnsRowsFromRealEngines(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)
			out := h.query(t, "SELECT 1 AS one, 'two' AS two")

			if got := jsonOf(t, out["columns"]); got != `["one","two"]` {
				t.Errorf(`columns = %s, want ["one","two"]`, got)
			}
			if got := jsonOf(t, out["rows"]); got != `[[1,"two"]]` {
				t.Errorf(`rows = %s, want [[1,"two"]]`, got)
			}
			if out["truncated"] != false {
				t.Errorf("truncated = %v, want false", out["truncated"])
			}
			if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
				t.Errorf("row_cap = %v, want %v", got, want)
			}
		})
	}
}

// TestTruncationCrossesTheWire is the rest of criterion 2's truncated field. An
// agent told nothing about a cut-off result reads it as the whole answer, and an
// agent told a complete result was cut off pages forever.
func TestTruncationCrossesTheWire(t *testing.T) {
	// No portable way to produce many rows without a table, and a table is the one
	// thing these tests must not need.
	generators := map[gate.Engine]func(n int) string{
		gate.PostgreSQL: func(n int) string {
			return "SELECT i FROM generate_series(1, " + strconv.Itoa(n) + ") AS i"
		},
		gate.MySQL: func(n int) string {
			return "WITH RECURSIVE s AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM s WHERE i < " + strconv.Itoa(n) + ") SELECT i FROM s"
		},
	}

	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)
			rowCap := h.settings.RowCap
			if rowCap < 2 {
				t.Fatalf("this test needs a row cap of at least 2, not %d", rowCap)
			}
			generate := generators[engine]

			over := h.query(t, generate(rowCap*2))
			if got := len(over["rows"].([]any)); got != rowCap {
				t.Errorf("got %d rows, want exactly the cap %d", got, rowCap)
			}
			if over["truncated"] != true {
				t.Error("a capped result reports truncated=false, so the agent cannot tell it is incomplete")
			}

			exact := h.query(t, generate(rowCap))
			if exact["truncated"] != false {
				t.Error("a result of exactly the cap reports truncation, which would make the agent page forever")
			}
		})
	}
}

// TestValueFormsCrossTheWireFromRealEngines is acceptance criterion 7: a NULL, a
// timestamp, a decimal, a UTF-8 text column and a non-UTF-8 blob, selected from a
// real engine and asserted as the exact JSON the client received.
//
// The statements select literals rather than reading a table. Nothing here may
// create one — the gate refuses DDL, which is the whole point of it — and a
// fixture that had to exist first would make this a test of the fixture.
func TestValueFormsCrossTheWireFromRealEngines(t *testing.T) {
	// The blob is 0xff 0xfe 0xfd on both engines. 0xff cannot begin a valid UTF-8
	// sequence under any reading, so internal/db's normalise leaves it as bytes
	// and this layer is what decides how it looks.
	// The column names avoid MySQL's reserved words: "dec" and "blob" are both
	// keywords there and either one turns this into a syntax-error test.
	statements := map[gate.Engine]string{
		gate.PostgreSQL: `SELECT CAST(NULL AS text) AS n, ` +
			`TIMESTAMPTZ '2024-03-01 12:34:56.789+00' AS ts, ` +
			`NUMERIC '123456789012345678901234.56789' AS amount, ` +
			`TEXT 'árbol ✓' AS txt, ` +
			`BYTEA '\xfffefd' AS payload`,
		gate.MySQL: `SELECT NULL AS n, ` +
			`TIMESTAMP '2024-03-01 12:34:56.789' AS ts, ` +
			`CAST('123456789012345678901234.56789' AS DECIMAL(30, 5)) AS amount, ` +
			`'árbol ✓' AS txt, ` +
			`X'FFFEFD' AS payload`,
	}
	// The timestamp is asserted as the instant rather than as one rendering of it,
	// and that is deliberate. pgx decodes a timestamptz into the client's local
	// zone, so the offset in the string is a property of the machine running the
	// test; what this layer promises is RFC 3339 with the offset the value carries,
	// not a particular offset.
	wantInstant := time.Date(2024, 3, 1, 12, 34, 56, 789000000, time.UTC)

	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)
			out := h.query(t, statements[engine])

			if got := jsonOf(t, out["columns"]); got != `["n","ts","amount","txt","payload"]` {
				t.Errorf("columns = %s", got)
			}
			rows, ok := out["rows"].([]any)
			if !ok || len(rows) != 1 {
				t.Fatalf("rows = %s, want exactly one", jsonOf(t, out["rows"]))
			}
			row := rows[0].([]any)
			if len(row) != 5 {
				t.Fatalf("the row has %d values, want 5: %s", len(row), jsonOf(t, row))
			}

			for i, want := range map[int]string{
				0: `null`,
				2: `"123456789012345678901234.56789"`,
				3: `"árbol ✓"`,
				4: `{"$base64":"//79"}`,
			} {
				if got := jsonOf(t, row[i]); got != want {
					t.Errorf("value %d = %s, want %s", i, got, want)
				}
			}

			rendered, ok := row[1].(string)
			if !ok {
				t.Fatalf("the timestamp arrived as %s, want an RFC 3339 string", jsonOf(t, row[1]))
			}
			parsed, err := time.Parse(time.RFC3339Nano, rendered)
			if err != nil {
				t.Fatalf("the timestamp %q is not RFC 3339: %v", rendered, err)
			}
			if !parsed.Equal(wantInstant) {
				t.Errorf("the timestamp %q is %s, want %s", rendered, parsed.UTC(), wantInstant)
			}
		})
	}
}

// TestOnlyFixedAgentMessagesReachTheClient is acceptance criterion 5, against
// errors a real engine produced rather than errors this test constructed.
func TestOnlyFixedAgentMessagesReachTheClient(t *testing.T) {
	// Reads the gate allows and the server cannot finish. The obvious slow read is
	// a sleep function, and the gate refuses those terminally, so what is left is
	// magnitude — which is precisely the thing the gate cannot see and the reason
	// internal/db bounds time at all.
	slowRead := map[gate.Engine]string{
		gate.PostgreSQL: "SELECT count(*) FROM generate_series(1, 200000) a, generate_series(1, 200000) b",
		gate.MySQL: "SELECT count(*) FROM information_schema.columns a," +
			" information_schema.columns b, information_schema.columns c",
	}
	// Real objects an unprivileged account may not read. When the configured
	// account can read them the class cannot be provoked at all, and the test says
	// so rather than passing on a failure it did not cause.
	restricted := map[gate.Engine]string{
		gate.PostgreSQL: "SELECT * FROM pg_authid",
		gate.MySQL:      "SELECT * FROM mysql.user",
	}

	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)

			t.Run("an object that does not exist", func(t *testing.T) {
				res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": "SELECT * FROM cerberus_no_such_table_anywhere"})
				h.assertAgentMessage(t, res, db.KindObjectNotFound)
			})

			t.Run("a statement the engine rejects", func(t *testing.T) {
				// The gate allows this: it begins with SELECT and names nothing
				// forbidden. Only the engine can refuse it, which is the point.
				res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": "SELECT FROM WHERE"})
				h.assertAgentMessage(t, res, db.KindInvalidStatement)
			})

			t.Run("permission denied on a real object", func(t *testing.T) {
				res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": restricted[engine]})
				if !res.IsError {
					t.Skipf("the configured account can read %s, so this class cannot be provoked with it; point the alias at an account without privileges to exercise it", restricted[engine])
				}
				h.assertAgentMessage(t, res, db.KindPermissionDenied)
			})

			t.Run("a statement that runs too long", func(t *testing.T) {
				res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": slowRead[engine]})
				h.assertAgentMessage(t, res, db.KindTimeout)
			})

			t.Run("a host that is not there", func(t *testing.T) {
				// A documentation-range address (RFC 5737). Nothing routes it, so the
				// connect either times out or is refused locally, and neither reaches a
				// server that could say anything back.
				broken := h.spec
				broken.Host = "192.0.2.1"
				unreachable := brokenAliasHarness(t, broken, h.settings)
				res := unreachable.call(t, ToolExecuteQuery, map[string]any{"alias": broken.Alias, "statement": "SELECT 1"})
				unreachable.assertAgentMessage(t, res, db.KindUnavailable, db.KindTimeout)
				// The working alias's own values are checked too, since the broken spec
				// differs from it in exactly one field.
				h.assertNothingAboutTheConnection(t, resultText(t, res))
			})

			t.Run("a wrong password", func(t *testing.T) {
				broken := h.spec
				broken.Password = db.Secret("definitely-not-the-password")
				wrong := brokenAliasHarness(t, broken, h.settings)
				res := wrong.call(t, ToolExecuteQuery, map[string]any{"alias": broken.Alias, "statement": "SELECT 1"})
				// Deliberately the same class as an unreachable host: telling the agent
				// apart "wrong password" from "no such host" would tell it whether a
				// credential it cannot see is valid, which is a fact about the
				// credential.
				wrong.assertAgentMessage(t, res, db.KindUnavailable)
			})
		})
	}
}

// TestEveryCallIsAudited is acceptance criterion 8: one event per call, across
// an allowed call, a refused call and a call that failed against the engine.
//
// The three run against the same server and the audit stream is read once at the
// end, so this also establishes the count: three calls, three events, no more.
func TestEveryCallIsAudited(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)

			const allowed = "SELECT 1 AS one"
			const refused = "DELETE FROM invoices"
			const failing = "SELECT * FROM cerberus_no_such_table_anywhere"

			h.query(t, allowed)
			for _, statement := range []string{refused, failing} {
				res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": statement})
				if !res.IsError {
					t.Fatalf("%q succeeded", statement)
				}
			}

			events := h.auditEventsFor(t, ToolExecuteQuery)
			if len(events) != 3 {
				t.Fatalf("got %d audit events for 3 calls:\n%s", len(events), h.audit.String())
			}

			for i, want := range []struct {
				statement string
				outcome   string
				verdict   string
				rows      float64
				errorKind string
			}{
				{allowed, string(OutcomeAllowed), string(gate.Allow), 1, ""},
				{refused, string(OutcomeRefused), string(gate.Deny), 0, string(db.KindRefused)},
				// The gate allowed this one, and recording that is what lets the log
				// answer "was this permitted" for a call that failed afterwards.
				{failing, string(OutcomeFailed), string(gate.Allow), 0, string(db.KindObjectNotFound)},
			} {
				event := events[i]
				for field, wantValue := range map[string]any{
					"statement":  want.statement,
					"alias":      h.alias,
					"engine":     string(engine),
					"outcome":    want.outcome,
					"verdict":    want.verdict,
					"rows":       want.rows,
					"error_kind": want.errorKind,
					"tool":       ToolExecuteQuery,
					"identity":   "",
				} {
					if got := event[field]; got != wantValue {
						t.Errorf("event %d: %s = %#v, want %#v", i, field, got, wantValue)
					}
				}
				elapsed, ok := event["elapsed_ms"].(float64)
				if !ok || elapsed <= 0 {
					t.Errorf("event %d: elapsed_ms = %#v, want a positive duration", i, event["elapsed_ms"])
				}
				if _, ok := event["time"].(string); !ok {
					t.Errorf("event %d carries no timestamp", i)
				}
			}

			// The refused statement never reached a socket, so the audit line is the
			// only record that it was attempted at all. That is the whole reason
			// refusals are audited.
			if !strings.Contains(h.audit.String(), refused) {
				t.Errorf("the refused statement is not in the audit stream:\n%s", h.audit.String())
			}
		})
	}
}

// TestSignalShutsDownAndClosesEveryPool is acceptance criterion 10, on a server
// started through the same entry point the binary uses, with real pools open.
//
// A real SIGTERM is sent to this process rather than a context being cancelled,
// because the criterion is about the signal. It is safe: Run registers a handler
// for SIGTERM before it binds, which disables the default terminate disposition
// for as long as it is registered, and this package runs no test in parallel with
// another — so no other test can be in flight when the signal lands.
func TestSignalShutsDownAndClosesEveryPool(t *testing.T) {
	// One engine is enough: what is under test is the lifecycle, and the pools are
	// closed by internal/db for every alias at once.
	engine := gate.PostgreSQL
	cfg, spec := liveConfig(t, engine)
	e := executorFor(t, cfg, engine, spec.Alias)

	const shutdownTimeout = 10 * time.Second
	ready := make(chan string, 1)
	srv, err := New(Deps{
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: shutdownTimeout, Audit: AuditStdout},
		Executor: e,
		Log:      NewLogger(os.Stderr),
		Audit:    NewAuditor(os.Stderr),
		Ready:    func(addr string) { ready <- addr },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(context.Background()) }()

	var addr string
	select {
	case addr = <-ready:
	case err := <-runErr:
		t.Fatalf("Run returned before it was serving: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the server never reported a listen address")
	}

	// A real query first, so that a pool has a live connection to close and the
	// shutdown below is not draining an idle server.
	session := clientAt(t, "http://"+addr+"/mcp")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name:      ToolExecuteQuery,
		Arguments: map[string]any{"alias": spec.Alias, "statement": "SELECT 1"},
	})
	if err != nil || res.IsError {
		t.Fatalf("the server did not answer a query before shutdown: err=%v result=%+v", err, res)
	}
	_ = session.Close()

	started := time.Now()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run() = %v, want a clean shutdown", err)
		}
	case <-time.After(shutdownTimeout + 10*time.Second):
		t.Fatal("Run did not return within its bounded shutdown timeout")
	}
	if elapsed := time.Since(started); elapsed > shutdownTimeout {
		t.Errorf("shutdown took %s, longer than its %s bound", elapsed, shutdownTimeout)
	}

	// The listener is gone: nothing is accepting on that address any more.
	if conn, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
		_ = conn.Close()
		t.Errorf("something is still accepting connections on %s", addr)
	}

	// And a query arriving after shutdown reaches a closed pool and is reported,
	// rather than panicking on an emptied registry. This is what internal/db's
	// Close buys by leaving its registry populated.
	afterCtx, afterCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer afterCancel()
	_, err = e.Execute(afterCtx, spec.Alias, "SELECT 1", nil)
	if !errors.Is(err, db.ErrUnavailable) {
		t.Errorf("a query after shutdown = %v, want an error wrapping db.ErrUnavailable", err)
	}
}

// clientAt connects the SDK's real client to a running server.
func clientAt(t *testing.T, endpoint string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "cerberus-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           http.DefaultClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client.Connect(%s): %v", endpoint, err)
	}
	return session
}

// jsonOf renders a decoded value back to JSON, so an assertion can be written as
// the bytes the client received rather than as a Go value.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %#v: %v", v, err)
	}
	return string(b)
}
