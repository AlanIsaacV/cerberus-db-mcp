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
// is engine-neutral — the same Executor.SearchSchema and the same
// db.SchemaSearch — so what is untested is the driver below, not the code above.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
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

// TestListDatabasesReachesTheAgentFromRealEngines is list_databases through the
// whole stack: real pool, real gate, real HTTP, real MCP client.
//
// What it establishes that no loopback test can is that the discovery statement is
// one a real engine accepts and that its rows survive the trip to a client as names
// — the gate's approval of it is internal/db's own suite, and the per-engine
// exclusion lists are its criterion 7. What is asserted here is the boundary: the
// payload's shape, the truncation flag, and one audit event carrying the alias and
// the gate's verdict.
func TestListDatabasesReachesTheAgentFromRealEngines(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)

			res := h.call(t, ToolListDatabases, map[string]any{"alias": h.alias})
			if res.IsError {
				t.Fatalf("list_databases failed: %s", resultText(t, res))
			}
			out, ok := structured(t, res).(map[string]any)
			if !ok {
				t.Fatalf("list_databases returned no structured content: %+v", res)
			}

			raw, ok := out["databases"].([]any)
			if !ok {
				t.Fatalf("databases = %s, want an array", jsonOf(t, out["databases"]))
			}
			names := make([]string, 0, len(raw))
			for i, value := range raw {
				name, ok := value.(string)
				if !ok {
					t.Fatalf("databases[%d] = %s, want a string; an agent is going to read this as a name", i, jsonOf(t, value))
				}
				names = append(names, name)
			}
			if len(names) == 0 {
				t.Errorf("the login sees no non-system database at all, so this test asserts nothing about a name: give this alias's login at least one database in deploy/compose.test.yaml")
			}
			// The database the alias is connected to is necessarily one the login can
			// see, so its presence is the one name this test can insist on without
			// depending on another fixture. An alias with no configured database — legal
			// on MySQL and SQL Server — has nothing to check here.
			if h.spec.Database != "" && !slices.Contains(names, h.spec.Database) {
				t.Errorf("databases = %v, which does not include the database this alias is connected to; the discovery statement or its exclusion list is dropping a database the login demonstrably reaches", names)
			}
			if out["truncated"] != false {
				t.Errorf("truncated = %v for %d names under a row cap of %d, want false", out["truncated"], len(names), h.settings.RowCap)
			}
			if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
				t.Errorf("row_cap = %v, want %v", got, want)
			}

			events := h.auditEventsFor(t, ToolListDatabases)
			if len(events) != 1 {
				t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
			}
			for field, wantValue := range map[string]any{
				"tool":    ToolListDatabases,
				"alias":   h.alias,
				"engine":  string(engine),
				"outcome": string(OutcomeAllowed),
				// The gate allowed internal/db's own constant, and the record says so
				// rather than leaving a successful discovery call unaccounted for.
				"verdict": string(gate.Allow),
				"rows":    float64(len(names)),
				// This tool's statement is internal/db's, not the agent's.
				"statement": "",
			} {
				if got := events[0][field]; got != wantValue {
					t.Errorf("%s = %#v, want %#v", field, got, wantValue)
				}
			}
		})
	}
}

// TestSearchSchemaReachesTheAgentFromTheWideFixture covers the schema-search
// surface end to end: the real SDK client receives the already-grouped result of
// internal/db's fixed, bound catalog statement. The MySQL connection is rebuilt
// for ledger because CI intentionally configures only testbed, while ledger is
// where that engine's deliberately wide archive table lives.
func TestSearchSchemaReachesTheAgentFromTheWideFixture(t *testing.T) {
	wantIdentity := testIdentity()
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := wideSchemaSearchHarness(t, engine, wantIdentity)

			res := h.call(t, ToolSearchSchema, map[string]any{"alias": h.alias, "pattern": "measure"})
			if res.IsError {
				t.Fatalf("search_schema failed: %s", resultText(t, res))
			}
			out, ok := structured(t, res).(map[string]any)
			if !ok {
				t.Fatalf("search_schema returned no structured content: %+v", res)
			}
			assertSearchSchemaDoesNotLeakConnection(t, h, jsonOf(t, out))
			assertSearchSchemaDoesNotLeakConnection(t, h, resultText(t, res))
			assertTheSchemaFieldSaysItIsNotAnAlias(t, h)
			assertColumnsTruncatedTellsTheAgentWhatItMeansAndWhatToDo(t, h)
			for _, forbidden := range []string{"alias", "database", "host", "port", "user", "password"} {
				if _, found := out[forbidden]; found {
					t.Errorf("search_schema result has a %q field: %s", forbidden, jsonOf(t, out))
				}
			}

			tables, ok := out["tables"].([]any)
			if !ok || len(tables) != 1 {
				t.Fatalf("tables = %s, want exactly the wide archive table", jsonOf(t, out["tables"]))
			}
			table, ok := tables[0].(map[string]any)
			if !ok {
				t.Fatalf("tables[0] = %s, want an object", jsonOf(t, tables[0]))
			}
			wantSchema := "harbor"
			if engine == gate.MySQL {
				wantSchema = "ledger"
			}
			if table["schema"] != wantSchema || table["table"] != "archive" {
				t.Errorf("table = %s, want %s.archive", jsonOf(t, table), wantSchema)
			}

			columns, ok := table["columns"].([]any)
			if !ok || len(columns) == 0 {
				t.Fatalf("archive columns = %s, want matching measure columns", jsonOf(t, table["columns"]))
			}
			// Whether this particular call was cut by the byte budget or by the row cap
			// depends on the cap this job configures, so what is asserted here is that the
			// marker crosses the wire as a boolean on every entry. Its true case is graded
			// in TestSearchSchemaWireSizeStaysUnderItsBounds, which raises the cap so that
			// the budget is the bound that bites.
			if _, ok := table["columns_truncated"].(bool); !ok {
				t.Errorf("table = %s, want a columns_truncated boolean saying whether that column list is all of them", jsonOf(t, table))
			}
			hasNullable, hasRequired := false, false
			for i, raw := range columns {
				column, ok := raw.(map[string]any)
				if !ok {
					t.Fatalf("columns[%d] = %s, want an object", i, jsonOf(t, raw))
				}
				name, nameOK := column["name"].(string)
				dataType, typeOK := column["data_type"].(string)
				nullable, nullableOK := column["nullable"].(bool)
				if !nameOK || !strings.HasPrefix(name, "measure_") || !typeOK || dataType == "" || !nullableOK {
					t.Errorf("columns[%d] = %s, want a measure name, a type and a nullability boolean", i, jsonOf(t, column))
				}
				hasNullable = hasNullable || nullable
				hasRequired = hasRequired || !nullable
			}
			if !hasNullable || !hasRequired {
				t.Errorf("measure columns do not show both nullable and required metadata: %s", jsonOf(t, columns))
			}
			if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
				t.Errorf("row_cap = %v, want %v", got, want)
			}

			// A table-name match deliberately does not turn every one of that table's
			// columns into a match. The empty array must survive the MCP mapping so an
			// agent does not infer that those columns matched its substring — and it must
			// arrive with columns_truncated false, because that is the only thing on the
			// wire separating this claim from a budget that cut a column list off before
			// its first entry.
			byTableName := h.call(t, ToolSearchSchema, map[string]any{"alias": h.alias, "pattern": "archive"})
			if byTableName.IsError {
				t.Fatalf("search_schema by table name failed: %s", resultText(t, byTableName))
			}
			nameOut, ok := structured(t, byTableName).(map[string]any)
			if !ok {
				t.Fatalf("table-name search returned no structured content: %+v", byTableName)
			}
			nameTables, ok := nameOut["tables"].([]any)
			if !ok || len(nameTables) == 0 {
				t.Fatalf("table-name search tables = %s, want archive", jsonOf(t, nameOut["tables"]))
			}
			for i, raw := range nameTables {
				nameTable, ok := raw.(map[string]any)
				if !ok || nameTable["table"] != "archive" {
					t.Fatalf("table-name search tables[%d] = %s, want archive", i, jsonOf(t, raw))
				}
				columns, ok := nameTable["columns"].([]any)
				if !ok || len(columns) != 0 {
					t.Errorf("name-matched archive columns = %s, want an empty array", jsonOf(t, nameTable["columns"]))
				}
				if nameTable["columns_truncated"] != false {
					t.Errorf("name-matched archive columns_truncated = %v, want false: two table entries cannot exhaust the byte budget, and a true here would tell the agent this empty list means nothing",
						nameTable["columns_truncated"])
				}
			}

			// The allowed and invalid-argument calls follow different executor exits.
			// The latter still reached the gate before pattern validation, so both records
			// must carry its allow verdict and this caller's identity.
			invalidArgument := h.call(t, ToolSearchSchema, map[string]any{"alias": h.alias, "pattern": "m"})
			if !invalidArgument.IsError {
				t.Fatal("a one-character schema pattern succeeded")
			}
			if got, want := resultText(t, invalidArgument), (&db.Error{Kind: db.KindInvalidArgument}).Agent(); got != want {
				t.Errorf("the client was told %q, want the invalid-argument message %q", got, want)
			}
			events := h.auditEventsFor(t, ToolSearchSchema)
			if len(events) != 3 {
				t.Fatalf("got %d audit events for three calls:\n%s", len(events), h.audit.String())
			}
			for i, want := range []struct {
				outcome   Outcome
				errorKind db.Kind
			}{
				{OutcomeAllowed, ""},
				{OutcomeAllowed, ""},
				{OutcomeFailed, db.KindInvalidArgument},
			} {
				event := events[i]
				for field, wantValue := range map[string]any{
					"tool":       ToolSearchSchema,
					"identity":   wantIdentity.Email,
					"subject":    wantIdentity.Subject,
					"alias":      h.alias,
					"engine":     string(engine),
					"outcome":    string(want.outcome),
					"verdict":    string(gate.Allow),
					"error_kind": string(want.errorKind),
					// internal/db owns the catalog statement and never returns it here.
					"statement": "",
				} {
					if got := event[field]; got != wantValue {
						t.Errorf("event %d: %s = %#v, want %#v", i, field, got, wantValue)
					}
				}
			}
		})
	}
}

// TestSearchSchemaWireSizeStaysUnderItsBounds is acceptance criterion 9, measured
// where the agent actually pays for it.
//
// internal/db has a size test of its own and it is not this one: it marshals
// db.SchemaSearch, whose field names are not the ones that cross the wire and
// whose single copy is not what is sent. The SDK emits a typed result twice —
// once as structured content, once as the duplicate JSON text block the MCP spec
// asks for — so the cost of one call is the whole CallToolResult, which is what
// is marshalled here. Everything but the JSON-RPC envelope around it is in that
// number.
//
// The row cap is raised to the shipped default rather than left at the low one
// this job configures, because the bound under test is the byte budget and the
// whole reason it exists is that it holds where the row cap does not fire. A cap
// of 50 truncates the catalog rows long before the budget is reached, and the
// measurement would then be of the cap.
//
// The worst case is a claim about every pattern the tool accepts, and what makes
// it measurable from two calls is that internal/db's budget bounds the grouped
// tables whatever the pattern was: a pattern that exhausts the budget produces
// the largest answer this surface can produce, and truncated is how each call
// below reports that it did. The two exhaust it from opposite directions — "re"
// reaches recorded_at in every fixture table, many tables holding one column
// each; "measure" reaches 250 columns of the one wide table — and the larger of
// the two is the figure reported.
func TestSearchSchemaWireSizeStaysUnderItsBounds(t *testing.T) {
	const (
		namedTableCeiling = 4 << 10
		worstCaseCeiling  = 20 << 10
	)
	identity := testIdentity()
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			rowCap := shippedRowCap(t)
			h := wideSchemaSearchHarness(t, engine, identity, func(s *db.Settings) { s.RowCap = rowCap })

			// A pattern that approximately names one table. A column-naming pattern
			// such as "measure" is not a counter-example to this bound: it answers with
			// a table's whole matching column list, which is the worst case below and
			// is what this surface is for.
			named := h.searchSchema(t, "archive")
			namedOut, ok := structured(t, named).(map[string]any)
			if !ok {
				t.Fatalf("search_schema(archive) returned no structured content: %+v", named)
			}
			namedTables, ok := namedOut["tables"].([]any)
			if !ok || len(namedTables) == 0 {
				t.Fatalf("search_schema(archive) tables = %s, want the fixture's archive tables; a bound measured over an empty answer is not measured", jsonOf(t, namedOut["tables"]))
			}
			namedSize := wireBytes(t, named)
			if namedSize >= namedTableCeiling {
				t.Errorf("a search naming one table costs %d bytes on the wire, want under %d", namedSize, namedTableCeiling)
			}

			worstSize, worstPattern, worstTables, worstColumns := 0, "", 0, 0
			for _, pattern := range []string{"re", "measure"} {
				res := h.searchSchema(t, pattern)
				out, ok := structured(t, res).(map[string]any)
				if !ok {
					t.Fatalf("search_schema(%q) returned no structured content: %+v", pattern, res)
				}
				if out["truncated"] != true {
					t.Errorf("search_schema(%q) reports a complete answer at row cap %d, so the byte budget did not bind and this call does not measure the worst case: %s",
						pattern, rowCap, jsonOf(t, out))
				}
				if pattern == "measure" {
					// The budget binds here, and it binds inside the one wide table: 250
					// matching columns of a single entry, of which about half fit. The entry
					// stays — dropping it would answer this search with nothing — so it is
					// the entry itself that has to say its column list is a prefix.
					assertTheCutTableSaysSo(t, out)
				}
				if size := wireBytes(t, res); size > worstSize {
					worstSize, worstPattern = size, pattern
					worstTables, worstColumns = countSearchSchemaTables(t, out)
				}
			}

			// Read in CI from the job summary of the integration job, which runs this
			// one test again with -v; `go test` without it discards a passing test's
			// output, and a number nobody can read does not report anything.
			t.Logf("search_schema wire size on %s: %d bytes for a search naming one table, worst case %d bytes for pattern %q over %d tables and %d columns at row cap %d",
				engine, namedSize, worstSize, worstPattern, worstTables, worstColumns, rowCap)
			if worstSize >= worstCaseCeiling {
				t.Errorf("the worst schema search costs %d bytes on the wire for pattern %q, want under %d", worstSize, worstPattern, worstCaseCeiling)
			}
		})
	}
}

// wireBytes is what one tool call cost the agent: the result object the SDK sent,
// both copies of the payload included.
func wireBytes(t *testing.T, res *sdk.CallToolResult) int {
	t.Helper()
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal the tool result: %v", err)
	}
	return len(encoded)
}

// shippedRowCap is the cap a deployment that configures nothing runs under. This
// job deliberately configures a much lower one, and a test about the bound that
// applies when the row cap does not fire has to ask for the shipped value rather
// than assume the environment it is running in.
//
// The alias it declares is MySQL because a PostgreSQL one would make internal/db
// consult the process's own PGSERVICE, and a value there would turn reading a
// default into a failure that has nothing to do with this measurement.
func shippedRowCap(t *testing.T) int {
	t.Helper()
	cfg, err := db.LoadConfigFrom(map[string]string{
		"CERBERUS_DB_ALIASES":             "warehouse",
		"CERBERUS_DB_WAREHOUSE_ENGINE":    "mysql",
		"CERBERUS_DB_WAREHOUSE_HOST":      "db.internal.example",
		"CERBERUS_DB_WAREHOUSE_PORT":      "3306",
		"CERBERUS_DB_WAREHOUSE_DATABASES": "testbed",
		"CERBERUS_DB_WAREHOUSE_USER":      "reader",
		"CERBERUS_DB_WAREHOUSE_PASSWORD":  "not-in-any-error",
	})
	if err != nil {
		t.Fatalf("db.LoadConfigFrom() = %v", err)
	}
	return cfg.Settings.RowCap
}

// assertTheCutTableSaysSo grades the marker's true case over a result the byte
// budget stopped: the last entry is the one the cut fell in — a truncated answer is
// a prefix of the ordered rows, so no other entry can be the one — and it is the
// only entry allowed to carry the marker.
func assertTheCutTableSaysSo(t *testing.T, out map[string]any) {
	t.Helper()
	tables, ok := out["tables"].([]any)
	if !ok || len(tables) == 0 {
		t.Fatalf("tables = %s, want the entry the budget cut into", jsonOf(t, out["tables"]))
	}
	for i, raw := range tables {
		table, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("tables[%d] = %s, want an object", i, jsonOf(t, raw))
		}
		want := i == len(tables)-1
		if table["columns_truncated"] != want {
			t.Errorf("tables[%d] of %d has columns_truncated = %v, want %v: only the entry the cut fell in reports a partial column list, and that is the last one",
				i, len(tables), table["columns_truncated"], want)
		}
	}
}

func countSearchSchemaTables(t *testing.T, out map[string]any) (tables, columns int) {
	t.Helper()
	raw, ok := out["tables"].([]any)
	if !ok {
		t.Fatalf("tables = %s, want an array", jsonOf(t, out["tables"]))
	}
	for i, entry := range raw {
		table, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("tables[%d] = %s, want an object", i, jsonOf(t, entry))
		}
		list, ok := table["columns"].([]any)
		if !ok {
			t.Fatalf("tables[%d].columns = %s, want an array", i, jsonOf(t, table["columns"]))
		}
		columns += len(list)
	}
	return len(raw), columns
}

// assertSearchSchemaDoesNotLeakConnection checks the values an MCP result has no
// reason to contain.
//
// The host, the port, the username and the password are checked against the text
// as it stands: none of them has any place in a schema search on any engine.
//
// The database name is different and is checked differently, because on MySQL it
// is a value the result legitimately carries — tables[].schema is the database
// the alias is bound to, since internal/db's statement filters on DATABASE().
// Asserting its absence there would fail on the correct answer; exempting the
// engine, which is what this did before, is not grading the criterion on the one
// engine where the value appears at all. So the schema fields are redacted and
// the name is asserted absent from everything that is left: it may appear as a
// table's namespace and nowhere else. What that leaves — that a namespace is not
// something to pass back as an alias — is not a property of a value and cannot be
// asserted over one, so it is graded over the tool's advertised schema by
// assertTheSchemaFieldSaysItIsNotAnAlias.
func assertSearchSchemaDoesNotLeakConnection(t *testing.T, h engineHarness, text string) {
	t.Helper()
	for label, value := range map[string]string{
		"the host":     h.spec.Host,
		"the port":     strconv.Itoa(h.spec.Port),
		"the username": h.spec.User,
		"the password": string(h.spec.Password),
	} {
		if value != "" && strings.Contains(text, value) {
			t.Errorf("the client-visible schema-search result contains %s (%q): %q", label, value, text)
		}
	}
	if h.spec.Database == "" {
		return
	}
	if remainder := withoutTableNamespaces(t, text); strings.Contains(remainder, h.spec.Database) {
		t.Errorf("the client-visible schema-search result names the database (%q) somewhere other than a table's schema field: %q", h.spec.Database, remainder)
	}
}

// withoutTableNamespaces is the result with every tables[].schema value removed,
// so that what remains can be searched for a name the field is allowed to hold.
func withoutTableNamespaces(t *testing.T, text string) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("the client-visible schema-search result is not a JSON object (%v): %q", err, text)
	}
	tables, ok := decoded["tables"].([]any)
	if !ok {
		t.Fatalf("the schema-search result carries no tables array: %q", text)
	}
	for i, raw := range tables {
		table, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("tables[%d] = %s, want an object", i, jsonOf(t, raw))
		}
		delete(table, "schema")
	}
	return jsonOf(t, decoded)
}

// assertTheSchemaFieldSaysItIsNotAnAlias grades the half of criterion 10 that a
// value cannot carry. On MySQL a returned schema is the alias's own database
// name, and the thing that must not happen is that an agent reads it as an alias
// and hands it to execute_query. Nothing in the payload can say so — the tool's
// advertised output schema is where the agent is told, so that is what is
// asserted, on every engine because it is one description for all three.
func assertTheSchemaFieldSaysItIsNotAnAlias(t *testing.T, h engineHarness) {
	t.Helper()
	description := searchSchemaTableFieldDescription(t, h, "schema")

	// Both halves are required. "not an alias" is the refusal the agent needs; the
	// engine's name is what makes it actionable on MySQL, where the value is the
	// database's own name and the agent would otherwise have to guess what it is.
	for _, want := range []string{"not an alias", string(gate.MySQL)} {
		if !strings.Contains(description, want) {
			t.Errorf("the advertised description of a table's schema field does not mention %q, so an agent reading a database name there is told nothing: %q", want, description)
		}
	}
}

// assertColumnsTruncatedTellsTheAgentWhatItMeansAndWhatToDo grades the marker where
// the schema field is graded, and for the same reason: an agent that cannot read a
// field's meaning off the tool's advertised schema cannot act on the value. The
// marker is worth less than nothing unread — the shape it disambiguates looks
// exactly like the claim criterion 6 makes — so both halves are required: that an
// empty or short column list under it says nothing about the table, and that the
// remedy is a narrower substring rather than paging.
func assertColumnsTruncatedTellsTheAgentWhatItMeansAndWhatToDo(t *testing.T, h engineHarness) {
	t.Helper()
	description := searchSchemaTableFieldDescription(t, h, "columns_truncated")
	for _, want := range []string{"beginning", "empty list says nothing", "substring"} {
		if !strings.Contains(description, want) {
			t.Errorf("the advertised description of columns_truncated does not mention %q, so an agent reading it cannot tell what the field claims or what to do about it: %q", want, description)
		}
	}
}

// searchSchemaTableFieldDescription reads one field of a returned table out of the
// tool's own advertised output schema, as a client sees it over tools/list.
func searchSchemaTableFieldDescription(t *testing.T, h engineHarness, field string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := h.session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var tool *sdk.Tool
	for _, candidate := range list.Tools {
		if candidate.Name == ToolSearchSchema {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tools/list carries no %s", ToolSearchSchema)
	}

	node, ok := tool.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("%s output schema = %s, want an object", ToolSearchSchema, jsonOf(t, tool.OutputSchema))
	}
	for _, step := range []string{"properties", "tables", "items", "properties", field} {
		next, ok := node[step].(map[string]any)
		if !ok {
			t.Fatalf("%s output schema has no %q on the way to a table's %s field: %s", ToolSearchSchema, step, field, jsonOf(t, tool.OutputSchema))
		}
		node = next
	}
	description, _ := node["description"].(string)
	return description
}

// wideSchemaSearchHarness is the whole stack over the database that holds the
// wide fixture. adjust changes the settings both the executor and the returned
// harness run under, so a test that needs bounds other than the job's own
// configuration cannot end up asserting against the ones it did not get.
func wideSchemaSearchHarness(t *testing.T, engine gate.Engine, identity auth.Identity, adjust ...func(*db.Settings)) engineHarness {
	t.Helper()
	cfg, spec := liveConfig(t, engine)
	if engine == gate.MySQL {
		// CI binds mytest.testbed only, to keep ordinary calls unable to cross into
		// ledger. This separate connection is solely the wide-fixture test subject.
		spec.Alias = "schema-search-ledger"
		spec.Database = "ledger"
	}
	settings := cfg.Settings
	for _, a := range adjust {
		a(&settings)
	}
	executor := executorFor(t, &db.Config{Settings: settings, Aliases: []db.AliasSpec{spec}}, engine, spec.Alias)
	return engineHarness{
		harness:  connect(t, executor, admittingEveryRequestAs(identity)),
		spec:     spec,
		alias:    spec.Alias,
		settings: settings,
	}
}

// searchSchema calls the tool and fails the test if the call did not answer.
func (h engineHarness) searchSchema(t *testing.T, pattern string) *sdk.CallToolResult {
	t.Helper()
	res := h.call(t, ToolSearchSchema, map[string]any{"alias": h.alias, "pattern": pattern})
	if res.IsError {
		t.Fatalf("search_schema(%q) failed: %s", pattern, resultText(t, res))
	}
	return res
}

// TestListDatabasesTellsTheAgentNothingWhenItCannotConnect is the no-leak half of
// acceptance criterion 9 at this boundary, against an error a real engine's driver
// produced rather than one this test constructed.
//
// The class is the one that can be provoked with a real container: a wrong password
// on the same alias. Permission-denied on a metadata statement cannot be — pg_database
// is readable by everyone and MySQL's SHOW DATABASES filters silently instead of
// failing — and that half of the criterion is internal/db's, against a low-privilege
// role. What both share is this assertion: one of internal/db's fixed sentences and
// none of the alias's own values.
func TestListDatabasesTellsTheAgentNothingWhenItCannotConnect(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)

			broken := h.spec
			broken.Password = db.Secret("definitely-not-the-password")
			wrong := brokenAliasHarness(t, broken, h.settings)

			res := wrong.call(t, ToolListDatabases, map[string]any{"alias": broken.Alias})
			// Deliberately the same class as an unreachable host, for the reason
			// execute_query's twin of this test gives: telling the agent a password is
			// wrong is telling it something about a credential it cannot see.
			wrong.assertAgentMessage(t, res, db.KindUnavailable)
			// The working alias's own values are checked too, since the broken spec
			// differs from it in exactly one field.
			h.assertNothingAboutTheConnection(t, resultText(t, res))

			events := wrong.auditEventsFor(t, ToolListDatabases)
			if len(events) != 1 {
				t.Fatalf("got %d audit events for one failed call:\n%s", len(events), wrong.audit.String())
			}
			for field, wantValue := range map[string]any{
				"tool":       ToolListDatabases,
				"alias":      broken.Alias,
				"outcome":    string(OutcomeFailed),
				"error_kind": string(db.KindUnavailable),
			} {
				if got := events[0][field]; got != wantValue {
					t.Errorf("%s = %#v, want %#v", field, got, wantValue)
				}
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
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: shutdownTimeout},
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
