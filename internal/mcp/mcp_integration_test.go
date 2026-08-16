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

// skipOrFail is internal/db's helper, duplicated here with its rule intact. It
// fails outright only for an engine requireEnginesVar insists on. The other half
// of the rule cannot be decided per test: a run that reached none of the servers
// its CERBERUS_DB_* block declares graded nothing, and Go's exit code does not
// distinguish a suite that skipped everything from one that passed everything —
// but whether this engine's silence leaves the run empty is a property of the
// whole run, so the skip is recorded and [TestMain] passes the verdict.
//
// An environment that declares no alias for this engine still skips quietly, and
// so does one whose other engines answered. That is what keeps the suite runnable
// with no containers at all, what keeps CI — which declares no SQL Server — green
// over the SQL Server tests, and what keeps a declared server behind a VPN that is
// down from reddening a run over the containers that are up.
func skipOrFail(t *testing.T, required bool, engine gate.Engine, reason string) {
	t.Helper()
	if required {
		t.Fatalf("%s names %s, so this is a failure and not a skip: %s", requireEnginesVar, engine, reason)
	}
	if engineIsConfigured(engine) {
		enginesThatDidNotAnswer[engine] = reason
	}
	t.Skip(reason)
}

// The engines this run asked and what came of asking them, accumulated across
// every test in the package for [TestMain] to read. internal/db keeps its own
// copy of this, for the reason skipOrFail is duplicated.
//
// Neither map is synchronised: this package runs no test in parallel with
// another, which several tests here already depend on — TestSignalShutsDownAndClosesEveryPool
// sends the process a real SIGTERM.
var (
	enginesThatAnswered     = map[gate.Engine]bool{}
	enginesThatDidNotAnswer = map[gate.Engine]string{}
)

// noteEngineAnswered records that a declared server was reached and read from.
// One of these is what entitles every other engine to a skip. It is called from
// [executorFor], which every harness in this package goes through.
func noteEngineAnswered(engine gate.Engine) { enginesThatAnswered[engine] = true }

// TestMain adds the verdict Go's exit code cannot carry. `go test` reports a
// package where every test skipped exactly as it reports one where every test
// passed, so a CERBERUS_DB_* block whose servers are all down produced a green
// run that had established nothing.
//
// The rule is the narrow one: the run fails only when it asked at least one
// declared engine and no engine answered at all. Demanding a particular engine is
// requireEnginesVar's job, which is what CI uses.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if reason, nothing := nothingWasGraded(); nothing {
			fmt.Fprintln(os.Stderr, reason)
			code = 1
		}
	}
	os.Exit(code)
}

// nothingWasGraded reports whether the run has to fail and what to say, naming
// every engine that was asked and did not answer: the run is only readable if it
// says which server the block declared and could not reach.
func nothingWasGraded() (string, bool) {
	if len(enginesThatAnswered) > 0 || len(enginesThatDidNotAnswer) == 0 {
		return "", false
	}
	var names, lines []string
	for _, engine := range gate.Engines() {
		if reason, asked := enginesThatDidNotAnswer[engine]; asked {
			names = append(names, string(engine))
			lines = append(lines, fmt.Sprintf("\t%s: %s", engine, reason))
		}
	}
	return fmt.Sprintf("FAIL: nothing was graded. The environment declares a server for %s, this run asked and none of them answered, so every fixture assertion skipped:\n%s",
		strings.Join(names, ", "), strings.Join(lines, "\n")), true
}

// engineIsConfigured reports whether the environment declares an alias for this
// engine. It reads the environment itself rather than taking a caller's
// configuration, because one of the paths into [skipOrFail] is there precisely
// because loading one failed.
func engineIsConfigured(engine gate.Engine) bool {
	cfg, err := db.LoadConfig()
	if err != nil {
		return false
	}
	for _, spec := range cfg.Aliases {
		if spec.Engine == engine {
			return true
		}
	}
	return false
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

	// A configured alias that cannot be reached goes through skipOrFail, which
	// records it: the environment declared this engine, and a run that reached none
	// of the engines it declares graded nothing.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := e.Execute(ctx, alias, "SELECT 1", nil); err != nil {
		if errors.Is(err, db.ErrUnavailable) {
			skipOrFail(t, engineIsRequired(t, engine), engine, fmt.Sprintf("alias %q (%s) is configured but not reachable: %v", alias, engine, err))
		}
		t.Fatalf("the configured %s alias %q rejected SELECT 1: %v", engine, alias, err)
	}
	noteEngineAnswered(engine)
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

// TestSearchSchemaNamesTheBoundAcrossTheWire exercises the three values through
// the real MCP handler and both live catalogs. The row-cap case deliberately
// leaves a table-name match with an empty column list and columns_truncated false:
// without the top-level cause, that shape falsely claims no column matched.
func TestSearchSchemaNamesTheBoundAcrossTheWire(t *testing.T) {
	identity := testIdentity()
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			for _, tt := range []struct {
				name       string
				pattern    string
				adjust     func(*db.Settings)
				truncation db.Truncation
			}{
				{
					name:       "complete",
					pattern:    "archive",
					adjust:     func(s *db.Settings) { s.RowCap = 300 },
					truncation: db.NoTruncation,
				},
				{
					name:       "row cap",
					pattern:    "archive",
					adjust:     func(s *db.Settings) { s.RowCap = 2 },
					truncation: db.RowCapTruncation,
				},
				{
					name:       "byte budget",
					pattern:    "measure",
					adjust:     func(s *db.Settings) { s.RowCap = shippedRowCap(t) },
					truncation: db.ByteBudgetTruncation,
				},
			} {
				t.Run(tt.name, func(t *testing.T) {
					h := wideSchemaSearchHarness(t, engine, identity, tt.adjust)
					out, ok := structured(t, h.searchSchema(t, tt.pattern)).(map[string]any)
					if !ok {
						t.Fatalf("search_schema(%q) returned no structured content", tt.pattern)
					}
					if got := out["truncation"]; got != string(tt.truncation) {
						t.Errorf("search_schema(%q) truncation = %#v, want %q", tt.pattern, got, tt.truncation)
					}
					if tt.truncation == db.RowCapTruncation {
						tables, ok := out["tables"].([]any)
						if !ok || len(tables) != 1 {
							t.Fatalf("row-cap tables = %s, want one partial archive entry", jsonOf(t, out["tables"]))
						}
						table, ok := tables[0].(map[string]any)
						if !ok || table["columns_truncated"] != false {
							t.Errorf("row-cap table = %s, want no byte-budget marker", jsonOf(t, tables[0]))
						}
						columns, ok := table["columns"].([]any)
						if !ok || len(columns) != 0 {
							t.Errorf("row-cap columns = %s, want the ambiguous empty list the top-level cause resolves", jsonOf(t, table["columns"]))
						}
					}
				})
			}
		})
	}
}

// TestDescribeTableReachesTheAgentFromTheWideFixture checks the catalog answer
// after it has crossed the MCP boundary. internal/db has already established the
// per-engine reads; this test guards the field-by-field mapping, the descriptions
// which stop a returned namespace being mistaken for an alias, and the audit
// record the handler adds around that answer.
func TestDescribeTableReachesTheAgentFromTheWideFixture(t *testing.T) {
	wantIdentity := testIdentity()
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := wideSchemaSearchHarness(t, engine, wantIdentity)
			schema := describeFixtureSchema(engine)

			res := h.describeTable(t, "multi_index_probe", schema)
			out, ok := structured(t, res).(map[string]any)
			if !ok {
				t.Fatalf("describe_table returned no structured content: %+v", res)
			}
			assertDescribeTableDoesNotLeakConnection(t, h, jsonOf(t, out))
			assertDescribeTableDoesNotLeakConnection(t, h, resultText(t, res))
			assertDescribeTableSchemaFieldSaysItIsNotAnAlias(t, h)
			for _, forbidden := range []string{"alias", "database", "host", "port", "user", "password"} {
				if _, found := out[forbidden]; found {
					t.Errorf("describe_table result has a %q field: %s", forbidden, jsonOf(t, out))
				}
			}

			table := oneDescribedTable(t, out, schema, "multi_index_probe")
			assertMultiIndexProbeColumns(t, table)
			if table["columns_truncated"] != false {
				t.Errorf("complete describe columns_truncated = %#v, want false", table["columns_truncated"])
			}
			if got := jsonOf(t, table["primary_key"]); got != `["id"]` {
				t.Errorf("primary_key = %s, want [\"id\"]", got)
			}
			if got := jsonOf(t, table["indexes"]); got != `[{"columns":["title"],"name":"ix_multi_index_probe_title","unique":false},{"columns":["batch_code"],"name":"uq_multi_index_probe_batch_code","unique":true},{"columns":["serial_code"],"name":"ux_multi_index_probe_serial_code","unique":true}]` {
				t.Errorf("indexes = %s, want every named secondary index with its key order and uniqueness", got)
			}
			if got := out["truncation"]; got != string(db.NoTruncation) {
				t.Errorf("truncation = %#v, want %q", got, db.NoTruncation)
			}
			if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
				t.Errorf("row_cap = %v, want %v", got, want)
			}

			// The fixture chose this index specifically because alphabetical order and
			// reverse order both produce a plausible but wrong answer. It verifies the
			// positional order reaches an agent, rather than merely that an index exists.
			ordered := h.describeTable(t, "multi_column_index_probe", schema)
			orderedOut, ok := structured(t, ordered).(map[string]any)
			if !ok {
				t.Fatalf("describe_table(multi_column_index_probe) returned no structured content: %+v", ordered)
			}
			orderedTable := oneDescribedTable(t, orderedOut, schema, "multi_column_index_probe")
			if got := jsonOf(t, orderedTable["indexes"]); got != `[{"columns":["recorded_at","title","amount"],"name":"ix_multi_column_index_probe_recorded_at_title_amount","unique":false}]` {
				t.Errorf("multi-column indexes = %s, want the catalog key order", got)
			}

			// The invalid argument exits after the fixed catalog statements have passed
			// the gate. It must still become the same safe agent message and an audit
			// event, rather than becoming a second handler-specific error path.
			invalid := h.call(t, ToolDescribeTable, map[string]any{"alias": h.alias, "table": "", "schema": schema})
			if !invalid.IsError {
				t.Fatal("describe_table accepted an empty table name")
			}
			if got, want := resultText(t, invalid), (&db.Error{Kind: db.KindInvalidArgument}).Agent(); got != want {
				t.Errorf("the client was told %q, want the invalid-argument message %q", got, want)
			}

			events := h.auditEventsFor(t, ToolDescribeTable)
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
					"tool":       ToolDescribeTable,
					"identity":   wantIdentity.Email,
					"subject":    wantIdentity.Subject,
					"alias":      h.alias,
					"engine":     string(engine),
					"outcome":    string(want.outcome),
					"verdict":    string(gate.Allow),
					"error_kind": string(want.errorKind),
					// The statements are owned by internal/db and have no agent-facing
					// spelling to put in the audit stream.
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

// TestDescribeTableKeepsKeyAndIndexesWhenTheColumnReadIsCapped tests the shape
// the tool is built to preserve. CI runs with a row cap of 50, well below this
// fixture's 257 columns, but the independent key and index reads still fit and
// must survive whole rather than being silently shortened with the column list.
func TestDescribeTableKeepsKeyAndIndexesWhenTheColumnReadIsCapped(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			// Set the CI cap explicitly: this is a test of the promise at that
			// operational bound, not a coincidence of whichever environment invokes it.
			h := wideSchemaSearchHarness(t, engine, testIdentity(), func(s *db.Settings) { s.RowCap = 50 })
			out, ok := structured(t, h.describeTable(t, "wide_composite_key_probe", describeFixtureSchema(engine))).(map[string]any)
			if !ok {
				t.Fatal("describe_table(wide_composite_key_probe) returned no structured content")
			}
			table := oneDescribedTable(t, out, describeFixtureSchema(engine), "wide_composite_key_probe")
			columns, ok := table["columns"].([]any)
			if !ok || len(columns) == 0 || len(columns) >= 257 {
				t.Errorf("wide columns = %s, want the short non-empty prefix at the CI row cap", jsonOf(t, table["columns"]))
			}
			if got := out["truncation"]; got != string(db.RowCapTruncation) {
				t.Errorf("wide truncation = %#v, want %q at row cap %d", got, db.RowCapTruncation, h.settings.RowCap)
			}
			if got := jsonOf(t, table["primary_key"]); got != `["series_no","area_code"]` {
				t.Errorf("wide primary_key = %s, want [\"series_no\",\"area_code\"]", got)
			}
			if got := jsonOf(t, table["indexes"]); got != `[{"columns":["title"],"name":"ix_wide_composite_key_probe_title","unique":false}]` {
				t.Errorf("wide indexes = %s, want its complete secondary index list", got)
			}
		})
	}
}

// TestDescribeTableWireSizeStaysUnderItsBounds measures the whole MCP result,
// including the SDK's duplicate JSON text block. The wide probe's gauge_NNN
// columns are deliberately the shortest filler family in the fixture, so more
// of them fit under internal/db's byte budget than the longer measure_NNN names.
// PostgreSQL additionally measures the unqualified two-schema call, because its
// table-entry prefix is the largest shape describe_table can return.
func TestDescribeTableWireSizeStaysUnderItsBounds(t *testing.T) {
	const (
		namedTableCeiling = 4 << 10
		worstCaseCeiling  = 20 << 10
	)
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			rowCap := shippedRowCap(t)
			h := wideSchemaSearchHarness(t, engine, testIdentity(), func(s *db.Settings) { s.RowCap = rowCap })
			schema := describeFixtureSchema(engine)

			named := h.describeTable(t, "multi_index_probe", schema)
			namedOut, ok := structured(t, named).(map[string]any)
			namedTables, tablesOK := namedOut["tables"].([]any)
			if !ok || !tablesOK || len(namedTables) == 0 {
				t.Fatalf("describe_table(multi_index_probe) = %s, want the fixture table", jsonOf(t, namedOut))
			}
			namedSize := wireBytes(t, named)
			if namedSize >= namedTableCeiling {
				t.Errorf("a describe of one small table costs %d bytes on the wire, want under %d", namedSize, namedTableCeiling)
			}

			wideSchema := schema
			wideScope := "qualified"
			if engine == gate.PostgreSQL {
				// The two schemas both hold this table. Leaving schema absent is the
				// real worst case: it exercises the shared result budget across table
				// entries rather than measuring only one entry in isolation.
				wideSchema = ""
				wideScope = "unqualified two-schema"
			}
			wide := h.describeTable(t, "wide_composite_key_probe", wideSchema)
			wideOut, ok := structured(t, wide).(map[string]any)
			if !ok {
				t.Fatalf("describe_table(wide_composite_key_probe) returned no structured content: %+v", wide)
			}
			wideTable := oneDescribedTable(t, wideOut, schema, "wide_composite_key_probe")
			if got := wideOut["truncation"]; got != string(db.ByteBudgetTruncation) {
				t.Errorf("wide truncation = %#v at row cap %d, want %q so the byte budget binds: %s", got, rowCap, db.ByteBudgetTruncation, jsonOf(t, wideOut))
			}
			if got := jsonOf(t, wideTable["primary_key"]); got != `["series_no","area_code"]` {
				t.Errorf("wide primary_key = %s, want its complete ordered key", got)
			}
			if got := jsonOf(t, wideTable["indexes"]); got != `[{"columns":["title"],"name":"ix_wide_composite_key_probe_title","unique":false}]` {
				t.Errorf("wide indexes = %s, want its complete index list", got)
			}
			if wideTable["columns_truncated"] != true {
				t.Errorf("wide columns_truncated = %#v, want true because the byte budget cut this entry", wideTable["columns_truncated"])
			}
			wideSize := wireBytes(t, wide)
			// CI has a separate verbose invocation for this test: passing t.Logf output
			// is not printed by ordinary go test, so the figure would otherwise not be
			// reported where the acceptance criterion says it must be visible.
			t.Logf("describe_table wire size on %s: %d bytes for multi_index_probe and %d bytes for %s wide_composite_key_probe at row cap %d", engine, namedSize, wideSize, wideScope, rowCap)
			if wideSize >= worstCaseCeiling {
				t.Errorf("the widest describe_table result costs %d bytes on the wire, want under %d", wideSize, worstCaseCeiling)
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
// Three shapes are measured, and the third is the point of the tool. A pattern
// that matches by table name alone comes back with an empty column list, and the
// worst case comes back with as much as the budget buys; between them is the call
// an agent makes when it knows roughly what it wants — one table named, a few of
// that table's columns with it — which no figure in this repository covered until
// namesake_probe was added to the fixture to make it producible at all.
//
// The worst case is a claim about every pattern the tool accepts, and what makes
// it approachable from a handful of calls is that internal/db's budget bounds the
// grouped tables whatever the pattern was: no pattern can be answered with more
// than the budget's worth of entries, and truncation is how each call below names
// the bound that cut its answer. What that argument gives is the order of the
// figure, not the figure — the budget is spent in an accounting of its own, and
// how many wire bytes a spent budget buys depends on the shape of what it bought.
// So what is reported here is the largest of three patterns hand-picked to exhaust
// the budget from different directions, not a proven maximum: "re" reaches
// recorded_at in every fixture table, many tables holding one column each;
// "measure" reaches the 250 measure_NNN columns of archive; "gauge" reaches the
// 250 gauge_NNN columns of wide_composite_key_probe. A filler family named more
// briefly than gauge_NNN would buy more columns per budget byte than any of the
// three and would need a pattern of its own added to the loop below — the fixture
// is grown by hand, so noticing that is a person's job and this sentence is the
// only thing that asks them to.
//
// That job has been done once since it was written, for namesake_probe: it is not
// such a family. Its four matching columns are named longer than gauge_NNN and
// there are four of them in one table rather than 250, so no pattern reaching them
// can approach the budget, and the winning patterns are unchanged — "gauge" on
// PostgreSQL, "re" on MySQL. What it did add is one more table for "re" to reach
// through recorded_at, in both schemas on PostgreSQL and in the one database this
// harness binds on MySQL.
//
// "gauge" is not redundant with "measure" even though both cut inside one wide
// table. The budget is charged in bytes, so a shorter column name lets more
// columns fit under the same charge, and every column that fits costs the wire
// the JSON object around it as well as its name — twice over, since the SDK sends
// the payload as structured content and again as an escaped JSON text block.
// gauge_NNN is two characters shorter than measure_NNN, which is what buys those
// extra columns and why it is the larger figure on PostgreSQL despite being
// reached through a much longer table name. A worst case measured only over the
// longer names understates.
//
// The two families are laid out differently as well, and the difference reads
// backwards to what it costs. measure_NNN exists in exactly one table in the whole
// fixture — the wide archive of the second schema or database — while gauge_NNN is
// in wide_composite_key_probe, which every schema and database has. So on
// PostgreSQL, where this harness reaches both schemas of testbed, "gauge" matches
// 500 columns across two tables and is still answered with one: the budget is
// spent inside the first table's column list long before the second table is
// reached, and it is that first table's own shape, not the number of tables the
// pattern matches, that sets the figure.
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

			// The call this tool exists for, measured here for the first time. Both
			// figures around it are extremes: "archive" matches by table name alone,
			// which internal/db answers with an empty column list, and the loop below
			// exhausts the budget. What an agent actually does — name the one table it
			// means and get back the few columns of it it cares about — sits between
			// them and was never a number.
			//
			// What the answer must contain is asserted by the shared namesake helper
			// rather than restated here, so that this measurement and the sequence test
			// that begins with the same call cannot come to disagree about the fixture.
			cheap := h.searchSchema(t, namesakePattern)
			cheapOut, ok := structured(t, cheap).(map[string]any)
			if !ok {
				t.Fatalf("search_schema(%q) returned no structured content: %+v", namesakePattern, cheap)
			}
			assertNamesakeSearchFoundTheTableAndItsColumns(t, engine, cheapOut, describeFixtureSchema(engine))
			cheapEntries, cheapColumns := countSearchSchemaTables(t, cheapOut)
			cheapSize := wireBytes(t, cheap)
			if cheapSize >= namedTableCeiling {
				t.Errorf("a search naming one table and %d of its columns costs %d bytes on the wire, want under %d", len(namesakeMatchedColumns), cheapSize, namedTableCeiling)
			}
			// Read in CI from the job summary, like the worst-case line below: the
			// wording carries "search_schema wire size" because that is what the
			// workflow's grep selects.
			t.Logf("search_schema wire size on %s: %d bytes for the call the tool exists for, pattern %q over %d entries and %d matching columns at row cap %d",
				engine, cheapSize, namesakePattern, cheapEntries, cheapColumns, rowCap)

			worstSize, worstPattern, worstTables, worstColumns := 0, "", 0, 0
			for _, pattern := range []string{"re", "measure", "gauge"} {
				res := h.searchSchema(t, pattern)
				out, ok := structured(t, res).(map[string]any)
				if !ok {
					t.Fatalf("search_schema(%q) returned no structured content: %+v", pattern, res)
				}
				if out["truncation"] != string(db.ByteBudgetTruncation) {
					t.Errorf("search_schema(%q) truncation = %#v at row cap %d, want %q so the byte budget binds and this call measures the worst case: %s",
						pattern, out["truncation"], rowCap, db.ByteBudgetTruncation, jsonOf(t, out))
				}
				if pattern == "measure" || pattern == "gauge" {
					// The budget binds here, and it binds inside one wide table: 250 matching
					// columns in that table, of which about half fit. "gauge" matches such a
					// table in every schema rather than in one, but the first of them spends
					// the whole budget on its own, so the cut still lands inside a single
					// entry. That entry stays — dropping it would answer this search with
					// nothing — so it is the entry itself that has to say its column list is
					// a prefix.
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

// agentSequenceCeiling is the whole promise the sequence tests measure — that an
// agent can find a table and its columns in a schema it has never seen for less
// than this much of its context — expressed as the serialised bytes of one
// four-call sequence.
const agentSequenceCeiling = 25 << 10

// sequenceMeter sums what a sequence of tool calls cost the agent's context.
//
// Two tests walk that sequence: TestAgentSequenceCostOnTheWire against the
// compose fixture on every push, and TestSQLServerAgentSequenceCostOnTheWire by
// hand against an instance no job can reach. The entire reason the pair exists is
// that their two figures are directly comparable, and a second copy of this
// arithmetic is how they would stop being.
type sequenceMeter struct {
	t     *testing.T
	total int
}

// measure adds one call's whole CallToolResult to the total and hands back its
// structured content.
//
// The figure is the whole result rather than internal/db's: the SDK sends a typed
// result twice, once as structured content and once as the duplicate JSON text
// block the MCP spec asks for, so measuring the payload alone would report about
// half of what the agent actually pays.
func (m *sequenceMeter) measure(label string, res *sdk.CallToolResult) map[string]any {
	m.t.Helper()
	size := wireBytes(m.t, res)
	m.total += size
	// The text block is one copy of the payload, logged beside the whole result so
	// the gap between them is a figure in the output rather than an inference: the
	// difference is the second copy plus the envelope, and it is why this
	// measurement cannot be taken over an internal/db result.
	m.t.Logf("wire size: %s cost %d bytes, carrying a %d-byte payload the SDK sends twice", label, size, len(resultText(m.t, res)))
	out, ok := structured(m.t, res).(map[string]any)
	if !ok {
		m.t.Fatalf("%s returned no structured content: %+v", label, res)
	}
	return out
}

// reportAgainstTheCeiling states the total and fails when it breaches
// agentSequenceCeiling. where says which run produced the figure, since one
// binary reports this line once per engine.
//
// The wording carries "agent sequence" because .github/workflows/ci.yml greps for
// it to build the job summary, and "wire size" in [sequenceMeter.measure] is
// selected the same way. Both are coupled to that workflow by string agreement
// and nothing else.
func (m *sequenceMeter) reportAgainstTheCeiling(where string) {
	m.t.Helper()
	verdict := "under"
	if m.total > agentSequenceCeiling {
		verdict = "over"
	}
	m.t.Logf("the whole agent sequence %s cost %d bytes on the wire, %s the %d-byte ceiling", where, m.total, verdict, agentSequenceCeiling)
	if m.total > agentSequenceCeiling {
		m.t.Errorf("the agent sequence cost %d bytes on the wire, want at most %d", m.total, agentSequenceCeiling)
	}
}

// describedSelect is the statement a sequence's fourth call runs, together with
// the parts of it a later assertion has to name: what it restricts on and where.
//
// Callers populate what their own assertions read. The SQL Server sequence needs
// all four, because it reads a window of key values back out of the table it just
// described and has to spell both names the way T-SQL wants them; the fixture
// sequence writes bare identifiers into one statement and reads only the key
// column back.
type describedSelect struct {
	statement string
	qualified string
	key       string
	keyColumn string
}

// namesTable reports whether a catalog answer contains one exact schema-qualified
// table.
func namesTable(t *testing.T, out map[string]any, schema, table string) bool {
	t.Helper()
	tables, ok := out["tables"].([]any)
	if !ok {
		t.Fatalf("the answer carries no tables array: %s", jsonOf(t, out))
	}
	for _, raw := range tables {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a table entry is %s, want an object", jsonOf(t, raw))
		}
		if entry["schema"] == schema && entry["table"] == table {
			return true
		}
	}
	return false
}

// assertRowBoundIsOnTheWire checks the half of the reporting rule that applies to
// a flat result: whether the row cap cut it, and the cap's own value beside the
// answer so the agent can tell a full page from a coincidence.
func assertRowBoundIsOnTheWire(t *testing.T, h engineHarness, out map[string]any, label string) {
	t.Helper()
	if _, ok := out["truncated"].(bool); !ok {
		t.Errorf("%s does not say whether the row cap cut it: %s", label, jsonOf(t, out))
	}
	if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
		t.Errorf("%s row_cap = %#v, want the cap that applied (%v)", label, got, want)
	}
}

// assertCatalogBoundsAreOnTheWire is the same rule over a catalog answer, which
// has two bounds rather than one and names which of them cut it.
//
// When the byte budget is what cut it, the answer also has to be a strict prefix:
// the entry the cut fell in is the last one and it is the only one that may say
// its column list is partial.
func assertCatalogBoundsAreOnTheWire(t *testing.T, h engineHarness, out map[string]any, label string) {
	t.Helper()
	truncation, _ := out["truncation"].(string)
	switch db.Truncation(truncation) {
	case db.NoTruncation, db.RowCapTruncation, db.ByteBudgetTruncation:
	default:
		t.Errorf("%s truncation = %#v, want one of %v", label, out["truncation"],
			[]db.Truncation{db.NoTruncation, db.RowCapTruncation, db.ByteBudgetTruncation})
	}
	if got, want := out["row_cap"], float64(h.settings.RowCap); got != want {
		t.Errorf("%s row_cap = %#v, want the cap that applied (%v)", label, got, want)
	}
	if budget, ok := out["byte_budget"].(float64); !ok || budget <= 0 {
		t.Errorf("%s does not report the byte budget it was assembled under: %s", label, jsonOf(t, out))
	}
	if db.Truncation(truncation) == db.ByteBudgetTruncation {
		assertTheCutTableSaysSo(t, out)
	}
	t.Logf("%s reports truncation %q under row cap %v and byte budget %v", label, truncation, out["row_cap"], out["byte_budget"])
}

// keyColumnIndex locates the restricted column in the answer's own column list,
// which is the only thing that says where its values sit: the projection order is
// the statement's, and the result reports it rather than the caller assuming it.
func keyColumnIndex(t *testing.T, query map[string]any, name string) int {
	t.Helper()
	columns, ok := query["columns"].([]any)
	if !ok {
		t.Fatalf("the result carries no columns array: %s", jsonOf(t, query))
	}
	for i, raw := range columns {
		if column, ok := raw.(string); ok && column == name {
			return i
		}
	}
	t.Fatalf("the result names %s, none of them the column the statement restricts on", jsonOf(t, columns))
	return -1
}

// leadingKeyColumn is the first column of the described primary key, or of the
// first described index when the table has no primary key.
func leadingKeyColumn(t *testing.T, table map[string]any) string {
	t.Helper()
	if key, ok := table["primary_key"].([]any); ok && len(key) > 0 {
		if name, ok := key[0].(string); ok {
			return name
		}
	}
	indexes, ok := table["indexes"].([]any)
	if !ok {
		return ""
	}
	for _, raw := range indexes {
		index, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		columns, ok := index["columns"].([]any)
		if !ok || len(columns) == 0 {
			continue
		}
		if name, ok := columns[0].(string); ok {
			return name
		}
	}
	return ""
}

// stringField reads one required string out of a decoded result.
func stringField(t *testing.T, out map[string]any, field string) string {
	t.Helper()
	value, ok := out[field].(string)
	if !ok || value == "" {
		t.Fatalf("the result has no %s: %s", field, jsonOf(t, out))
	}
	return value
}

// The namesake fixture contract, stated once for the two tests that turn on it:
// TestSearchSchemaWireSizeStaysUnderItsBounds, which measures what that call
// costs, and TestAgentSequenceCostOnTheWire, which walks the sequence it begins.
//
// tools/wide-schema emits namesake_probe into every schema and database of the
// wide fixture, and it is the only table there whose own name and several of its
// column names share a substring — which is what lets one pattern reach a table
// *and* a handful of its columns, and therefore what makes this the call the tool
// exists for rather than a name-only match that comes back with no columns at all.
const (
	namesakeTable     = "namesake_probe"
	namesakePattern   = "namesake"
	namesakeKeyColumn = "id"
	// The seeded rows are id = 1..5 consecutive, and the sequence's restriction
	// keeps those above namesakeKeyFloor. Both numbers are named rather than
	// inlined because the assertion that the restriction dropped rows is arithmetic
	// over the pair: it is only a claim about restricting if fewer rows come back
	// than the table holds, and that comparison needs to know both.
	namesakeSeededRows = 5
	namesakeKeyFloor   = 2
)

// namesakeMatchedColumns are the columns namesakePattern reaches, in the order a
// search answers with: alphabetical, because search_schema's catalog statements
// end in ORDER BY column_name while describe_table's order by ordinal position.
// The two tools answer about the same table in different orders on purpose — a
// search result is a set of matches, a description is the table — so writing the
// fixture's DDL order here would fail. The table's other six columns do not carry
// the substring, which is what makes the answer a handful of columns rather than
// the whole table.
var namesakeMatchedColumns = []string{"namesake_code", "namesake_label", "namesake_rank", "namesake_state"}

// assertNamesakeSearchFoundTheTableAndItsColumns grades the narrow question the
// namesake fixture exists to make askable: the pattern reached the table by its
// own name, and the answer carries only the columns sharing that substring, each
// with a type an agent can pick its columns off.
//
// The expected number of entries is per engine because the two aliases reach
// different amounts of schema, not because the tool behaves differently. The
// PostgreSQL alias is bound to testbed, whose atelier and harbor schemas both hold
// this table; the MySQL one is bound to ledger alone, since MySQL has no schema
// below the database. Both are the same one-table answer repeated as many times as
// the alias can see it.
func assertNamesakeSearchFoundTheTableAndItsColumns(t *testing.T, engine gate.Engine, search map[string]any, schema string) {
	t.Helper()
	wantEntries := 1
	if engine == gate.PostgreSQL {
		wantEntries = 2
	}
	entries, columns := countSearchSchemaTables(t, search)
	t.Logf("search_schema(%q) matched %d tables and %d columns", namesakePattern, entries, columns)
	if entries != wantEntries || columns != wantEntries*len(namesakeMatchedColumns) {
		t.Errorf("search_schema(%q) matched %d tables and %d columns, want %d and %d: %s",
			namesakePattern, entries, columns, wantEntries, wantEntries*len(namesakeMatchedColumns), jsonOf(t, search["tables"]))
	}
	if !namesTable(t, search, schema, namesakeTable) {
		t.Errorf("search_schema(%q) did not find %s.%s, the table the pattern is the name of: %s", namesakePattern, schema, namesakeTable, jsonOf(t, search))
	}
	// A truncated answer would make the column count above a statement about the
	// budget rather than about the table, and both callers would then be measuring a
	// cut result on a fixture that is supposed to fit.
	if got := search["truncation"]; got != string(db.NoTruncation) {
		t.Errorf("search_schema(%q) truncation = %#v, want %q: this pattern reaches one small table and nothing here should be cut", namesakePattern, got, db.NoTruncation)
	}

	tables, _ := search["tables"].([]any)
	for i, raw := range tables {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("tables[%d] = %s, want an object", i, jsonOf(t, raw))
		}
		if entry["table"] != namesakeTable {
			t.Errorf("tables[%d] = %s, want %s", i, jsonOf(t, entry), namesakeTable)
		}
		if entry["columns_truncated"] != false {
			t.Errorf("tables[%d] columns_truncated = %#v, want false: this answer is complete", i, entry["columns_truncated"])
		}
		list, ok := entry["columns"].([]any)
		if !ok || len(list) == 0 {
			t.Fatalf("tables[%d] columns = %s, want the columns the pattern names; an empty list is the table-name-only shape and not the call this is about", i, jsonOf(t, entry["columns"]))
		}
		names := make([]string, 0, len(list))
		for j, rawColumn := range list {
			column, ok := rawColumn.(map[string]any)
			if !ok {
				t.Fatalf("tables[%d] columns[%d] = %s, want an object", i, j, jsonOf(t, rawColumn))
			}
			name, _ := column["name"].(string)
			names = append(names, name)
			if dataType, _ := column["data_type"].(string); dataType == "" {
				t.Errorf("tables[%d] columns[%d] = %s, want a data type: an agent picks its columns off these", i, j, jsonOf(t, column))
			}
		}
		if !slices.Equal(names, namesakeMatchedColumns) {
			t.Errorf("tables[%d] columns = %v, want exactly %v", i, names, namesakeMatchedColumns)
		}
	}
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

// assertDescribeTableDoesNotLeakConnection is the describe_table counterpart of
// assertSearchSchemaDoesNotLeakConnection. A MySQL table schema is its database
// name, so that one legitimate field is removed before the remaining result is
// searched; every other connection value has no place in this response at all.
func assertDescribeTableDoesNotLeakConnection(t *testing.T, h engineHarness, text string) {
	t.Helper()
	for label, value := range map[string]string{
		"the host":     h.spec.Host,
		"the port":     strconv.Itoa(h.spec.Port),
		"the username": h.spec.User,
		"the password": string(h.spec.Password),
	} {
		if value != "" && strings.Contains(text, value) {
			t.Errorf("the client-visible describe-table result contains %s (%q): %q", label, value, text)
		}
	}
	if h.spec.Database == "" {
		return
	}
	if remainder := withoutDescribedTableNamespaces(t, text); strings.Contains(remainder, h.spec.Database) {
		t.Errorf("the client-visible describe-table result names the database (%q) somewhere other than a table's schema field: %q", h.spec.Database, remainder)
	}
}

// withoutDescribedTableNamespaces removes every tables[].schema value from a
// describe_table result before a MySQL database name is treated as a leak.
func withoutDescribedTableNamespaces(t *testing.T, text string) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("the client-visible describe-table result is not a JSON object (%v): %q", err, text)
	}
	tables, ok := decoded["tables"].([]any)
	if !ok {
		t.Fatalf("the describe-table result carries no tables array: %q", text)
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

// assertDescribeTableSchemaFieldSaysItIsNotAnAlias checks the advertised
// metadata rather than a payload value. The sentence is what keeps a MySQL
// database name in tables[].schema from being passed back as an alias.
func assertDescribeTableSchemaFieldSaysItIsNotAnAlias(t *testing.T, h engineHarness) {
	t.Helper()
	description := describeTableFieldDescription(t, h, "schema")
	for _, want := range []string{"not an alias", string(gate.MySQL)} {
		if !strings.Contains(description, want) {
			t.Errorf("the advertised description of a described table's schema field does not mention %q: %q", want, description)
		}
	}
}

// describeTableFieldDescription reads one field of describe_table's advertised
// result schema through tools/list, the same view an MCP client receives.
func describeTableFieldDescription(t *testing.T, h engineHarness, field string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := h.session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var tool *sdk.Tool
	for _, candidate := range list.Tools {
		if candidate.Name == ToolDescribeTable {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tools/list carries no %s", ToolDescribeTable)
	}
	node, ok := tool.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("%s output schema = %s, want an object", ToolDescribeTable, jsonOf(t, tool.OutputSchema))
	}
	for _, step := range []string{"properties", "tables", "items", "properties", field} {
		next, ok := node[step].(map[string]any)
		if !ok {
			t.Fatalf("%s output schema has no %q on the way to a table's %s field: %s", ToolDescribeTable, step, field, jsonOf(t, tool.OutputSchema))
		}
		node = next
	}
	description, _ := node["description"].(string)
	return description
}

func describeFixtureSchema(engine gate.Engine) string {
	if engine == gate.MySQL {
		return "ledger"
	}
	return "atelier"
}

// oneDescribedTable returns the qualified fixture table, keeping every caller's
// cardinality assertion explicit: a table absent from the wire is not an empty
// description of it, and an unqualified duplicate must not silently satisfy a
// test intended to read one table.
func oneDescribedTable(t *testing.T, out map[string]any, schema, name string) map[string]any {
	t.Helper()
	tables, ok := out["tables"].([]any)
	if !ok || len(tables) != 1 {
		t.Fatalf("tables = %s, want exactly %s.%s", jsonOf(t, out["tables"]), schema, name)
	}
	table, ok := tables[0].(map[string]any)
	if !ok {
		t.Fatalf("tables[0] = %s, want an object", jsonOf(t, tables[0]))
	}
	if table["schema"] != schema || table["table"] != name {
		t.Fatalf("table = %s, want %s.%s", jsonOf(t, table), schema, name)
	}
	return table
}

func assertMultiIndexProbeColumns(t *testing.T, table map[string]any) {
	t.Helper()
	columns, ok := table["columns"].([]any)
	if !ok || len(columns) != 8 {
		t.Fatalf("columns = %s, want all eight multi_index_probe columns", jsonOf(t, table["columns"]))
	}
	wantNames := map[string]bool{
		"id": false, "title": false, "note": false, "amount": false,
		"active": false, "recorded_at": false, "serial_code": false, "batch_code": false,
	}
	for i, raw := range columns {
		column, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("columns[%d] = %s, want an object", i, jsonOf(t, raw))
		}
		name, nameOK := column["name"].(string)
		dataType, typeOK := column["data_type"].(string)
		nullable, nullableOK := column["nullable"].(bool)
		if !nameOK || !typeOK || dataType == "" || !nullableOK {
			t.Errorf("columns[%d] = %s, want a name, type and nullability boolean", i, jsonOf(t, column))
			continue
		}
		if _, found := wantNames[name]; !found {
			t.Errorf("columns[%d].name = %q, want one of the fixture's eight columns", i, name)
			continue
		}
		if wantNames[name] {
			t.Errorf("columns repeats %q: %s", name, jsonOf(t, columns))
		}
		wantNames[name] = true
		if wantNullable := name == "note"; nullable != wantNullable {
			t.Errorf("columns[%d] %q nullable = %v, want %v", i, name, nullable, wantNullable)
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("columns = %s, missing %q", jsonOf(t, columns), name)
		}
	}
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

// listDatabases calls the tool and fails the test if it did not answer.
func (h engineHarness) listDatabases(t *testing.T) *sdk.CallToolResult {
	t.Helper()
	res := h.call(t, ToolListDatabases, map[string]any{"alias": h.alias})
	if res.IsError {
		t.Fatalf("list_databases failed: %s", resultText(t, res))
	}
	return res
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

// describeTable calls the fixed metadata tool and keeps its success check with
// the other live-fixture helpers, so the individual assertions stay about the
// answer that crossed the transport rather than about protocol mechanics.
func (h engineHarness) describeTable(t *testing.T, table, schema string) *sdk.CallToolResult {
	t.Helper()
	args := map[string]any{"alias": h.alias, "table": table}
	if schema != "" {
		args["schema"] = schema
	}
	res := h.call(t, ToolDescribeTable, args)
	if res.IsError {
		t.Fatalf("describe_table(%q, %q) failed: %s", table, schema, resultText(t, res))
	}
	return res
}

// TestDescribeTableTellsTheAgentNothingWhenItCannotConnect ensures the handler
// sends failures through refuseOrFail rather than exposing a catalog, driver or
// configured connection detail. The wrong credential provokes a real driver
// failure while leaving the working fixture untouched.
func TestDescribeTableTellsTheAgentNothingWhenItCannotConnect(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUpEngine(t, engine)
			broken := h.spec
			broken.Password = db.Secret("definitely-not-the-password")
			wrong := brokenAliasHarness(t, broken, h.settings)

			res := wrong.call(t, ToolDescribeTable, map[string]any{"alias": broken.Alias, "table": "multi_index_probe"})
			wrong.assertAgentMessage(t, res, db.KindUnavailable)
			// The working alias differs only in the credential, and checking it as
			// well proves a replacement error path did not expose the original config.
			h.assertNothingAboutTheConnection(t, resultText(t, res))

			events := wrong.auditEventsFor(t, ToolDescribeTable)
			if len(events) != 1 {
				t.Fatalf("got %d audit events for one failed call:\n%s", len(events), wrong.audit.String())
			}
			for field, wantValue := range map[string]any{
				"tool":       ToolDescribeTable,
				"alias":      broken.Alias,
				"engine":     string(engine),
				"outcome":    string(OutcomeFailed),
				"verdict":    string(gate.Allow),
				"error_kind": string(db.KindUnavailable),
				"statement":  "",
			} {
				if got := events[0][field]; got != wantValue {
					t.Errorf("%s = %#v, want %#v", field, got, wantValue)
				}
			}
		})
	}
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
