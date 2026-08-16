//go:build integration

// The integration tests live behind a build tag rather than behind
// testcontainers-go. The repository had no non-driver dependency at all before
// this objective, and testcontainers pulls the OpenTelemetry SDK, its exporters
// and the Docker client; a compose file plus a build tag adds nothing.
//
// PostgreSQL and MySQL run as local containers — see deploy/compose.test.yaml.
// SQL Server does not, because no arm64 image of it exists; those tests take
// their connection entirely from the per-alias environment variables and skip
// with a clear message when they are not set. Nothing here assumes where any
// server lives.
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// containerEngines are the engines deploy/compose.test.yaml runs, and therefore
// the only ones against which a claim about a database the fixture created can be
// made.
//
// SQL Server is absent because no arm64 image of it exists (README.md:162-164).
// The SQL Server answer to the discovery criteria is a manual run against the real
// instance, and a green result here says nothing about it.
var containerEngines = []gate.Engine{gate.PostgreSQL, gate.MySQL}

// The two databases deploy/compose.test.yaml's init scripts create on both
// container engines.
//
// They are spelled out here rather than taken from the alias's configuration
// because they are facts about that fixture, not about a server somebody
// configured — and only the tests that are about the fixture use them. Every other
// test in this file still learns its whole topology from the environment, which is
// what lets them be pointed at an instance nothing here knows the shape of.
const (
	fixtureDatabase       = "testbed"
	fixtureSecondDatabase = "ledger"
)

// aliasEnvironment renders one alias back into the CERBERUS_DB_* variables it
// would have been declared with, with databases as the value of _DATABASES and the
// variable left out entirely when it is empty.
//
// It exists so that a test about a configuration shape can take a real server's
// topology from the environment and change only the shape: the host, the port and
// the credential come from an alias that is already known to work, and what the
// test varies is the one variable it is about. Going through [LoadConfigFrom]
// afterwards rather than assembling an [AliasSpec] is deliberate — the acceptance
// of the shape is then part of what the test establishes rather than something it
// assumes.
//
// No setting variable is included, so the bounds are the package's own defaults
// rather than the ones the run was configured with. Every caller reads a handful of
// rows.
func aliasEnvironment(alias string, spec AliasSpec, databases string) map[string]string {
	family := aliasPrefix + strings.ToUpper(alias)
	env := map[string]string{
		"CERBERUS_DB_ALIASES":   alias,
		family + suffixEngine:   string(spec.Engine),
		family + suffixHost:     spec.Host,
		family + suffixPort:     strconv.Itoa(spec.Port),
		family + suffixUser:     spec.User,
		family + suffixPassword: spec.Password.reveal(),
	}
	if spec.TLS != "" {
		env[family+suffixTLS] = string(spec.TLS)
	}
	if databases != "" {
		env[family+suffixDatabases] = databases
	}
	return env
}

// executorForEnvironment loads a configuration from env and builds an executor
// over it, through the same two calls the production startup path makes.
func executorForEnvironment(t *testing.T, env map[string]string) *Executor {
	t.Helper()
	neutraliseForeignVariables(t)
	cfg, err := LoadConfigFrom(env)
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

// slowReadThroughTheGate is, per engine, a read the gate allows and the server
// cannot finish. SQL Server is absent on purpose: there is no slow read on that
// engine that is safe to run against somebody else's production server, so its
// timeout is provoked through the driver in its own test file.
var slowReadThroughTheGate = map[gate.Engine]func(marker string) string{
	gate.PostgreSQL: pgSlowRead,
	gate.MySQL:      mySlowRead,
}

// restrictedObjectRead is, per engine, the reads of something an account without
// privileges is not allowed to see, tried in order until one of them is actually
// refused. They are real objects rather than simulated failures, which is what
// acceptance criterion 8 asks for — and when the configured account is privileged
// enough to read all of them, the test says which and skips rather than passing
// on a failure it did not provoke.
//
// The SQL Server entries are deliberately not catalog views. A caller without
// permission on a catalog view sees zero rows rather than error 229, so a catalog
// view cannot provoke this class at all: it looks like success with an empty
// result. Both entries here are plain user tables that ship in a system database
// with no grant to public, so only a principal with privileges in that database
// can read them and everyone else gets 229. `master` comes first because a login
// reaches it on a default instance whether or not it has a user of its own there.
var restrictedObjectRead = map[gate.Engine][]string{
	gate.PostgreSQL: {"SELECT * FROM pg_authid"},
	gate.MySQL:      {"SELECT * FROM mysql.user"},
	gate.SQLServer: {
		"SELECT * FROM master.dbo.MSreplication_options",
		"SELECT * FROM msdb.dbo.sysmail_server",
	},
}

// harness is one engine's executor plus the alias it was found under.
type harness struct {
	*Executor
	alias string
	spec  AliasSpec
}

// requireEnginesVar names the engines a run insists on, comma-separated, in the
// same spelling CERBERUS_DB_<ALIAS>_ENGINE uses.
//
// It exists because every skip in [setUp] is individually right — no
// configuration, no alias for the engine, or a configured alias that cannot be
// reached — and together they mean a typo in a CERBERUS_DB_* variable name
// produces exit 0 with nothing asserted, indistinguishable from the legitimate
// SQL Server skip. Five of this objective's ten acceptance criteria turn on that
// distinction, so CI names the engines it has containers for and a typo fails the
// job instead of passing it.
//
// Unset, an engine the environment says nothing about is optional, and that is
// what keeps the suite runnable by a developer with no containers at all. This
// variable is the only way to demand a particular engine, and what [TestMain]
// adds is deliberately weaker and orthogonal: it refuses a run that reached no
// engine at all. A declared alias for a server this machine cannot see — a VPN
// that is down — is still a skip as long as something else answered, so naming
// the engines a run must grade is still this variable's job and CI's business.
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

// skipOrFail skips, or fails when the run cannot honestly call this a skip. The
// reason is reported either way, so a green run can be read for what it actually
// established.
//
// One thing makes it a failure here: the engine is one the run insists on, which
// is CI's case and what requireEnginesVar is for. The other thing that must fail
// cannot be decided here. A CERBERUS_DB_* block that names a server is a claim
// the server is there, and a run that reached none of the servers it declares
// established nothing — `go test -tags integration ./internal/db/` against a
// block whose engines are all down exited 0 in half a second with every fixture
// assertion skipped, and Go's exit code cannot tell that apart from every one of
// them passing. But "no engine answered" is a property of the whole run and this
// is called per test, so the skip is recorded and [TestMain] passes the verdict
// once every test has had its turn. An engine that did not answer while another
// did is a skip: the run graded something, and a server this machine cannot
// reach today is not a defect in this package.
//
// Declaring nothing at all is recorded as nothing, and that is why the record is
// conditioned on the environment rather than on the reachability check that led
// here: somebody with no containers and no configuration must not be forced to
// start them, and an absent SQL Server alias — which is CI's own situation — must
// stay the quiet skip it has always been.
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
// every test in the package so that [TestMain] can answer a question no single
// test can: whether anything at all was graded.
//
// Neither map is synchronised. No test in this package calls t.Parallel — the
// suite neutralises ambient driver variables with t.Setenv, which panics under it
// — so every write here happens on one goroutine at a time.
var (
	enginesThatAnswered     = map[gate.Engine]bool{}
	enginesThatDidNotAnswer = map[gate.Engine]string{}
)

// noteEngineAnswered records that a declared server was reached and read from.
// One of these is what entitles every other engine to a skip.
//
// Every path in this package that reaches an engine calls it: [setUp], the
// reachability probe most tests share, and the two harnesses that probe on their
// own — the wide fixture's PostgreSQL path and the named SQL Server one. A
// harness that reached a server without recording here would not merely make
// [TestMain] stricter; it would make it wrong, because the sentence TestMain
// prints says every fixture assertion skipped, and those assertions ran and
// passed. Any harness added later has to record too.
func noteEngineAnswered(engine gate.Engine) { enginesThatAnswered[engine] = true }

// TestMain adds the verdict Go's exit code cannot carry. `go test` reports a
// package where every test skipped exactly as it reports one where every test
// passed, so a CERBERUS_DB_* block whose servers are all down produced a green
// run that had established nothing.
//
// The rule is deliberately the narrow one: the run fails only when it asked at
// least one declared engine and no engine answered at all. A run that graded one
// engine may skip another that did not answer — an operator whose environment
// declares a production server behind a VPN still gets a green local run over the
// containers that are up. Demanding a specific engine is CERBERUS_TEST_REQUIRE_ENGINES'
// job, which is what CI uses.
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
// because loading one failed — and a configuration that will not load is not a
// declaration of anything.
func engineIsConfigured(engine gate.Engine) bool {
	cfg, err := LoadConfig()
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

// setUp builds an executor from the process environment and finds an alias for
// the requested engine, skipping the test when there is none.
//
// Configuration comes from the environment and only from the environment, which
// is the same rule the production path follows. That is deliberate for SQL Server
// in particular: the test can then be pointed at whatever instance is available
// without a line of it knowing a host name.
func setUp(t *testing.T, engine gate.Engine) harness {
	t.Helper()
	// Asked here rather than only on a skip path, so that a misspelled engine name
	// in CERBERUS_TEST_REQUIRE_ENGINES is caught on a run where nothing skips.
	required := engineIsRequired(t, engine)
	// The integration environment is sourced into a shell that may well be the
	// operator's own, and every alias here reaches New. See
	// neutraliseForeignVariables: without this, an exported PGSERVICE turns the
	// whole integration suite into one startup refusal.
	neutraliseForeignVariables(t)
	cfg, err := LoadConfig()
	if err != nil {
		skipOrFail(t, required, engine, fmt.Sprintf("no usable CERBERUS_DB_* configuration in the environment (%v); see .env.example and deploy/compose.test.yaml", err))
	}
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)

	aliases := e.engineAliases(engine)
	if len(aliases) == 0 {
		skipOrFail(t, required, engine, fmt.Sprintf("no %s alias is configured; set CERBERUS_DB_ALIASES and the CERBERUS_DB_<ALIAS>_* family for a %s server", engine, engine))
	}
	alias := aliases[0]
	c, _ := e.connFor(alias)

	// A configured alias that cannot be reached goes through skipOrFail, which
	// records it: an alias declared in the environment is a claim that a server is
	// there, and a run that reached none of them graded nothing. "The VPN is down"
	// is not a defect in this package, so it stops being a skip only when it is the
	// whole of what this run could reach.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := e.Execute(ctx, alias, "SELECT 1", nil); err != nil {
		if errors.Is(err, ErrUnavailable) {
			skipOrFail(t, required, engine, fmt.Sprintf("alias %q (%s) is configured but not reachable: %v", alias, engine, err))
		}
		t.Fatalf("the configured %s alias %q rejected SELECT 1: %v", engine, alias, err)
	}
	noteEngineAnswered(engine)
	return harness{Executor: e, alias: alias, spec: c.spec()}
}

// TestExecuteReturnsRows is the base case every other test rests on: an
// authenticated caller asks for a read by alias and gets rows back, on whichever
// engines are configured.
func TestExecuteReturnsRows(t *testing.T) {
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUp(t, engine)
			res, err := h.Execute(context.Background(), h.alias, "SELECT 1 AS one, 'two' AS two", nil)
			if err != nil {
				t.Fatalf("Execute() = %v", err)
			}
			if len(res.Rows) != 1 || len(res.Columns) != 2 {
				t.Fatalf("got %d rows and %d columns, want 1 and 2: %+v", len(res.Rows), len(res.Columns), res)
			}
			if res.Truncated {
				t.Error("a one-row result reports truncation")
			}
			if res.Decision.Verdict != gate.Allow {
				t.Errorf("the result carries verdict %q", res.Decision.Verdict)
			}
			if res.Engine != engine || res.Alias != h.alias {
				t.Errorf("the result does not identify what ran it: %+v", res)
			}
			if res.Elapsed <= 0 {
				t.Error("the result reports no elapsed time, so an audit line cannot say how long it took")
			}
			// Row values must be usable without a driver type assertion the caller
			// cannot make. On MySQL every column arrives as []byte, so this is
			// where the normalisation earns its place.
			if got, ok := res.Rows[0][1].(string); !ok || got != "two" {
				t.Errorf("second column = %#v, want the string \"two\"", res.Rows[0][1])
			}
		})
	}
}

// TestRowCapStopsTheIterationAndReportsIt is acceptance criterion 7's row-cap
// half. The generator is written per engine because there is no portable way to
// produce many rows without a table, and a table is the one thing this test must
// not need against a third party's server.
func TestRowCapStopsTheIterationAndReportsIt(t *testing.T) {
	generators := map[gate.Engine]func(n int) string{
		gate.PostgreSQL: func(n int) string {
			return "SELECT i FROM generate_series(1, " + strconv.Itoa(n) + ") AS i"
		},
		gate.MySQL: func(n int) string {
			// A recursive CTE is the portable way to count on MySQL 8. It is also
			// exactly the construct a recorded wont-fix says this layer bounds by
			// magnitude rather than by depth, so running it here is on purpose.
			return "WITH RECURSIVE s AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM s WHERE i < " + strconv.Itoa(n) + ") SELECT i FROM s"
		},
		gate.SQLServer: func(n int) string {
			return "WITH s AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM s WHERE i < " + strconv.Itoa(n) + ") SELECT i FROM s OPTION (MAXRECURSION 0)"
		},
	}

	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUp(t, engine)
			rowCap := h.Settings().RowCap
			if rowCap < 2 {
				t.Fatalf("this test needs a row cap of at least 2, not %d", rowCap)
			}

			t.Run("a result larger than the cap is capped and says so", func(t *testing.T) {
				res, err := h.Execute(context.Background(), h.alias, generators[engine](rowCap*2), nil)
				if err != nil {
					t.Fatalf("Execute() = %v", err)
				}
				if len(res.Rows) != rowCap {
					t.Errorf("got %d rows, want exactly the cap %d", len(res.Rows), rowCap)
				}
				if !res.Truncated {
					t.Error("a capped result does not report truncation, so the agent cannot tell it is incomplete")
				}
			})

			t.Run("a result of exactly the cap is not called truncated", func(t *testing.T) {
				res, err := h.Execute(context.Background(), h.alias, generators[engine](rowCap), nil)
				if err != nil {
					t.Fatalf("Execute() = %v", err)
				}
				if len(res.Rows) != rowCap {
					t.Errorf("got %d rows, want %d", len(res.Rows), rowCap)
				}
				if res.Truncated {
					t.Error("a result of exactly the cap reports truncation, which would make the agent re-query forever")
				}
			})

			t.Run("a result under the cap is not called truncated", func(t *testing.T) {
				res, err := h.Execute(context.Background(), h.alias, generators[engine](rowCap-1), nil)
				if err != nil {
					t.Fatalf("Execute() = %v", err)
				}
				if len(res.Rows) != rowCap-1 || res.Truncated {
					t.Errorf("got %d rows, truncated=%v, want %d and false", len(res.Rows), res.Truncated, rowCap-1)
				}
			})
		})
	}
}

// TestSanitisationAgainstRealErrorClasses is acceptance criterion 8 against
// errors an engine actually produced. Every class here is provoked rather than
// constructed, and the assertion is made against the alias's own configured
// values rather than against a list of patterns — so a value nobody thought to
// look for is still caught.
func TestSanitisationAgainstRealErrorClasses(t *testing.T) {
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			h := setUp(t, engine)

			t.Run("a syntax error", func(t *testing.T) {
				// The gate allows this: it begins with SELECT and contains nothing
				// forbidden. Only the engine can reject it, which is the point.
				_, err := h.Execute(context.Background(), h.alias, "SELECT FROM WHERE", nil)
				assertSanitised(t, err, h.spec, KindInvalidStatement)
			})

			t.Run("an object that does not exist", func(t *testing.T) {
				_, err := h.Execute(context.Background(), h.alias, "SELECT * FROM cerberus_no_such_table_anywhere", nil)
				assertSanitised(t, err, h.spec, KindObjectNotFound)
			})

			t.Run("permission denied on a real object", func(t *testing.T) {
				statements := restrictedObjectRead[engine]
				if len(statements) == 0 {
					t.Skipf("no restricted object is known for %s", engine)
				}
				// Only two outcomes let a candidate be passed over: the account can
				// read it, or the object is not on this instance. A refusal that is
				// anything else is reported rather than skipped past, because on this
				// class an unclassified refusal — SQL Server's 916, say, for a
				// database the login cannot enter at all — is the finding.
				var passedOver []string
				for _, statement := range statements {
					_, err := h.Execute(context.Background(), h.alias, statement, nil)
					if err == nil {
						passedOver = append(passedOver, statement+" (this account can read it)")
						continue
					}
					var dbErr *Error
					if !errors.As(err, &dbErr) {
						t.Fatalf("%s: got %v, want a *db.Error", statement, err)
					}
					if dbErr.Kind == KindObjectNotFound {
						passedOver = append(passedOver, statement+" (no such object on this instance)")
						continue
					}
					assertSanitised(t, err, h.spec, KindPermissionDenied)
					return
				}
				t.Skipf("no permission failure could be provoked with this account: %s; point the alias at an account without privileges on one of them to exercise this class", strings.Join(passedOver, "; "))
			})

			t.Run("a query timeout", func(t *testing.T) {
				statement, ok := slowReadThroughTheGate[engine]
				if !ok {
					t.Skipf("no slow read that the gate allows is known for %s; its timeout is covered by the engine's own test", engine)
				}
				_, err := h.Execute(context.Background(), h.alias, statement("cerberus-sanitised-timeout"), nil)
				assertSanitised(t, err, h.spec, KindTimeout)
			})

			for _, tt := range []struct {
				name string
				bend func(spec *AliasSpec)
			}{
				{"a connection that times out", func(spec *AliasSpec) {
					// A documentation-range address (RFC 5737). Nothing routes it, so
					// the connect either times out or is refused by the local network
					// — both are the same class to the agent, and neither reaches a
					// server that could tell it anything.
					spec.Host = "192.0.2.1"
				}},
				{"a wrong password", func(spec *AliasSpec) { spec.Password = Secret("definitely-not-the-password") }},
				{"a host that does not resolve", func(spec *AliasSpec) {
					spec.Host = "no-such-host.cerberus.invalid"
				}},
				{"a port with nothing behind it", func(spec *AliasSpec) { spec.Port = deadPort(t) }},
				{"a database that does not exist", func(spec *AliasSpec) {
					spec.Database = "cerberus_no_such_database"
				}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					broken := h.spec
					tt.bend(&broken)
					_, err := executorForSpec(t, broken, h.Settings()).Execute(context.Background(), broken.Alias, "SELECT 1", nil)
					if err == nil {
						t.Fatal("the broken connection succeeded")
					}
					// Which class it lands in is the engine's business — a wrong
					// database is unavailable on one engine and a permission
					// failure on another. What must hold on all of them is that
					// the agent's side is clean and the operator's side is not
					// empty.
					var dbErr *Error
					if !errors.As(err, &dbErr) {
						t.Fatalf("Execute() = %v, want a *db.Error", err)
					}
					assertAgentSideIsClean(t, dbErr, broken)
					// The host of a broken spec is the one value that is not the
					// real alias's, so the real alias's values are checked too.
					assertAgentSideIsClean(t, dbErr, h.spec)
					if dbErr.Detail == "" {
						t.Error("the operator-facing detail is empty: the error was discarded rather than sanitised")
					}
				})
			}
		})
	}
}

func assertSanitised(t *testing.T, err error, spec AliasSpec, want Kind) {
	t.Helper()
	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("got %v, want a *db.Error", err)
	}
	if dbErr.Kind != want {
		t.Errorf("Kind = %q, want %q (detail: %s)", dbErr.Kind, want, dbErr.Detail)
	}
	if dbErr.Detail == "" {
		t.Error("the operator-facing detail is empty: the error was discarded rather than sanitised")
	}
	assertAgentSideIsClean(t, dbErr, spec)
}

// TestListDatabasesReportsTheFixtureDatabaseAndNoSystemOne is acceptance criterion
// 7 against the two engines that have containers.
//
// Both halves of it are needed and neither is enough alone. That a database the
// fixture created is reported is what says the tool answers the question at all;
// that no excluded name is reported is what says the exclusion list ran — and the
// control at the end is what stops the second half passing on a server that simply
// has nothing to exclude. The exclusion lists are read out of the package rather
// than restated here, so a name added to one is checked by this test the moment it
// is added.
func TestListDatabasesReportsTheFixtureDatabaseAndNoSystemOne(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := setUp(t, engine)
			d, ok := discoveryFor(engine)
			if !ok {
				t.Fatalf("no discovery statement is defined for %s", engine)
			}

			list, err := h.ListDatabases(context.Background(), h.alias)
			if err != nil {
				t.Fatalf("ListDatabases() = %v", err)
			}
			if list.Alias != h.alias || list.Engine != engine {
				t.Errorf("the answer does not identify what produced it: %+v", list)
			}
			if list.Decision.Verdict != gate.Allow {
				t.Errorf("the answer carries verdict %q", list.Decision.Verdict)
			}
			if list.Elapsed <= 0 {
				t.Error("the answer reports no elapsed time, so an audit line cannot say how long it took")
			}
			if list.Truncated {
				t.Fatalf("the row cap of %d stopped the discovery read, so a missing name below would mean the cap and not the exclusion list", list.RowCap)
			}
			if !slices.Contains(list.Databases, fixtureSecondDatabase) {
				t.Errorf("the answer %v does not contain %q, which deploy/compose.test.yaml's init scripts create on this engine", list.Databases, fixtureSecondDatabase)
			}
			for _, excluded := range d.exclude {
				if slices.Contains(list.Databases, excluded) {
					t.Errorf("%q is on this engine's exclusion list and in the answer anyway: %v", excluded, list.Databases)
				}
			}

			// The control. Without it the loop above is satisfied by any server that
			// happens to report none of those names, and a broken exclusion list would
			// pass. It runs the same statement through Execute — the same gate, the
			// same bounds — so what it compares against is the rows the answer was
			// computed from.
			raw, err := h.Execute(context.Background(), h.alias, d.statement, nil)
			if err != nil {
				t.Fatalf("the discovery statement through Execute = %v", err)
			}
			var dropped []string
			for _, row := range raw.Rows {
				if len(row) == 0 {
					continue
				}
				if name := databaseName(row[0]); slices.Contains(d.exclude, name) {
					dropped = append(dropped, name)
				}
			}
			if len(dropped) == 0 {
				t.Errorf("this server reports none of %v, so nothing above was actually excluded; the statement returned %v", d.exclude, raw.Rows)
			} else {
				t.Logf("excluded from the answer: %v", dropped)
			}
		})
	}
}

// executorForSpec builds a one-alias executor over a deliberately broken spec, so
// that a failure class can be provoked without disturbing the working alias.
func executorForSpec(t *testing.T, spec AliasSpec, s Settings) *Executor {
	t.Helper()
	neutraliseForeignVariables(t)
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	// A short connect timeout: several of these cases are meant to fail at the
	// socket and there is no reason for the suite to wait out a full VPN timeout.
	s.ConnectTimeout = 5 * time.Second
	s.QueryTimeout = 5 * time.Second
	e, err := New(g, &Config{Settings: s, Aliases: []AliasSpec{spec}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}
