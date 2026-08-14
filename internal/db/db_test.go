package db

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// deadPort returns a TCP port on the loopback interface with nothing listening
// on it. A listener is opened and closed so that the port is one the operating
// system just handed out, rather than a number picked in the hope that it is
// free — a test that silently connected to something else would prove nothing.
func deadPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// deadPortDatabase is the database name a dead-port PostgreSQL alias lists.
//
// Only PostgreSQL gets one, and the asymmetry is the configuration under test
// rather than an accident of this helper: PostgreSQL requires
// CERBERUS_DB_<ALIAS>_DATABASES because a connection there is bound to one database
// by the protocol, while on MySQL and SQL Server leaving it out is a supported
// choice. So a PostgreSQL alias here is always a derived one and its name always
// carries the dot, and the other two keep the name they were declared under.
const deadPortDatabase = "nothing_is_there"

// pgAlias is the name the PostgreSQL alias in [allThreeEngines] actually ends up
// with, which is not the name it was declared under.
const pgAlias = "pg" + derivedAliasSeparator + deadPortDatabase

// deadPortEnvironment builds an environment with one alias per requested engine,
// each pointing at a port with nothing behind it.
func deadPortEnvironment(t *testing.T, engines map[string]gate.Engine) map[string]string {
	t.Helper()
	names := make([]string, 0, len(engines))
	env := map[string]string{
		"CERBERUS_DB_QUERY_TIMEOUT":   "2s",
		"CERBERUS_DB_CONNECT_TIMEOUT": "1s",
		"CERBERUS_DB_TIMEOUT_GRACE":   "1s",
	}
	for alias, engine := range engines {
		names = append(names, alias)
		family := "CERBERUS_DB_" + strings.ToUpper(alias)
		env[family+"_ENGINE"] = string(engine)
		env[family+"_HOST"] = "127.0.0.1"
		env[family+"_PORT"] = strconv.Itoa(deadPort(t))
		env[family+"_USER"] = "nobody"
		env[family+"_PASSWORD"] = "irrelevant-because-nothing-listens"
		if engine == gate.PostgreSQL {
			env[family+"_DATABASES"] = deadPortDatabase
		}
	}
	env["CERBERUS_DB_ALIASES"] = strings.Join(names, ",")
	return env
}

// allThreeEngines is the alias-to-engine map most of this file's tests use. Its
// PostgreSQL entry is declared as "pg" and configured as [pgAlias]; see
// [deadPortDatabase].
func allThreeEngines() map[string]gate.Engine {
	return map[string]gate.Engine{"pg": gate.PostgreSQL, "my": gate.MySQL, "ms": gate.SQLServer}
}

// neutraliseForeignVariables takes the variables [refuseForeignConfiguration]
// refuses, and the ones a driver reads behind this package's back, out of play for
// one test.
//
// Without it the suite is decided by the shell it runs in, and the person most
// likely to have PGSERVICE exported is exactly the psql-using operator the refusal
// was written for: with PGSERVICE set, ten tests in this package fail, and four of
// them print the operator's own ~/.pg_service.conf path into the test output. The
// product is behaving as designed in every one of those cases — what is wrong is a
// suite that reads the ambient environment as input.
//
// Empty rather than unset, because empty is the value both drivers ignore, which
// is the state this package's own tolerance test pins: pgx skips a PG* variable
// set to empty (pgconn/config.go:609-613) and msdsn guards its read with
// `if epaString != ""`. Unsetting would work too; setting to empty says out loud
// which state is being asked for.
//
// It uses t.Setenv, so it is incompatible with t.Parallel. No test in this package
// is parallel, and this is one more reason none should become so without reading
// this first.
func neutraliseForeignVariables(t *testing.T) {
	t.Helper()
	for _, name := range append(slices.Clone(serviceFileVariables), epaVariable) {
		t.Setenv(name, "")
	}
}

// executorOnDeadPorts builds one alias per engine, each pointing at a port with
// nothing behind it. Any statement that reaches a driver therefore fails, which
// is what makes "refused before a connection is used" observable: the refusal has
// to arrive instead of a dial failure, not merely before it.
func executorOnDeadPorts(t *testing.T) *Executor {
	t.Helper()
	neutraliseForeignVariables(t)
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	cfg, err := LoadConfigFrom(deadPortEnvironment(t, allThreeEngines()))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

// TestRefusedStatementsNeverReachADriver is acceptance criterion 2. The control
// case at the end is what gives it teeth: the same alias, the same executor and a
// statement the gate allows must fail with a connection error, proving the port
// really is dead and that a refused statement did not merely get lucky.
func TestRefusedStatementsNeverReachADriver(t *testing.T) {
	e := executorOnDeadPorts(t)

	for _, tt := range []struct {
		name      string
		alias     string
		statement string
		want      Kind
	}{
		{"a write", pgAlias, "DELETE FROM users", KindRefused},
		{"a write hidden in a CTE", pgAlias, "WITH w AS (DELETE FROM users RETURNING id) SELECT * FROM w", KindRefused},
		{"two statements separated by a semicolon", "my", "SELECT 1; SELECT 2", KindRefused},
		{"two statements separated by one space", "ms", "SELECT 1 SELECT 2", KindRefused},
		{"schema change", "ms", "DROP TABLE dbo.Invoices", KindRefused},
		{"a permission change", "my", "GRANT ALL ON *.* TO 'x'@'%'", KindRefused},
		{"a shell out", "ms", "EXEC xp_cmdshell 'dir'", KindRefused},
		{"an unknown leading keyword", pgAlias, "COMMENT ON TABLE users IS 'x'", KindRefused},
		{"a call to a function nobody has approved", "ms", "SELECT dbo.CalcularSaldo(1)", KindNeedsApproval},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := e.Execute(context.Background(), tt.alias, tt.statement, nil)
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("Execute() = %v, want a *db.Error", err)
			}
			if dbErr.Kind != tt.want {
				t.Fatalf("Kind = %q, want %q (detail: %s)", dbErr.Kind, tt.want, dbErr.Detail)
			}
			if dbErr.Detail != "" {
				t.Errorf("a refusal carries a driver detail, so something spoke to a driver: %s", dbErr.Detail)
			}
			if dbErr.Op != "execute" {
				t.Errorf("Op = %q, so an operator's log names the wrong call", dbErr.Op)
			}
			if dbErr.Decision == nil {
				t.Fatal("the gate's decision is not carried on the error")
			}
			// The verdict and reason must be the gate's own. Asking the gate again
			// is how the test asserts "unmodified" without restating the gate's
			// rules here.
			want := e.gate.Validate(e.conns[tt.alias].spec().Engine, tt.statement, nil)
			if dbErr.Decision.Verdict != want.Verdict || dbErr.Decision.Reason != want.Reason ||
				dbErr.Decision.RuleID != want.RuleID || dbErr.Decision.Detail != want.Detail {
				t.Errorf("decision = %+v, want the gate's own %+v", *dbErr.Decision, want)
			}
		})
	}

	// The control: nothing is listening, so an allowed statement must fail at the
	// socket. If this passed, every case above would be meaningless.
	for _, alias := range []string{pgAlias, "my", "ms"} {
		t.Run("the port really is dead for "+alias, func(t *testing.T) {
			_, err := e.Execute(context.Background(), alias, "SELECT 1", nil)
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("Execute() = %v, want a *db.Error", err)
			}
			if dbErr.Kind != KindUnavailable && dbErr.Kind != KindTimeout {
				t.Fatalf("Kind = %q, want the connection to have failed; detail: %s", dbErr.Kind, dbErr.Detail)
			}
			if dbErr.Decision != nil {
				t.Errorf("a connection failure carries a gate decision: %+v", *dbErr.Decision)
			}
		})
	}
}

func TestGrantUnblocksAnEscalationBeforeAnyConnection(t *testing.T) {
	e := executorOnDeadPorts(t)
	const statement = "SELECT dbo.CalcularSaldo(1)"

	_, err := e.Execute(context.Background(), "ms", statement, nil)
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Kind != KindNeedsApproval {
		t.Fatalf("Execute() without a grant = %v, want needs-approval", err)
	}
	if len(refusal.Decision.Pending) == 0 {
		t.Fatal("an escalation with nothing pending cannot be granted")
	}

	// With the grant the statement is allowed, so it must now reach the driver
	// and fail there. That transition is the proof that the grant is passed
	// through to the gate rather than being interpreted here.
	grants := []gate.Grant{{RuleID: refusal.Decision.Pending[0]}}
	_, err = e.Execute(context.Background(), "ms", statement, grants)
	var granted *Error
	if !errors.As(err, &granted) {
		t.Fatalf("Execute() with a grant = %v, want a *db.Error", err)
	}
	if granted.Kind == KindNeedsApproval || granted.Kind == KindRefused {
		t.Fatalf("Kind = %q, want the grant to have let the statement reach the driver", granted.Kind)
	}
}

func TestUnknownAliasTouchesNothing(t *testing.T) {
	e := executorOnDeadPorts(t)
	_, err := e.Execute(context.Background(), "no-such-alias", "SELECT 1", nil)
	if !errors.Is(err, ErrUnknownAlias) {
		t.Fatalf("Execute() = %v, want ErrUnknownAlias", err)
	}
	var dbErr *Error
	if !errors.As(err, &dbErr) || dbErr.Detail != "" {
		t.Fatalf("Execute() = %v, want an error with no driver detail", err)
	}
}

func TestAliasesListsNameAndEngineOnly(t *testing.T) {
	e := executorOnDeadPorts(t)
	got := e.Aliases()
	if len(got) != 3 {
		t.Fatalf("Aliases() = %v, want three", got)
	}
	byName := map[string]gate.Engine{}
	for _, a := range got {
		byName[a.Name] = a.Engine
	}
	for name, engine := range map[string]gate.Engine{pgAlias: gate.PostgreSQL, "my": gate.MySQL, "ms": gate.SQLServer} {
		if byName[name] != engine {
			t.Errorf("alias %q = %q, want %q", name, byName[name], engine)
		}
	}
}

// TestAliasesPutDerivedNamesWhereTheParentWasDeclared is the second half of
// acceptance criterion 2, at the executor rather than at the loader: the registry
// preserves declared order and list_connections shows it to the agent unsorted, so
// where a derived alias lands is something an agent sees.
func TestAliasesPutDerivedNamesWhereTheParentWasDeclared(t *testing.T) {
	env := deadPortEnvironment(t, map[string]gate.Engine{
		"first":  gate.MySQL,
		"middle": gate.PostgreSQL,
		"last":   gate.SQLServer,
	})
	// deadPortEnvironment writes CERBERUS_DB_ALIASES from a map, so the order it
	// chose is whatever the runtime chose. It is restated here because the property
	// under test is a claim about that order.
	env["CERBERUS_DB_ALIASES"] = "first,middle,last"
	env["CERBERUS_DB_MIDDLE_DATABASES"] = "sales, ops ,archive"

	neutraliseForeignVariables(t)
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	cfg, err := LoadConfigFrom(env)
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)

	want := []Alias{
		{Name: "first", Engine: gate.MySQL},
		{Name: "middle.sales", Engine: gate.PostgreSQL},
		{Name: "middle.ops", Engine: gate.PostgreSQL},
		{Name: "middle.archive", Engine: gate.PostgreSQL},
		{Name: "last", Engine: gate.SQLServer},
	}
	if got := e.Aliases(); !slices.Equal(got, want) {
		t.Errorf("Aliases() = %+v, want %+v", got, want)
	}
}

func TestNewRejectsAMissingGate(t *testing.T) {
	cfg, err := LoadConfigFrom(completeEnvironment())
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	if _, err := New(nil, cfg); !errors.Is(err, ErrNoGate) {
		t.Fatalf("New(nil, cfg) = %v, want ErrNoGate", err)
	}
}

// TestNewRefusesToStartOnAServiceFileVariable is criterion 1's "no file is read
// for configuration" clause, for the one case a connection-string value cannot
// close. With PGSERVICE set, pgx reads a service file during ParseConfig on the
// presence of the key alone, so the alternative to refusing is an operator's psql
// habits deciding whether this process starts — and a missing file makes every
// PostgreSQL alias fail to open.
//
// Each case asserts four things: the refusal is our sentinel and not pgx's own
// failure to read the file, it names the variable, it quotes no value, and it
// arrives instead of an open error rather than after one.
func TestNewRefusesToStartOnAServiceFileVariable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		variable string
		value    string
	}{
		{
			name:     "PGSERVICE, whose file does not exist",
			variable: "PGSERVICE",
			value:    "cerberus-service-entry",
		},
		{
			name: "PGSERVICEFILE, whose value is a path",
			// A path that does exist would be read; one that does not makes pgx fail.
			// Either way it must not get that far, and the path must not be quoted
			// back — which is why this value is checked against as a value.
			variable: "PGSERVICEFILE",
			value:    "/home/operator/.pg_service.conf",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := deadPortEnvironment(t, allThreeEngines())
			// Neutralised first and then set, in that order: this test asserts
			// which variable is named, and an ambient PGSERVICE would be found
			// before the PGSERVICEFILE case's own. t.Setenv applies in call order,
			// so the second call is the one that stands.
			neutraliseForeignVariables(t)
			t.Setenv(tt.variable, tt.value)

			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			cfg, err := LoadConfigFrom(env)
			if err != nil {
				t.Fatalf("LoadConfigFrom: %v", err)
			}
			e, err := New(g, cfg)
			if e != nil {
				t.Cleanup(e.Close)
			}
			if !errors.Is(err, ErrUnsupportedVariable) {
				t.Fatalf("New() = %v, want ErrUnsupportedVariable", err)
			}
			text := err.Error()
			if !strings.Contains(text, tt.variable) {
				t.Errorf("the error does not name %s, so an operator cannot act on it: %s", tt.variable, text)
			}
			// pgx's own words for the same condition. Seeing them would mean the
			// refusal fired after ParseConfig rather than before it, and pgx's text
			// carries the connection string and the path.
			if strings.Contains(text, "failed to read service") {
				t.Errorf("the error is pgx's, so a service file was read before we refused: %s", text)
			}
			// The variable's own value is checked alongside the alias's, because a
			// path is exactly the kind of thing this package must not print.
			withValue := maps.Clone(env)
			withValue[tt.variable] = tt.value
			assertNoValues(t, text, withValue)
		})
	}
}

// TestNewToleratesAServiceFileVariableItCannotAffect is the other half of the
// decision, and it is what keeps the refusal proportionate. The variable only
// matters because a driver reads it, so with no alias for that driver there is
// nothing to refuse — an operator whose shell sets PGSERVICE for their own psql
// has broken nothing.
func TestNewToleratesAServiceFileVariableItCannotAffect(t *testing.T) {
	for _, tt := range []struct {
		name    string
		engines map[string]gate.Engine
		value   string
	}{
		{
			name:    "no PostgreSQL alias is configured",
			engines: map[string]gate.Engine{"my": gate.MySQL, "ms": gate.SQLServer},
			value:   "cerberus-service-entry",
		},
		{
			// pgx ignores a PG* variable set to the empty string, so an empty value
			// cannot cause the read and refusing on it would be a refusal on a
			// condition that does not exist.
			name:    "the variable is present but empty",
			engines: allThreeEngines(),
			value:   "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The SQL Server alias in both cases makes this test sensitive to an
			// ambient MSSQL_USE_EPA, which is a different refusal than the one under
			// test here.
			neutraliseForeignVariables(t)
			t.Setenv("PGSERVICE", tt.value)
			t.Setenv("PGSERVICEFILE", tt.value)

			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			cfg, err := LoadConfigFrom(deadPortEnvironment(t, tt.engines))
			if err != nil {
				t.Fatalf("LoadConfigFrom: %v", err)
			}
			e, err := New(g, cfg)
			if err != nil {
				t.Fatalf("New() = %v, want an executor", err)
			}
			t.Cleanup(e.Close)
			if len(e.Aliases()) != len(tt.engines) {
				t.Errorf("Aliases() = %v, want %d", e.Aliases(), len(tt.engines))
			}
		})
	}
}

// TestNewRefusesToStartOnTheDriverEPAVariable is MSSQL_USE_EPA closed the same
// way PGSERVICE is. It is not a file read and not a credential, so criterion 1
// does not reach it; it is refused because it is the last variable outside
// CERBERUS_DB_* that a driver in this package's dependency closure still consults
// in non-test code, and because of what it does when it is malformed.
//
// Measured against msdsn v1.10.0 with this package's own DSN: unset gives
// EpaEnabled false, "true" gives true, and "not-a-bool" makes msdsn.Parse fail
// with `invalid epa enabled value 'not-a-bool'` — which openSQLServer wraps into an
// open error that quotes the value back. So without this refusal the malformed case
// is a startup error printing a value, which is what every other error in this
// package is written to avoid.
func TestNewRefusesToStartOnTheDriverEPAVariable(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{name: "a value the driver accepts", value: "true"},
		{
			// The case that would otherwise reach msdsn and come back with the value
			// in the error text.
			name:  "a value the driver cannot parse",
			value: "not-a-bool",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := deadPortEnvironment(t, allThreeEngines())
			neutraliseForeignVariables(t)
			t.Setenv(epaVariable, tt.value)

			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			cfg, err := LoadConfigFrom(env)
			if err != nil {
				t.Fatalf("LoadConfigFrom: %v", err)
			}
			e, err := New(g, cfg)
			if e != nil {
				t.Cleanup(e.Close)
			}
			if !errors.Is(err, ErrUnsupportedVariable) {
				t.Fatalf("New() = %v, want ErrUnsupportedVariable", err)
			}
			text := err.Error()
			if !strings.Contains(text, epaVariable) {
				t.Errorf("the error does not name %s, so an operator cannot act on it: %s", epaVariable, text)
			}
			// The driver's own words for the malformed case. Seeing them would mean
			// the refusal fired after msdsn.Parse rather than before it, and msdsn's
			// text carries the value.
			if strings.Contains(text, "invalid epa enabled value") {
				t.Errorf("the error is the driver's, so the DSN was parsed before we refused: %s", text)
			}
			withValue := maps.Clone(env)
			withValue[epaVariable] = tt.value
			assertNoValues(t, text, withValue)
		})
	}
}

// TestNewToleratesAnEPAVariableItCannotAffect is the proportionate half, and the
// empty case is the one that says why the refusal is on a non-empty value rather
// than on presence. Measured: msdsn guards its read with `if epaString != ""`
// (msdsn/conn_str.go:660), so MSSQL_USE_EPA= gives EpaEnabled false exactly as
// unset does — the same rule pgx follows for PG*, and refusing on it would be a
// refusal on a condition that does not exist.
func TestNewToleratesAnEPAVariableItCannotAffect(t *testing.T) {
	for _, tt := range []struct {
		name    string
		engines map[string]gate.Engine
		value   string
	}{
		{
			name:    "no SQL Server alias is configured",
			engines: map[string]gate.Engine{"pg": gate.PostgreSQL, "my": gate.MySQL},
			value:   "true",
		},
		{
			name:    "the variable is present but empty",
			engines: allThreeEngines(),
			value:   "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			neutraliseForeignVariables(t)
			t.Setenv(epaVariable, tt.value)

			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			cfg, err := LoadConfigFrom(deadPortEnvironment(t, tt.engines))
			if err != nil {
				t.Fatalf("LoadConfigFrom: %v", err)
			}
			e, err := New(g, cfg)
			if err != nil {
				t.Fatalf("New() = %v, want an executor", err)
			}
			t.Cleanup(e.Close)
			if len(e.Aliases()) != len(tt.engines) {
				t.Errorf("Aliases() = %v, want %d", e.Aliases(), len(tt.engines))
			}
		})
	}
}

// TestForeignVariablesAreStillRefusedWhateverTheDatabaseSetIs guards the one place
// where per-alias database sets could silently switch [refuseForeignConfiguration]
// off. Each of its checks asks "does any alias use the driver that reads this
// variable", and it answers that from the parsed specs — so the refusal depends on
// every declared alias producing at least one spec that carries its engine.
//
// Both directions of that are here. An alias listing several databases must not
// answer the question once per family and lose the engine on the way, and an alias
// listing none at all must still count: an alias that produced no spec would be an
// alias whose driver nothing knows is in play, and the refusal would then quietly
// stop applying to exactly the configuration that made it disappear.
func TestForeignVariablesAreStillRefusedWhateverTheDatabaseSetIs(t *testing.T) {
	for _, tt := range []struct {
		name     string
		engines  map[string]gate.Engine
		bend     func(env map[string]string)
		variable string
		value    string
	}{
		{
			name:     "a PostgreSQL alias listing three databases",
			engines:  map[string]gate.Engine{"pg": gate.PostgreSQL},
			bend:     func(env map[string]string) { env["CERBERUS_DB_PG_DATABASES"] = "one,two,three" },
			variable: "PGSERVICE",
			value:    "cerberus-service-entry",
		},
		{
			name:     "a SQL Server alias listing no databases at all",
			engines:  map[string]gate.Engine{"ms": gate.SQLServer},
			bend:     func(env map[string]string) {},
			variable: epaVariable,
			value:    "true",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := deadPortEnvironment(t, tt.engines)
			tt.bend(env)
			neutraliseForeignVariables(t)
			t.Setenv(tt.variable, tt.value)

			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			cfg, err := LoadConfigFrom(env)
			if err != nil {
				t.Fatalf("LoadConfigFrom: %v", err)
			}
			e, err := New(g, cfg)
			if e != nil {
				t.Cleanup(e.Close)
			}
			if !errors.Is(err, ErrUnsupportedVariable) {
				t.Fatalf("New() = %v, want ErrUnsupportedVariable", err)
			}
			if !strings.Contains(err.Error(), tt.variable) {
				t.Errorf("the error does not name %s: %s", tt.variable, err)
			}
		})
	}
}

// TestPostgresURLAnswersEveryKeyThatWouldReadAFile is the passfile half of the
// same criterion, and it is asserted through pgx rather than by looking for a
// substring: pgx reads a passfile on every ParseConfig — PGPASSFILE's, or ~/.pgpass
// by default — and answers the password from it whenever the connection string
// left one empty. So the connection string is given an empty password on purpose
// here, which is the only state in which the file's answer is observable at all.
func TestPostgresURLAnswersEveryKeyThatWouldReadAFile(t *testing.T) {
	// ParseConfig is reached directly here, so New's refusal is not in the way and
	// an ambient PGSERVICE would make pgx fail on the operator's own service file
	// before this test asserted anything.
	neutraliseForeignVariables(t)

	path := filepath.Join(t.TempDir(), "pgpass")
	if err := os.WriteFile(path, []byte("*:*:*:*:a-password-from-a-file\n"), 0o600); err != nil {
		t.Fatalf("write passfile: %v", err)
	}
	t.Setenv("PGPASSFILE", path)

	spec := pgSpec()
	spec.Password = ""
	cfg, err := pgxpool.ParseConfig(postgresURL(spec))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.ConnConfig.Password != "" {
		t.Errorf("Password = %q, so PGPASSFILE answered a configuration question", cfg.ConnConfig.Password)
	}
}

// TestOpenIsNotAReachabilityCheck pins a deliberate choice: construction must
// not connect. A server that refuses to start while the VPN is down is a server
// that cannot be deployed on the Pi it is meant to run on.
func TestOpenIsNotAReachabilityCheck(t *testing.T) {
	start := time.Now()
	e := executorOnDeadPorts(t)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("construction took %v, so something tried to connect", elapsed)
	}
	if len(e.Aliases()) != 3 {
		t.Fatal("aliases were dropped at construction")
	}
}

// TestCloseIsSafeWhileQueriesAreInFlight is the shutdown case. This executor is
// built to serve concurrent tool calls, so a shutdown overlaps in-flight ones by
// construction — and if Close emptied the registry it would be a concurrent map
// write against every reader, which is a runtime crash rather than a race the
// detector merely reports. The registry is therefore written once in New and
// never again, and this is what says so.
//
// It has to run under -race, which the repository's CI does for every test.
func TestCloseIsSafeWhileQueriesAreInFlight(t *testing.T) {
	e := executorOnDeadPorts(t)
	aliases := []string{pgAlias, "my", "ms"}

	// Enough readers that Close lands in the middle of one. The queries go to
	// dead ports, so each one is a dial that fails rather than a query that
	// finishes, which is what keeps them in flight while Close runs.
	const readers, rounds = 12, 3
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, readers*rounds)
	for i := range readers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			alias := aliases[i%len(aliases)]
			for range rounds {
				_, err := e.Execute(context.Background(), alias, "SELECT 1", nil)
				errs <- err
				// Aliases reads the same two fields Close used to write. t.Errorf
				// rather than t.Fatalf: this is not the test's own goroutine.
				if got := e.Aliases(); len(got) != len(aliases) {
					t.Errorf("Aliases() = %v during shutdown, want %d aliases", got, len(aliases))
				}
			}
		}(i)
	}
	close(start)
	// Close concurrently with the readers, and twice, because a shutdown path that
	// runs after a deferred one is ordinary.
	e.Close()
	e.Close()
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil {
			continue
		}
		var dbErr *Error
		if !errors.As(err, &dbErr) {
			t.Fatalf("Execute() = %v, want a *db.Error", err)
		}
		// A query that arrives after Close reaches a closed pool. Both drivers
		// report that where the transaction is begun, which this package wraps in
		// errNoSession, so the caller is told the database is unavailable rather
		// than being handed something it cannot classify. KindTimeout is the other
		// legitimate answer here: a dial against a dead port can outlive the
		// deadline.
		if dbErr.Kind != KindUnavailable && dbErr.Kind != KindTimeout {
			t.Fatalf("Kind = %q, want unavailable or timeout; detail: %s", dbErr.Kind, dbErr.Detail)
		}
	}

	// And the registry is still readable after Close, which is the property the
	// in-flight calls above depend on.
	if len(e.Aliases()) != len(aliases) {
		t.Errorf("Aliases() = %v after Close, want the registry to be immutable", e.Aliases())
	}
}

// TestDSNAssemblyEscapesAndCarriesTheBounds checks the strings handed to the two
// drivers that take one, against a password full of characters that break naive
// concatenation. It is a unit test because a DSN is never stored anywhere a
// running system could be asked for it.
func TestDSNAssemblyEscapesAndCarriesTheBounds(t *testing.T) {
	spec := AliasSpec{
		Alias:    "a",
		Host:     "db.example",
		Port:     1433,
		Database: "Reporting",
		User:     "svc@corp",
		Password: Secret("p@ss:w/rd?&=#%"),
	}
	s := Settings{QueryTimeout: 9 * time.Second, LockTimeout: 2 * time.Second, ConnectTimeout: 6 * time.Second, RowCap: 10, MaxConns: 2, TimeoutGrace: time.Second}

	t.Run("sql server", func(t *testing.T) {
		for _, tt := range []struct {
			mode TLSMode
			want []string
		}{
			{TLSDefault, []string{"database=Reporting", "dial+timeout=6", "disableretry=true"}},
			{TLSDisable, []string{"encrypt=disable"}},
			{TLSRequire, []string{"encrypt=true"}},
			{TLSRequireInsecure, []string{"encrypt=true", "trustservercertificate=true"}},
		} {
			t.Run(string("mode "+tt.mode), func(t *testing.T) {
				withMode := spec
				withMode.TLS = tt.mode
				dsn := sqlServerDSN(withMode, s)
				for _, want := range tt.want {
					if !strings.Contains(dsn, want) {
						t.Errorf("DSN lacks %q: %s", want, dsn)
					}
				}
				// "connection timeout" must not be there, on any mode. The driver
				// turns it into a per-Read and per-Write socket deadline that lasts
				// the connection's whole life, so on the one engine with no
				// server-side statement bound it would quietly replace QueryTimeout
				// with ConnectTimeout as the statement bound — and the resulting
				// i/o timeout is a net.Error, which classify reports to the agent as
				// an unreachable database rather than as a timeout. Connecting is
				// bounded by "dial timeout" instead. See sqlServerDSN.
				if strings.Contains(dsn, "connection+timeout") || strings.Contains(dsn, "connection%20timeout") {
					t.Errorf("the DSN sets connection timeout, which is a socket deadline for the connection's whole life: %s", dsn)
				}
				// The whole point of building it with net/url: the password
				// survives escaping and can be recovered by a parser.
				assertRoundTrips(t, dsn, withMode)
			})
		}
	})

	t.Run("postgresql", func(t *testing.T) {
		for _, tt := range []struct {
			mode TLSMode
			want string
		}{
			// TLSDefault is spelled out rather than left off: an absent sslmode is
			// one PGSSLMODE gets to answer, and "prefer" is the answer pgx would
			// have given anyway.
			{TLSDefault, "sslmode=prefer"},
			{TLSDisable, "sslmode=disable"},
			{TLSRequire, "sslmode=verify-full"},
			{TLSRequireInsecure, "sslmode=require"},
		} {
			t.Run(string("mode "+tt.mode), func(t *testing.T) {
				withMode := spec
				withMode.TLS = tt.mode
				got := postgresURL(withMode)
				if !strings.Contains(got, tt.want) {
					t.Errorf("URL lacks %q: %s", tt.want, got)
				}
				assertRoundTrips(t, got, withMode)
			})
		}
	})

	t.Run("mysql carries the server-side bounds as session variables", func(t *testing.T) {
		cfg := mysqlConfig(spec, s, boundEnforced)
		if got := cfg.Params["max_execution_time"]; got != "9000" {
			t.Errorf("max_execution_time = %q, want 9000", got)
		}
		if got := cfg.Params["innodb_lock_wait_timeout"]; got != "2" {
			t.Errorf("innodb_lock_wait_timeout = %q, want 2", got)
		}
		if got := cfg.Params["lock_wait_timeout"]; got != "2" {
			t.Errorf("lock_wait_timeout = %q, want 2", got)
		}
		if cfg.MultiStatements {
			t.Error("multiStatements is on, which would let a second statement execute")
		}
		if cfg.Passwd != spec.Password.reveal() {
			t.Error("the password did not survive into the driver config")
		}
		// The only caller that omits the bound is the test that proves the bound
		// is what stops a runaway query.
		if _, ok := mysqlConfig(spec, s, boundOmitted).Params["max_execution_time"]; ok {
			t.Error("boundOmitted still set max_execution_time")
		}
	})

	t.Run("sql server session init carries the lock timeout and read uncommitted", func(t *testing.T) {
		got := sessionInitSQL(s)
		for _, want := range []string{"SET LOCK_TIMEOUT 2000", "READ UNCOMMITTED", "DEADLOCK_PRIORITY LOW"} {
			if !strings.Contains(got, want) {
				t.Errorf("session init lacks %q: %s", want, got)
			}
		}
	})
}

func assertRoundTrips(t *testing.T, dsn string, spec AliasSpec) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("the assembled DSN does not parse: %v", err)
	}
	if got, _ := u.User.Password(); got != spec.Password.reveal() {
		t.Errorf("password round-tripped as %q", got)
	}
	if u.User.Username() != spec.User {
		t.Errorf("user round-tripped as %q", u.User.Username())
	}
}
