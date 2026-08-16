//go:build integration

// The sequence measured in this file runs against a real SQL Server instance that
// exists only behind a VPN, which is why it is named rather than discovered:
// CERBERUS_TEST_SQLSERVER_ALIAS says which configured alias to use, and everything
// here skips when it names nothing. The alias is taken by name and never by
// "whichever sqlserver alias the configuration happened to list first" — more than
// one can be configured at a time and they are different databases, so the wrong
// one would measure a schema nobody asked about.
//
// No identifier from that instance may be written into this repository. Every
// schema, table and column name the sequence uses is read out of the server at run
// time, which is why the search pattern below is not a literal and why the SELECT
// is assembled rather than written out.
//
// SQL Server is deliberately not part of testedEngines(): there is no container for
// it, so nothing here can run in CI and CERBERUS_TEST_REQUIRE_ENGINES does not name
// it.
package mcp

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// sqlServerAliasVar names the configured alias the SQL Server tests run against.
// It is separate from the CERBERUS_DB_* family on purpose: those say what exists,
// and this says which of the things that exist a run may touch.
const sqlServerAliasVar = "CERBERUS_TEST_SQLSERVER_ALIAS"

// TestSQLServerAgentSequenceCostOnTheWire runs the sequence an agent runs, over
// the real transport, and reports what each call cost it.
//
// It is summed by the same sequenceMeter against the same agentSequenceCeiling as
// the fixture-backed TestAgentSequenceCostOnTheWire, which is what makes the two
// figures one measurement taken on two instances rather than two measurements
// that happen to share a name.
//
// The four calls are the sequence and nothing else is counted. The table they run
// over, and the key values the last call's restriction is checked against, come
// from separate reads below made through the executor rather than through a tool,
// because a call made over the transport would be a fifth number in a total that
// is supposed to be the agent's four.
func TestSQLServerAgentSequenceCostOnTheWire(t *testing.T) {
	h, executor := sqlServerHarness(t)
	schema, table := probeTable(t, executor, h.alias)
	meter := &sequenceMeter{t: t}

	databases := meter.measure("list_databases", h.listDatabases(t))
	if names, ok := databases["databases"].([]any); !ok || len(names) == 0 {
		t.Errorf("list_databases returned %s, want the databases this login can see", jsonOf(t, databases["databases"]))
	}
	assertRowBoundIsOnTheWire(t, h, databases, "list_databases")

	// The pattern is the table's own name: the narrowest substring that reaches it,
	// and the one an agent lands on once it knows what it is looking for. A shorter
	// pattern is the heaviest argument form rather than a cheaper one, and this run
	// is not authorised to send it against somebody else's production server.
	search := meter.measure("search_schema", h.searchSchema(t, table))
	searchTables, searchColumns := countSearchSchemaTables(t, search)
	t.Logf("search_schema matched %d tables and %d columns", searchTables, searchColumns)
	if !namesTable(t, search, schema, table) {
		t.Errorf("search_schema did not find the table the pattern was taken from: %s", jsonOf(t, search))
	}
	assertCatalogBoundsAreOnTheWire(t, h, search, "search_schema")

	described := meter.measure("describe_table", h.describeTable(t, table, schema))
	assertCatalogBoundsAreOnTheWire(t, h, described, "describe_table")
	target := oneDescribedTable(t, described, schema, table)

	// Criterion 3: the statement is written from the description that just arrived
	// and from nothing else — no catalog read of its own, no name this file knows.
	sel := selectFromDescription(t, target)
	t.Logf("execute_query statement built from describe_table: %s", sel.statement)
	window := leadingKeyWindow(t, executor, h.alias, sel)
	res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": sel.statement})
	if res.IsError {
		t.Fatalf("the SELECT written from describe_table failed: %s", resultText(t, res))
	}
	query := meter.measure("execute_query", res)
	rows, ok := query["rows"].([]any)
	if !ok || len(rows) == 0 {
		t.Errorf("the SELECT written from describe_table returned no rows: %s", jsonOf(t, query))
	}
	t.Logf("execute_query returned columns %s and %d rows: %s", jsonOf(t, query["columns"]), len(rows), jsonOf(t, query["rows"]))
	assertTheRestrictionExcludedTheMinimum(t, sel, window, rows, query)
	assertRowBoundIsOnTheWire(t, h, query, "execute_query")

	meter.reportAgainstTheCeiling("against the named SQL Server alias at row cap " + strconv.Itoa(h.settings.RowCap))
}

// sqlServerHarness is the whole stack over the one named SQL Server alias, and the
// executor underneath it.
//
// It does not use liveConfig: that takes the first alias of an engine, and taking
// whichever sqlserver alias comes first is exactly the mistake this file must not
// make.
func sqlServerHarness(t *testing.T) (engineHarness, *db.Executor) {
	t.Helper()
	name := strings.TrimSpace(os.Getenv(sqlServerAliasVar))
	if name == "" {
		t.Skipf("%s is unset, so no SQL Server instance is named; set it to a configured sqlserver alias to run this", sqlServerAliasVar)
	}
	neutraliseForeignVariables(t)

	cfg, err := db.LoadConfig()
	if err != nil {
		t.Skipf("no usable CERBERUS_DB_* configuration in the environment (%v); see .env.example", err)
	}
	spec, ok := sqlServerSpec(cfg, name)
	if !ok {
		t.Skipf("%s names %q, which is not a configured sqlserver alias", sqlServerAliasVar, name)
	}

	executor := executorFor(t, &db.Config{Settings: cfg.Settings, Aliases: []db.AliasSpec{spec}}, gate.SQLServer, spec.Alias)
	return engineHarness{
		harness:  connect(t, executor, admittingEveryRequestAs(testIdentity())),
		spec:     spec,
		alias:    spec.Alias,
		settings: cfg.Settings,
	}, executor
}

// sqlServerSpec resolves one configured alias by the name the environment gave.
//
// An alias that lists databases is not exposed under its declared name at all: it
// becomes one alias per database, spelled "<declared>.<database>". So the declared
// spelling has to match that prefix as well, or a correctly named alias looks
// unconfigured and the test skips on a machine where it should have run.
func sqlServerSpec(cfg *db.Config, name string) (db.AliasSpec, bool) {
	for _, spec := range cfg.Aliases {
		if spec.Engine != gate.SQLServer {
			continue
		}
		if spec.Alias == name || strings.HasPrefix(spec.Alias, name+".") {
			return spec, true
		}
	}
	return db.AliasSpec{}, false
}

// probeTable chooses the table the sequence runs over, at run time, because no
// name from this instance may be written into this file.
//
// What it looks for is a table the rest of the sequence can actually use: a
// primary key to restrict on, and at least two rows. Two, not one, because the
// SELECT the sequence writes excludes the rows holding the minimum key — over a
// one-row table that restriction would be correct and would return nothing, so
// "returns rows without error" and "the restriction filtered" could not both be
// claims about the statement. The longest name wins because the search pattern is
// that name — a longer one is less likely to be a substring of some other table's
// name or of a column somewhere else, and a pattern that matches half the schema
// is the heavy argument form this run must not send.
//
// It goes through the executor rather than through execute_query so that the
// measured sequence is the agent's four calls and not five.
func probeTable(t *testing.T, e *db.Executor, alias string) (schema, table string) {
	t.Helper()
	const statement = `SELECT TOP (1) s.name AS table_schema, t.name AS table_name ` +
		`FROM sys.tables AS t ` +
		`JOIN sys.schemas AS s ON s.schema_id = t.schema_id ` +
		`WHERE EXISTS (SELECT 1 FROM sys.indexes AS i WHERE i.object_id = t.object_id AND i.is_primary_key = 1) ` +
		`AND EXISTS (SELECT 1 FROM sys.partitions AS p WHERE p.object_id = t.object_id AND p.index_id IN (0, 1) AND p.rows > 1) ` +
		`ORDER BY LEN(t.name) DESC, t.name`

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := e.Execute(ctx, alias, statement, nil)
	if err != nil {
		t.Fatalf("choosing a table to run the sequence over: %v", err)
	}
	if len(result.Rows) == 0 {
		t.Skipf("no table on alias %q has both a primary key and two rows, so the sequence has nothing to describe, or nothing whose key restriction could both filter and return rows", alias)
	}
	schema, schemaOK := result.Rows[0][0].(string)
	table, tableOK := result.Rows[0][1].(string)
	if !schemaOK || !tableOK {
		t.Fatalf("the catalog answered with %s, want a schema name and a table name", jsonOf(t, result.Rows[0]))
	}
	return schema, table
}

// selectWindow is how many rows the assembled SELECT takes. The unrestricted
// read that the answer is checked against takes one more, so that the row the
// restriction pushes into view is already in hand.
const selectWindow = 5

// selectFromDescription writes the statement acceptance criterion 3 is about: one
// read whose every name came from the describe_table result that preceded it.
//
// Three things make it a real answer rather than a formality. It names columns
// instead of *, so the description is what decided the shape of the result. It
// restricts on the leading column of the described key, so the description is what
// decided the access path too. And the bound of the restriction is read back from
// the table itself, because the description says what the key column is called and
// what type it has but not one value it holds — a literal here would either be
// invented or be a name from this instance written into this file, and it may be
// neither.
//
// The comparison is strict. Against a non-nullable key, ">= MIN(key)" is a
// tautology: it admits every row, and what would bound the answer is the TOP, not
// the predicate — so the run would show the key column is projectable and
// orderable while showing nothing about restricting on it. "> MIN(key)" excludes
// the rows holding the minimum by construction, which is what
// [assertTheRestrictionExcludedTheMinimum] then holds the answer to.
func selectFromDescription(t *testing.T, table map[string]any) describedSelect {
	t.Helper()
	qualified := bracketed(t, stringField(t, table, "schema")) + "." + bracketed(t, stringField(t, table, "table"))

	restrictOn := leadingKeyColumn(t, table)
	if restrictOn == "" {
		t.Fatalf("the description carries neither a primary key nor an index, so there is no key column to restrict on: %s", jsonOf(t, table))
	}

	names := selectableColumns(t, table, restrictOn)
	if len(names) < 2 {
		t.Fatalf("the description lists too few columns to write a non-degenerate SELECT: %s", jsonOf(t, table["columns"]))
	}
	projected := make([]string, 0, len(names))
	for _, name := range names {
		projected = append(projected, bracketed(t, name))
	}
	key := bracketed(t, restrictOn)

	return describedSelect{
		statement: "SELECT TOP (" + strconv.Itoa(selectWindow) + ") " + strings.Join(projected, ", ") +
			" FROM " + qualified +
			" WHERE " + key + " > (SELECT MIN(" + key + ") FROM " + qualified + ")" +
			" ORDER BY " + key,
		qualified: qualified,
		key:       key,
		keyColumn: restrictOn,
	}
}

// leadingKeyWindow reads the head of the key column in the order the assembled
// SELECT orders by, so the restricted answer has something to be held against.
//
// It reads one row more than that SELECT takes, because that extra row is what
// the restriction pulls into the window when it drops the minimum-key rows. Like
// [probeTable] it goes through the executor rather than through execute_query, so
// the measured sequence stays the agent's four calls.
//
// These are values, not schema: both names in the statement came out of the
// description that already crossed the wire, and nothing here asks the catalog
// anything.
func leadingKeyWindow(t *testing.T, e *db.Executor, alias string, sel describedSelect) []any {
	t.Helper()
	statement := "SELECT TOP (" + strconv.Itoa(selectWindow+1) + ") " + sel.key +
		" FROM " + sel.qualified + " ORDER BY " + sel.key

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := e.Execute(ctx, alias, statement, nil)
	if err != nil {
		t.Fatalf("reading the key values the restriction is checked against: %v", err)
	}
	window := make([]any, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 1 {
			t.Fatalf("the key read answered with %s, want one value per row", jsonOf(t, row))
		}
		window = append(window, row[0])
	}
	// The probe asked the catalog for a table with two rows, and the catalog's row
	// count is maintained rather than counted. This is the same question asked of
	// the data, and it is asked before the call so that a table which cannot show
	// the restriction working skips rather than reporting the criterion failed.
	if len(window) < 2 {
		t.Skipf("the chosen table holds %d row(s), and the restriction excludes the minimum-key row, so it cannot both filter and return rows here", len(window))
	}
	return window
}

// assertTheRestrictionExcludedTheMinimum is what makes criterion 3 a claim about
// restricting rather than about projecting and ordering: rows the predicate
// covers are missing from the answer, and the run says which ones.
//
// It checks two things against the same key values read straight from the table.
// The minimum-key rows are absent — that is the exclusion. And what came back is
// the rest of the window, in order — that is what stops the first check passing on
// a technicality, since two values that could never compare equal because they
// crossed the wire in different shapes would fail this one instead of silently
// satisfying that one.
func assertTheRestrictionExcludedTheMinimum(t *testing.T, sel describedSelect, window, rows []any, query map[string]any) {
	t.Helper()
	at := keyColumnIndex(t, query, sel.keyColumn)

	minimum := jsonOf(t, window[0])
	excluded := 0
	for _, value := range window {
		if jsonOf(t, value) != minimum {
			break
		}
		excluded++
	}
	if excluded == len(window) {
		t.Skipf("every one of the %d rows at the head of the key carries the same value, so a bounded read cannot show what the restriction left behind", len(window))
	}
	t.Logf("the restriction excludes %d of the %d rows at the head of the key, beginning at %s", excluded, len(window), minimum)

	for i, raw := range rows {
		row, ok := raw.([]any)
		if !ok || at >= len(row) {
			t.Fatalf("row %d is %s, want a value for every column the result names", i, jsonOf(t, raw))
		}
		got := jsonOf(t, row[at])
		if got == minimum {
			t.Errorf("row %d still carries the minimum key %s, so restricting on %q excluded nothing", i, minimum, sel.keyColumn)
			continue
		}
		if want := excluded + i; want < len(window) {
			if wanted := jsonOf(t, window[want]); got != wanted {
				t.Errorf("row %d has key %s, want %s: the answer is not the head of the table with the minimum-key rows dropped, so either the restriction did something else or the table changed under the run", i, got, wanted)
			}
		}
	}
}

// selectableColumns picks the projection: the key column first, then described
// columns of types whose values a JSON result renders as themselves.
//
// The type filter is not squeamishness about large values — it is what keeps this
// test measuring the sequence rather than the driver's handling of whatever
// spatial, XML or binary column a third party's table happens to begin with. When
// no column passes it, the description's own order is taken instead, because a
// SELECT that names real columns is still the criterion and a skipped test is not.
func selectableColumns(t *testing.T, table map[string]any, key string) []string {
	t.Helper()
	// Types whose SQL Server values arrive over this stack as a JSON number or
	// string, so a row of them reads as the table's own data in the run's output.
	plainTypes := map[string]bool{
		"bigint": true, "int": true, "smallint": true, "tinyint": true, "bit": true,
		"decimal": true, "numeric": true, "money": true, "smallmoney": true,
		"float": true, "real": true,
		"char": true, "varchar": true, "nchar": true, "nvarchar": true,
		"date": true, "datetime": true, "datetime2": true, "smalldatetime": true,
		"uniqueidentifier": true,
	}

	columns, ok := table["columns"].([]any)
	if !ok {
		t.Fatalf("the description carries no columns array: %s", jsonOf(t, table))
	}
	var plain, described []string
	for _, raw := range columns {
		column, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a described column is %s, want an object", jsonOf(t, raw))
		}
		name, _ := column["name"].(string)
		if name == "" || name == key {
			continue
		}
		described = append(described, name)
		if dataType, _ := column["data_type"].(string); plainTypes[strings.ToLower(dataType)] {
			plain = append(plain, name)
		}
	}
	rest := plain
	if len(rest) == 0 {
		rest = described
	}
	if len(rest) > 2 {
		rest = rest[:2]
	}
	return append([]string{key}, rest...)
}

// bracketed quotes one identifier for T-SQL.
//
// A name containing a bracket is refused rather than escaped: the gate's lexer
// reads a bracketed identifier up to the first ']' and does not recognise the ']]'
// doubling that SQL Server accepts, so an escaped name would be a statement the
// gate and the server read differently. Nothing in this repository needs such a
// name to work, and a clear failure here beats a statement whose validation and
// execution disagree.
func bracketed(t *testing.T, name string) string {
	t.Helper()
	if name == "" {
		t.Fatal("an empty identifier cannot be quoted")
	}
	if strings.ContainsAny(name, "[]") {
		t.Fatalf("the identifier %q contains a bracket, which this test does not quote", name)
	}
	return "[" + name + "]"
}
