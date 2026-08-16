//go:build integration

// The SQL Server catalog surface, graded against a real instance.
//
// It is a file of its own because the engine has no fixture: there is no arm64
// image, no container in deploy/compose.test.yaml and therefore no schema whose
// contents anything here may assume. What is asserted is consequently shape and
// not content — that the four catalog statements parse and run, that their rows
// decode, that grouping and ordering hold, and that a bound which cut an answer
// says which one — with every name the assertions need discovered at runtime
// from the instance the run is pointed at. Nothing in this file names a schema,
// a table or a column of the server it runs against, and nothing may: the
// instance belongs to a third party.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// The variable that names the alias these tests run against. Its value is the
// alias as declared in CERBERUS_DB_ALIASES, not as spelled in the variable
// family: a hyphen there becomes an underscore in the variable name and stays a
// hyphen in the alias.
//
// The alias is chosen by name rather than taken from whichever alias setUp finds
// first, because more than one sqlserver alias is normally configured and a
// catalog assertion made against whichever one came first alphabetically would
// be an assertion about a server nobody chose.
//
// There is deliberately no default. The instance this surface has been graded
// against belongs to a third party, and its alias is an identifier of theirs
// like any other — so it lives in an operator's environment and in no file here.
// Unset, these tests skip, and they skip even where a sqlserver alias is
// declared: leaving this variable unset is an operator saying "not that server
// today", which is an opt-out and not an engine that failed to answer.
const sqlServerCatalogAliasVar = "CERBERUS_TEST_SQLSERVER_ALIAS"

// msCatalogHarness is setUp for one named alias. Its reachability and
// configuration conditions are setUp's own, in the same order and for the same
// reasons: no configuration, no alias of this engine by that name, or a
// configured alias behind a VPN that is down.
func msCatalogHarness(t *testing.T) harness {
	t.Helper()
	required := engineIsRequired(t, gate.SQLServer)
	neutraliseForeignVariables(t)
	cfg, err := LoadConfig()
	if err != nil {
		skipOrFail(t, required, gate.SQLServer, fmt.Sprintf("no usable CERBERUS_DB_* configuration in the environment (%v); see .env.example", err))
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

	configured := e.engineAliases(gate.SQLServer)
	want := os.Getenv(sqlServerCatalogAliasVar)
	if want == "" {
		// t.Skipf and not skipOrFail, whose rule is "the environment declares this
		// engine and the run graded nothing against it because the server did not
		// answer". No server has been asked anything at this point, and the operator
		// who left this variable unset chose not to ask one.
		t.Skipf("%s is unset, so no server has been chosen for these tests; set it to one of the sqlserver aliases declared in CERBERUS_DB_ALIASES (configured: %v)", sqlServerCatalogAliasVar, configured)
	}
	alias := ""
	for _, name := range configured {
		// A declared alias with one database in CERBERUS_DB_<ALIAS>_DATABASES is
		// exposed as "<alias>.<database>", so the configured name is a prefix of the
		// alias an executor knows rather than the alias itself.
		if name == want || strings.HasPrefix(name, want+derivedAliasSeparator) {
			alias = name
			break
		}
	}
	if alias == "" {
		skipOrFail(t, required, gate.SQLServer, fmt.Sprintf("%s names %q, and no sqlserver alias is declared with that name; configured: %v", sqlServerCatalogAliasVar, want, configured))
	}
	c, _ := e.connFor(alias)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := e.Execute(ctx, alias, "SELECT 1", nil); err != nil {
		if errors.Is(err, ErrUnavailable) {
			skipOrFail(t, required, gate.SQLServer, fmt.Sprintf("alias %q is configured but not reachable: %v", alias, err))
		}
		t.Fatalf("the sqlserver alias %q rejected SELECT 1: %v", alias, err)
	}
	// Recorded here for the same reason setUp records it: the named alias never
	// goes through setUp, so a run that graded this instance and skipped every
	// other engine would otherwise be failed by TestMain as having graded nothing.
	noteEngineAnswered(gate.SQLServer)
	return harness{Executor: e, alias: alias, spec: c.spec()}
}

// msTarget is one table this run discovered on the instance. It is passed around
// rather than written down anywhere, which is the whole point.
type msTarget struct {
	schema string
	table  string
}

func (t msTarget) String() string { return t.schema + "." + t.table }

// msLiteral renders a discovered name as a T-SQL string literal, for the probe
// statements that cross-check what the shipped statements return.
//
// The shipped statements bind every name as a driver parameter and this does not
// contradict that: [Executor.Execute] is the agent's path and takes no
// parameters, so a probe that has to restrict on a name it learned at runtime
// has nowhere else to put it. The value always comes from the server's own
// catalog, never from a test input.
func msLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func msRows(t *testing.T, h harness, statement string) [][]any {
	t.Helper()
	res, err := h.Execute(context.Background(), h.alias, statement, nil)
	if err != nil {
		t.Fatalf("probe %q = %v", statement, err)
	}
	return res.Rows
}

func msText(t *testing.T, value any) string {
	t.Helper()
	text, ok := schemaText(value)
	if !ok {
		t.Fatalf("catalog value %#v is not text", value)
	}
	return text
}

// msDiscoverTarget picks the table the describe assertions are made against: one
// with a primary key and at least one secondary index, so that every part of the
// answer has something to be graded on. It falls back twice, because an instance
// that has neither still has to be able to grade the column half.
//
// Among the candidates it takes the one with the longest name, for the same
// reason msLongestColumn does. The table's own name becomes a search pattern
// below, and the first candidate in alphabetical order is as likely as not to be
// a short word that is a substring of a tenth of the catalog — which is the read
// this wave is required not to send.
func msDiscoverTarget(t *testing.T, h harness) msTarget {
	t.Helper()
	for _, probe := range []struct {
		what      string
		statement string
	}{
		// A multi-column key first, because key_ordinal ordering is only graded by a
		// key that has more than one column: over a single-column key every possible
		// ordering agrees.
		{"a multi-column key, a primary key and a secondary index", "SELECT TOP 1 s.name, t.name FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.key_constraints AS k ON k.parent_object_id = t.object_id AND k.type = 'PK' JOIN sys.indexes AS i ON i.object_id = t.object_id AND i.is_primary_key = 0 AND i.index_id > 0 JOIN sys.index_columns AS ic ON ic.object_id = t.object_id AND ic.key_ordinal > 1 ORDER BY LEN(t.name) DESC, s.name, t.name"},
		{"a primary key and a secondary index", "SELECT TOP 1 s.name, t.name FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.key_constraints AS k ON k.parent_object_id = t.object_id AND k.type = 'PK' JOIN sys.indexes AS i ON i.object_id = t.object_id AND i.is_primary_key = 0 AND i.index_id > 0 ORDER BY LEN(t.name) DESC, s.name, t.name"},
		{"a primary key", "SELECT TOP 1 s.name, t.name FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.key_constraints AS k ON k.parent_object_id = t.object_id AND k.type = 'PK' ORDER BY LEN(t.name) DESC, s.name, t.name"},
		{"any table at all", "SELECT TOP 1 s.name, t.name FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id ORDER BY LEN(t.name) DESC, s.name, t.name"},
	} {
		rows := msRows(t, h, probe.statement)
		if len(rows) == 1 && len(rows[0]) == 2 {
			target := msTarget{schema: msText(t, rows[0][0]), table: msText(t, rows[0][1])}
			t.Logf("describe target: the longest-named table with %s", probe.what)
			return target
		}
	}
	t.Skip("this login sees no table in sys.tables, so there is nothing to describe")
	return msTarget{}
}

// msLongestColumn is the target's longest column name, which is the narrowest
// column-name pattern this run can be sure matches something. A short one — an
// id, a timestamp — is exactly the pattern that matches a large fraction of a
// several-hundred-table catalog, which this wave must not send.
func msLongestColumn(t *testing.T, h harness, target msTarget) string {
	t.Helper()
	rows := msRows(t, h, "SELECT TOP 1 c.name FROM sys.columns AS c JOIN sys.tables AS t ON t.object_id = c.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE t.name = "+msLiteral(target.table)+" AND s.name = "+msLiteral(target.schema)+" ORDER BY LEN(c.name) DESC, c.name")
	if len(rows) != 1 || len(rows[0]) != 1 {
		t.Fatalf("no column of %s is visible to this login", target)
	}
	return msText(t, rows[0][0])
}

// TestSQLServerCatalogViewsThisLoginCanRead establishes, view by view, whether
// the login the alias is configured with can read each catalog view the shipped
// statements touch — and where it cannot, which [Kind] the refusal surfaced as.
//
// The distinction the log draws is the one that matters on this engine: sys.*
// filters by metadata visibility rather than refusing, so a login with no rights
// on an object sees an empty result instead of error 229. "Readable" and
// "readable but empty" are therefore different answers, and only the third —
// an actual error — carries a Kind at all.
//
// An error that classifies as [KindInternal] fails the run rather than being
// logged. That is the shape error 916 takes, which classifySQLServer does not
// map, and an opaque internal error on a catalog read is the finding this test
// exists to surface rather than to pass over.
func TestSQLServerCatalogViewsThisLoginCanRead(t *testing.T) {
	h := msCatalogHarness(t)
	for _, view := range []struct {
		name      string
		statement string
	}{
		{"sys.databases", "SELECT TOP 1 name FROM sys.databases"},
		{"sys.schemas", "SELECT TOP 1 name FROM sys.schemas"},
		{"sys.tables", "SELECT TOP 1 name FROM sys.tables"},
		{"sys.columns", "SELECT TOP 1 name FROM sys.columns"},
		{"sys.types", "SELECT TOP 1 name FROM sys.types"},
		{"sys.key_constraints", "SELECT TOP 1 name FROM sys.key_constraints"},
		// Both of these are read by object_id rather than by name: a heap's row in
		// sys.indexes carries a NULL name, so name would decode as absent for a
		// reason that has nothing to do with permission.
		{"sys.indexes", "SELECT TOP 1 object_id FROM sys.indexes"},
		{"sys.index_columns", "SELECT TOP 1 object_id FROM sys.index_columns"},
	} {
		t.Run(view.name, func(t *testing.T) {
			started := time.Now()
			res, err := h.Execute(context.Background(), h.alias, view.statement, nil)
			elapsed := time.Since(started)
			if err == nil {
				if len(res.Rows) == 0 {
					t.Logf("%s: readable, and empty for this login — metadata visibility, not a refusal (%v)", view.name, elapsed)
					return
				}
				t.Logf("%s: readable, %d row in %v", view.name, len(res.Rows), elapsed)
				return
			}
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("%s: got %v, want a *db.Error", view.name, err)
			}
			if dbErr.Kind == KindInternal {
				t.Errorf("%s: unreadable and unclassified — Kind %q, detail %q. An agent is told nothing it can act on", view.name, dbErr.Kind, dbErr.Detail)
				return
			}
			t.Errorf("%s: unreadable, Kind %q (detail: %s)", view.name, dbErr.Kind, dbErr.Detail)
		})
	}
}

// TestSQLServerCatalogBooleansDecode grades the one dialect decision these
// statements rest on, in isolation from the catalog: T-SQL has no boolean value,
// so both match reasons are CASE WHEN … THEN 1 ELSE 0 END, and the integer that
// produces has to survive this driver and schemaBool. If it does not, every row
// of a search silently fails the decode and the answer is empty rather than
// wrong — which is the failure mode a shape assertion over the catalog alone
// cannot tell from a pattern that matched nothing.
func TestSQLServerCatalogBooleansDecode(t *testing.T) {
	h := msCatalogHarness(t)
	rows := msRows(t, h, "SELECT CASE WHEN 1 = 1 THEN 1 ELSE 0 END AS matched, CASE WHEN 1 = 0 THEN 1 ELSE 0 END AS unmatched, CONVERT(bit, 1) AS bit_true, CONVERT(bit, 0) AS bit_false")
	if len(rows) != 1 || len(rows[0]) != 4 {
		t.Fatalf("the CASE probe returned %#v, want one four-column row", rows)
	}
	for i, want := range []bool{true, false, true, false} {
		got, ok := schemaBool(rows[0][i])
		if !ok || got != want {
			t.Errorf("schemaBool(%#v) = %v, %v; want %v, true", rows[0][i], got, ok, want)
		}
	}
}

// TestSQLServerSearchSchemaOverTheRealCatalog is the first execution of
// sqlServerSchemaSearch anywhere.
//
// Every pattern it sends is derived from a name the instance itself returned, so
// nothing here guesses at a substring that might match a large fraction of a
// several-hundred-table catalog: a whole table name matches that table, and the
// target's longest column name is the least common column pattern this run can
// be sure of.
func TestSQLServerSearchSchemaOverTheRealCatalog(t *testing.T) {
	h := msCatalogHarness(t)
	target := msDiscoverTarget(t, h)
	ctx := context.Background()

	byName, err := h.SearchSchema(ctx, h.alias, target.table)
	if err != nil {
		t.Fatalf("SearchSchema by table name = %v", err)
	}
	t.Logf("search by a whole table name: %d tables, %d columns, truncation %q, %d bytes assembled, %v",
		len(byName.Tables), schemaColumnCount(byName.Tables), byName.Truncation, schemaJSONSize(t, byName.Tables), byName.Elapsed)

	if byName.Decision.Verdict != gate.Allow {
		t.Errorf("the answer carries verdict %q: the shipped statement no longer passes the gate", byName.Decision.Verdict)
	}
	if byName.Alias != h.alias || byName.Engine != gate.SQLServer {
		t.Errorf("the answer does not identify what produced it: %+v", byName)
	}
	if byName.Elapsed <= 0 {
		t.Error("the answer reports no elapsed time")
	}
	// The target's presence is what says the whole row decoded: schemaTables drops
	// any row whose schema, table or either match reason it cannot read, so a
	// statement that ran but whose 1/0 did not decode would answer with no tables
	// at all rather than with wrong ones.
	if !slices.Contains(schemaTableIDs(byName.Tables), target.String()) && byName.Truncation == NoTruncation {
		t.Errorf("a complete search for a table's own name returned %v, which does not include %s", schemaTableIDs(byName.Tables), target)
	}
	assertMSSearchInvariants(t, h, byName)

	upper, err := h.SearchSchema(ctx, h.alias, strings.ToUpper(target.table))
	if err != nil {
		t.Fatalf("SearchSchema with the pattern upper-cased = %v", err)
	}
	// The statement lowers both the pattern and the name it compares against, so
	// the answer must not depend on how the caller cased its pattern — including on
	// an instance whose collation would otherwise make it depend on exactly that.
	if !slices.Equal(schemaTableIDs(byName.Tables), schemaTableIDs(upper.Tables)) {
		t.Errorf("case changed the answer: %v then %v", schemaTableIDs(byName.Tables), schemaTableIDs(upper.Tables))
	}

	column := msLongestColumn(t, h, target)
	byColumn, err := h.SearchSchema(ctx, h.alias, column)
	if err != nil {
		t.Fatalf("SearchSchema by column name = %v", err)
	}
	t.Logf("search by a %d-character column name: %d tables, %d columns, truncation %q, %d bytes assembled, %v",
		len(column), len(byColumn.Tables), schemaColumnCount(byColumn.Tables), byColumn.Truncation, schemaJSONSize(t, byColumn.Tables), byColumn.Elapsed)
	assertMSSearchInvariants(t, h, byColumn)
	if schemaColumnCount(byColumn.Tables) == 0 && byColumn.Truncation == NoTruncation {
		t.Errorf("a complete search for a column this login can see returned %d tables and no columns: the column half of the statement matched nothing", len(byColumn.Tables))
	}

	t.Run("the row cap cuts the catalog read and the answer names it", func(t *testing.T) {
		// One row: the smallest read that still reaches the server, and the cheapest
		// way to establish on this instance that the cap is applied here and reported
		// as the cause. The byte budget cannot be provoked this way — it is spent on
		// the assembled answer, so only a pattern matching much more of the catalog
		// reaches it, and that form is deferred to an explicit approval.
		defer func(previous int) { h.settings.RowCap = previous }(h.Settings().RowCap)
		h.settings.RowCap = 1
		capped, err := h.SearchSchema(ctx, h.alias, target.table)
		if err != nil {
			t.Fatalf("SearchSchema under a row cap of 1 = %v", err)
		}
		if capped.Truncation != RowCapTruncation || capped.RowCap != 1 {
			t.Errorf("truncation = %q at row cap %d, want %q at 1", capped.Truncation, capped.RowCap, RowCapTruncation)
		}
		if capped.ByteBudget != SchemaResultBudget {
			t.Errorf("byte budget reported as %d, want %d", capped.ByteBudget, SchemaResultBudget)
		}
	})
}

func assertMSSearchInvariants(t *testing.T, h harness, result *SchemaSearch) {
	t.Helper()
	assertMSCatalogOrder(t, result.Tables)
	assertOnlyTheLastTableCanBeMarked(t, result.Tables)
	if result.RowCap != h.Settings().RowCap {
		t.Errorf("the answer reports row cap %d, want the configured %d", result.RowCap, h.Settings().RowCap)
	}
	if result.ByteBudget != SchemaResultBudget {
		t.Errorf("the answer reports byte budget %d, want %d", result.ByteBudget, SchemaResultBudget)
	}
	if cost := schemaBudgetCost(result.Tables); cost > result.ByteBudget {
		t.Errorf("the answer charges %d bytes against a %d-byte budget", cost, result.ByteBudget)
	}
	switch result.Truncation {
	case NoTruncation, RowCapTruncation, ByteBudgetTruncation:
	default:
		t.Errorf("truncation = %q, which names no bound", result.Truncation)
	}
	for _, table := range result.Tables {
		if table.Schema == "" || table.Table == "" {
			t.Errorf("an entry came back unnamed: %#v", table)
		}
		if table.Columns == nil {
			t.Errorf("%s.%s carries a nil column list, which serialises as null rather than as an empty list", table.Schema, table.Table)
		}
		for _, c := range table.Columns {
			if c.Name == "" || c.DataType == "" {
				t.Errorf("%s.%s returned an incomplete column %#v", table.Schema, table.Table, c)
			}
		}
	}
}

// assertMSCatalogOrder is assertSchemaOrder for a server whose collation this run
// did not choose.
//
// The three statements ORDER BY the server's collation and this package preserves
// the order it gets; asserting Go's byte order over the result therefore grades
// the collation and not the statement. Under a case-insensitive collation, which
// is SQL Server's default, a lower-case name can precede a capitalised one on the
// server and follow it in Go — an ordering the fixture tests never see, because
// every name in the fixture is lower case. What is asserted here is the claim
// that survives any collation: the answer is ordered by schema, then table, then
// column, compared case-folded.
func assertMSCatalogOrder(t *testing.T, tables []SchemaTable) {
	t.Helper()
	before := func(a, b string) bool { return strings.ToLower(a) > strings.ToLower(b) }
	for i := 1; i < len(tables); i++ {
		previous, current := tables[i-1], tables[i]
		if before(previous.Schema, current.Schema) || (strings.EqualFold(previous.Schema, current.Schema) && before(previous.Table, current.Table)) {
			t.Errorf("tables are not in schema/table order: %s.%s then %s.%s", previous.Schema, previous.Table, current.Schema, current.Table)
		}
	}
	for _, table := range tables {
		for i := 1; i < len(table.Columns); i++ {
			if before(table.Columns[i-1].Name, table.Columns[i].Name) {
				t.Errorf("columns of one table are not in name order: %s then %s", table.Columns[i-1].Name, table.Columns[i].Name)
			}
		}
	}
}

// TestSQLServerDescribeTableQualifiedBySchema is the first execution of the
// three describe statements, on a table discovered at runtime and always
// qualified by its schema.
//
// Qualified is the only form this wave sends. The unqualified one returns an
// entry per schema holding a table of that name, which is the argument form that
// produces the most entries — the one ADR 01M04ECKDDYSJMJW3288YQ2XXS says the
// ceiling must be measured against, and the one that runs only after the narrow
// figures below have been seen and approved.
//
// Ordering and grouping are graded against an independent read of the same
// catalog, deliberately ordered by name rather than by key ordinal: comparing
// the shipped statement's output to itself would agree with any ordering it
// happened to produce.
func TestSQLServerDescribeTableQualifiedBySchema(t *testing.T) {
	h := msCatalogHarness(t)
	target := msDiscoverTarget(t, h)
	ctx := context.Background()

	result, err := h.DescribeTable(ctx, h.alias, target.table, target.schema)
	if err != nil {
		t.Fatalf("DescribeTable(%s) = %v", target, err)
	}
	t.Logf("describe of one schema-qualified table: %d entries, %d columns, %d key columns, %d indexes, truncation %q, %d bytes assembled, %d bytes charged, %v",
		len(result.Tables), msColumnCount(result.Tables), msKeyCount(result.Tables), msIndexCount(result.Tables),
		result.Truncation, schemaJSONSize(t, result.Tables), describeResultCharge(result.Tables), result.Elapsed)

	if len(result.Tables) != 1 {
		t.Fatalf("a schema-qualified describe returned %d entries, want exactly one", len(result.Tables))
	}
	table := result.Tables[0]
	if table.Schema != target.schema || table.Table != target.table {
		t.Fatalf("describe answered about %s.%s, not about the table it was asked for", table.Schema, table.Table)
	}
	if result.ByteBudget != describeResultBudget || result.RowCap != h.Settings().RowCap {
		t.Errorf("the answer reports budget %d and row cap %d, want %d and %d", result.ByteBudget, result.RowCap, describeResultBudget, h.Settings().RowCap)
	}
	if charge := describeResultCharge(result.Tables); charge > result.ByteBudget {
		t.Errorf("the answer charges %d bytes against a %d-byte budget", charge, result.ByteBudget)
	}
	for _, c := range table.Columns {
		if c.Name == "" || c.DataType == "" {
			t.Errorf("column %#v came back without a name or a type, so a SELECT cannot be written from it", c)
		}
	}

	// Every column of the catalog is present unless a bound cut the answer. This
	// is what grades the nullability decode across the whole table rather than on
	// one column: describeTables drops a row whose is_nullable it cannot read, so a
	// BIT this driver returned in an unexpected shape would show up here as a short
	// column list and nowhere else.
	visible := msCount(t, h, "SELECT COUNT(*) FROM sys.columns AS c JOIN sys.tables AS t ON t.object_id = c.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE t.name = "+msLiteral(target.table)+" AND s.name = "+msLiteral(target.schema))
	switch {
	case result.Truncation == NoTruncation && int64(len(table.Columns)) != visible:
		t.Errorf("a complete describe returned %d of the %d columns this login can see", len(table.Columns), visible)
	case result.Truncation != NoTruncation && int64(len(table.Columns)) > visible:
		t.Errorf("describe returned %d columns, more than the %d the catalog holds", len(table.Columns), visible)
	case result.Truncation != NoTruncation && !table.ColumnsTruncated:
		t.Errorf("the answer reports truncation %q and no entry says its column list was cut", result.Truncation)
	}

	if want := msPrimaryKeyByOrdinal(t, h, target); !slices.Equal(table.PrimaryKey, want) {
		t.Errorf("primary key = %v, want %v in key-ordinal order", table.PrimaryKey, want)
	} else if len(want) > 0 {
		t.Logf("primary key: %d column(s), composite=%v", len(want), len(want) > 1)
	}

	// Indexes are compared by name rather than position. The shipped statement
	// orders them with the server's own collation, which this run does not know and
	// must not assume matches Go's byte order — while the two claims that are the
	// product's own are position-independent: each index appears exactly once
	// (grouping), and its columns are in key-ordinal order.
	want := msIndexesByOrdinal(t, h, target)
	seen := map[string]int{}
	for _, got := range table.Indexes {
		seen[got.Name]++
		if seen[got.Name] > 1 {
			t.Errorf("index %q has %d entries: rows for one index were not grouped into one", got.Name, seen[got.Name])
		}
	}
	if len(table.Indexes) != len(want) {
		t.Fatalf("describe returned %d indexes, want %d", len(table.Indexes), len(want))
	}
	multiColumn := 0
	for _, index := range table.Indexes {
		if len(index.Columns) > 1 {
			multiColumn++
		}
	}
	// Said out loud because it decides what this run established: a single-column
	// key agrees with every possible ordering, so key-ordinal order is graded only
	// where a key has more than one column.
	t.Logf("key-ordinal ordering is graded by %d of %d indexes and by the %d-column primary key", multiColumn, len(table.Indexes), len(table.PrimaryKey))

	for _, got := range table.Indexes {
		at := slices.IndexFunc(want, func(candidate TableIndex) bool { return candidate.Name == got.Name })
		if at < 0 {
			t.Errorf("describe returned index %q, which the catalog does not report for this table", got.Name)
			continue
		}
		if got.Unique != want[at].Unique || !slices.Equal(got.Columns, want[at].Columns) {
			t.Errorf("index %q = %#v, want columns %v in key-ordinal order and unique=%v", got.Name, got, want[at].Columns, want[at].Unique)
		}
	}
}

// msPrimaryKeyByOrdinal reads the target's primary key with an ordering the
// shipped statement does not use, and puts it in key-ordinal order here. What
// comes back is therefore an expectation and not an echo.
func msPrimaryKeyByOrdinal(t *testing.T, h harness, target msTarget) []string {
	t.Helper()
	rows := msRows(t, h, "SELECT ic.key_ordinal, c.name FROM sys.key_constraints AS k JOIN sys.tables AS t ON t.object_id = k.parent_object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.index_columns AS ic ON ic.object_id = t.object_id AND ic.index_id = k.unique_index_id JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = ic.column_id WHERE k.type = 'PK' AND ic.key_ordinal > 0 AND t.name = "+msLiteral(target.table)+" AND s.name = "+msLiteral(target.schema)+" ORDER BY c.name")
	type keyColumn struct {
		ordinal int64
		name    string
	}
	out := make([]keyColumn, 0, len(rows))
	for _, row := range rows {
		ordinal, ok := asInt64(row[0])
		if !ok {
			t.Fatalf("key_ordinal came back as %#v, which is not an integer", row[0])
		}
		out = append(out, keyColumn{ordinal: ordinal, name: msText(t, row[1])})
	}
	slices.SortFunc(out, func(a, b keyColumn) int { return int(a.ordinal - b.ordinal) })
	names := make([]string, 0, len(out))
	for _, c := range out {
		names = append(names, c.name)
	}
	return names
}

// msIndexesByOrdinal is msPrimaryKeyByOrdinal for the secondary indexes: read in
// an order the shipped statement does not produce, then grouped and ordered here.
func msIndexesByOrdinal(t *testing.T, h harness, target msTarget) []TableIndex {
	t.Helper()
	rows := msRows(t, h, "SELECT i.name, ic.key_ordinal, c.name, i.is_unique FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = ic.column_id WHERE i.is_primary_key = 0 AND ic.key_ordinal > 0 AND t.name = "+msLiteral(target.table)+" AND s.name = "+msLiteral(target.schema)+" ORDER BY c.name, i.name")
	type indexColumn struct {
		ordinal int64
		name    string
	}
	columns := map[string][]indexColumn{}
	unique := map[string]bool{}
	var names []string
	for _, row := range rows {
		name := msText(t, row[0])
		ordinal, ok := asInt64(row[1])
		if !ok {
			t.Fatalf("key_ordinal came back as %#v, which is not an integer", row[1])
		}
		isUnique, ok := schemaBool(row[3])
		if !ok {
			t.Fatalf("is_unique came back as %#v, which schemaBool cannot read", row[3])
		}
		if _, seen := columns[name]; !seen {
			names = append(names, name)
			unique[name] = isUnique
		}
		columns[name] = append(columns[name], indexColumn{ordinal: ordinal, name: msText(t, row[2])})
	}
	slices.Sort(names)
	out := make([]TableIndex, 0, len(names))
	for _, name := range names {
		entry := columns[name]
		slices.SortFunc(entry, func(a, b indexColumn) int { return int(a.ordinal - b.ordinal) })
		index := TableIndex{Name: name, Columns: make([]string, 0, len(entry)), Unique: unique[name]}
		for _, c := range entry {
			index.Columns = append(index.Columns, c.name)
		}
		out = append(out, index)
	}
	return out
}

func msCount(t *testing.T, h harness, statement string) int64 {
	t.Helper()
	rows := msRows(t, h, statement)
	if len(rows) != 1 || len(rows[0]) != 1 {
		t.Fatalf("counting probe %q returned %#v, want one value", statement, rows)
	}
	n, ok := asInt64(rows[0][0])
	if !ok {
		t.Fatalf("counting probe %q returned %#v, which is not an integer", statement, rows[0][0])
	}
	return n
}

func msColumnCount(tables []TableDescription) int {
	n := 0
	for _, table := range tables {
		n += len(table.Columns)
	}
	return n
}

func msKeyCount(tables []TableDescription) int {
	n := 0
	for _, table := range tables {
		n += len(table.PrimaryKey)
	}
	return n
}

func msIndexCount(tables []TableDescription) int {
	n := 0
	for _, table := range tables {
		n += len(table.Indexes)
	}
	return n
}

// TestSQLServerCatalogSurfaceRunsUnderTheSameBounds is acceptance criterion 5 for
// the catalog statements specifically: they are not a side path with bounds of
// their own, they run under the ones every other statement runs under.
//
// The transaction half is observed on a pinned session, because that is the only
// place it can be: the mitigations are session-scoped and a #temp table exists
// only on the session that created it. The real search statement runs inside that
// transaction with a bound pattern, so what is graded is the transaction the
// catalog surface actually uses.
func TestSQLServerCatalogSurfaceRunsUnderTheSameBounds(t *testing.T) {
	h := msCatalogHarness(t)
	c, _ := h.connFor(h.alias)
	ms := c.(*msConn)
	target := msDiscoverTarget(t, h)
	pattern, ok := schemaPattern(target.table)
	if !ok {
		t.Fatalf("the discovered table name is too short to be a search pattern")
	}
	ctx := context.Background()

	t.Run("the session carries its mitigations while the catalog statement runs", func(t *testing.T) {
		conn, err := ms.pool.Conn(ctx)
		if err != nil {
			t.Fatalf("pin a connection: %v", err)
		}
		defer func() { _ = conn.Close() }()

		err = ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, sqlServerSchemaSearch, pattern)
			if err != nil {
				return err
			}
			if err := rows.Close(); err != nil {
				return err
			}
			var lockTimeout, isolation int
			if err := tx.QueryRowContext(ctx, "SELECT @@LOCK_TIMEOUT").Scan(&lockTimeout); err != nil {
				return err
			}
			if want := int(milliseconds(h.Settings().LockTimeout)); lockTimeout != want {
				t.Errorf("@@LOCK_TIMEOUT during the catalog read = %d, want %d (-1 is the default, wait forever)", lockTimeout, want)
			}
			if err := tx.QueryRowContext(ctx,
				"SELECT transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID").Scan(&isolation); err != nil {
				// A login without VIEW SERVER STATE still sees its own session row,
				// so this failing is worth reporting rather than skipping past.
				return err
			}
			if isolation != 1 {
				t.Errorf("transaction_isolation_level during the catalog read = %d, want 1 (READ UNCOMMITTED)", isolation)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("the catalog statement inside a pinned transaction = %v", err)
		}
	})

	for _, tt := range []struct {
		name string
		run  func(tx *sql.Tx) error
	}{
		{"success", func(tx *sql.Tx) error { return nil }},
		{"an engine error after the read", func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "SELECT * FROM cerberus_no_such_table")
			if err == nil {
				t.Fatal("the deliberately broken statement succeeded")
			}
			return err
		}},
	} {
		t.Run("the transaction around a catalog read is rolled back on "+tt.name, func(t *testing.T) {
			conn, err := ms.pool.Conn(ctx)
			if err != nil {
				t.Fatalf("pin a connection: %v", err)
			}
			defer func() { _ = conn.Close() }()

			// A read leaves nothing behind to look for, so the transaction carries a
			// marker of its own. #temp is what makes that safe against a third party's
			// server: it belongs to this session and dies with it.
			err = ms.withTxOn(ctx, conn, txReadOnly, func(tx *sql.Tx) error {
				rows, err := tx.QueryContext(ctx, sqlServerSchemaSearch, pattern)
				if err != nil {
					return err
				}
				if err := rows.Close(); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, "SELECT 1 AS marker INTO #cerberus_catalog_probe"); err != nil {
					return err
				}
				// The control, read from inside the transaction that made it: without
				// it, "the marker is gone afterwards" is also what a SELECT INTO that
				// never worked looks like.
				var inside int64
				if err := tx.QueryRowContext(ctx, "SELECT ISNULL(OBJECT_ID('tempdb..#cerberus_catalog_probe'), 0)").Scan(&inside); err != nil {
					return err
				}
				if inside == 0 {
					t.Error("the marker does not exist inside the transaction, so its absence afterwards establishes nothing")
				}
				return tt.run(tx)
			})
			if tt.name == "success" && err != nil {
				t.Fatalf("the successful path returned %v", err)
			}

			if id := msTempObjectID(t, ctx, conn, "#cerberus_catalog_probe"); id != 0 {
				t.Errorf("the marker survived the %s path: the transaction around the catalog read was not rolled back", tt.name)
			}
			var trancount int
			if err := conn.QueryRowContext(ctx, "SELECT @@TRANCOUNT").Scan(&trancount); err != nil {
				t.Fatalf("read @@TRANCOUNT after the %s path: %v", tt.name, err)
			}
			if trancount != 0 {
				t.Errorf("@@TRANCOUNT = %d after the %s path, want 0", trancount, tt.name)
			}
		})
	}

	t.Run("the configured query deadline bounds a catalog call", func(t *testing.T) {
		// The deadline is lowered rather than the statement made slow. On this engine
		// the context deadline is the whole time bound — there is no server-side
		// statement bound to lean on — and provoking it with a slow read would mean
		// running a slow read against somebody else's production server.
		defer func(previous time.Duration) { h.settings.QueryTimeout = previous }(h.Settings().QueryTimeout)
		h.settings.QueryTimeout = time.Millisecond
		_, err := h.SearchSchema(ctx, h.alias, target.table)
		var dbErr *Error
		if !errors.As(err, &dbErr) {
			t.Fatalf("SearchSchema under a 1ms deadline = %v, want a *db.Error", err)
		}
		if dbErr.Kind != KindTimeout {
			t.Errorf("Kind = %q, want %q (detail: %s)", dbErr.Kind, KindTimeout, dbErr.Detail)
		}
		assertAgentSideIsClean(t, dbErr, h.spec)
	})
}

// TestSQLServerInstanceFacts reports what this run establishes about the
// instance. Every figure it prints is a fact about one third-party server, which
// is why it is printed and not asserted: there is nothing here a second instance
// would reproduce.
//
// The database is reported first because a catalog read against the wrong one
// returns a small, clean and entirely misleading answer — sys.tables is
// current-database only, so an alias bound to a database other than the one whose
// schema matters looks exactly like a schema with very few tables.
func TestSQLServerInstanceFacts(t *testing.T) {
	h := msCatalogHarness(t)
	rows := msRows(t, h, "SELECT DB_NAME() AS current_database, d.collation_name, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS product_version, CONVERT(nvarchar(128), SERVERPROPERTY('Collation')) AS server_collation FROM sys.databases AS d WHERE d.database_id = DB_ID()")
	if len(rows) != 1 {
		t.Fatalf("the instance probe returned %d rows, want one", len(rows))
	}
	t.Logf("current database %q, database collation %v, server version %v, server collation %v", rows[0][0], rows[0][1], rows[0][2], rows[0][3])
	if configured := h.spec.Database; configured != "" && msText(t, rows[0][0]) != configured {
		t.Errorf("the connection is reading database %v while the alias is configured for %q", rows[0][0], configured)
	}

	t.Logf("tables visible to this login: %d", msCount(t, h, "SELECT COUNT(*) FROM sys.tables"))
	t.Logf("columns visible to this login: %d", msCount(t, h, "SELECT COUNT(*) FROM sys.columns AS c JOIN sys.tables AS t ON t.object_id = c.object_id"))
	for _, row := range msRows(t, h, "SELECT s.name, COUNT(*) AS tables FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id GROUP BY s.name ORDER BY s.name") {
		t.Logf("schema %v holds %v tables", row[0], row[1])
	}
}
