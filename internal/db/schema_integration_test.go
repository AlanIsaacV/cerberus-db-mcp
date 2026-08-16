//go:build integration

package db

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// TestSearchSchemaBindsAndFoldsCase establishes both properties at the driver
// boundary: the same fixed statement answers differently for different bound
// values, and casing that value differently does not change the answer.
func TestSearchSchemaBindsAndFoldsCase(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			h.settings.RowCap = 300

			archive, err := h.SearchSchema(context.Background(), h.alias, "archive")
			if err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}
			beacon, err := h.SearchSchema(context.Background(), h.alias, "beacon")
			if err != nil {
				t.Fatalf("SearchSchema(beacon) = %v", err)
			}
			if slices.Equal(schemaTableIDs(archive.Tables), schemaTableIDs(beacon.Tables)) {
				t.Fatalf("different bound patterns returned the same tables: %v", schemaTableIDs(archive.Tables))
			}

			upper, err := h.SearchSchema(context.Background(), h.alias, "ARCHIVE")
			if err != nil {
				t.Fatalf("SearchSchema(ARCHIVE) = %v", err)
			}
			if !slices.Equal(schemaTableIDs(archive.Tables), schemaTableIDs(upper.Tables)) {
				t.Errorf("case changed matching tables: lower = %v, upper = %v", schemaTableIDs(archive.Tables), schemaTableIDs(upper.Tables))
			}
			assertSchemaOrder(t, archive.Tables)
			assertSchemaOrder(t, upper.Tables)
		})
	}
}

func TestSearchSchemaRejectsShortPatterns(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			for _, pattern := range []string{"", "a", " "} {
				_, err := h.SearchSchema(context.Background(), h.alias, pattern)
				var dbErr *Error
				if !errors.As(err, &dbErr) || dbErr.Kind != KindInvalidArgument {
					t.Errorf("SearchSchema(%q) = %v, want an invalid-argument error", pattern, err)
				}
			}
		})
	}
}

// TestSearchSchemaGroupsOnlyMatchingColumns is acceptance criterion 6: one entry
// per matching table, carrying only the columns that matched, and an empty list
// where the table name alone matched.
//
// Every expectation below is derived from the fixture's checked-in declaration and
// then trimmed by [schemaWithinBudget], because two of these three searches now
// overrun [SchemaResultBudget] — the 250-column measure search always, and the
// title search on PostgreSQL, where one matching column in each of 100 tables costs
// more than the budget allows. What the derivation buys is that the expectation
// still names which columns of which tables, in order, rather than degrading into
// "some prefix".
func TestSearchSchemaGroupsOnlyMatchingColumns(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			database := fixtureDatabase
			if engine == gate.MySQL {
				database = fixtureSecondDatabase
			}
			h := schemaFixtureHarness(t, engine, database)
			h.settings.RowCap = 300

			byTableName, err := h.SearchSchema(context.Background(), h.alias, "archive")
			if err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}
			assertSchemaTableIDs(t, byTableName.Tables, schemaArchiveTableIDs(engine, database))
			for _, table := range byTableName.Tables {
				if table.Columns == nil || len(table.Columns) != 0 {
					t.Errorf("name-matched %s.%s columns = %#v, want an empty non-nil list", table.Schema, table.Table, table.Columns)
				}
				// The empty list is criterion 6's claim only while the entry says it is
				// whole; the same two fields with the marker set would mean the budget cut
				// this table's columns off, which is the ambiguity the marker removes.
				if table.ColumnsTruncated {
					t.Errorf("name-matched %s.%s reports a cut column list under a %d-byte budget it never approached", table.Schema, table.Table, byTableName.ByteBudget)
				}
			}
			if byTableName.Truncation != NoTruncation {
				t.Errorf("a two-table name match reports truncation %q under a %d-byte budget and a row cap of %d, want %q", byTableName.Truncation, byTableName.ByteBudget, byTableName.RowCap, NoTruncation)
			}

			byColumn, err := h.SearchSchema(context.Background(), h.alias, "title")
			if err != nil {
				t.Fatalf("SearchSchema(title) = %v", err)
			}
			wantColumn, columnTruncated := schemaWithinBudget(schemaFixtureMatches(engine, database, "title"))
			// The expectation covers the 256-column archive as well, whose entry must
			// carry its one matching column and no other.
			assertSchemaTables(t, byColumn.Tables, wantColumn)
			wantColumnTruncation := NoTruncation
			if columnTruncated {
				wantColumnTruncation = ByteBudgetTruncation
			}
			if byColumn.Truncation != wantColumnTruncation {
				t.Errorf("SearchSchema(title) truncation = %q over %d tables, want %q", byColumn.Truncation, len(byColumn.Tables), wantColumnTruncation)
			}

			byMeasure, err := h.SearchSchema(context.Background(), h.alias, "measure")
			if err != nil {
				t.Fatalf("SearchSchema(measure) = %v", err)
			}
			wantMeasure, measureTruncated := schemaWithinBudget(schemaFixtureMatches(engine, database, "measure"))
			if !measureTruncated {
				t.Fatal("the 250-column measure search no longer overruns the budget, so this case has stopped grading the truncation it was written for")
			}
			// The budget stops inside the wide table rather than at its boundary, so the
			// entry survives with part of its column list and declares it. Dropping the
			// entry instead would answer this search — 250 matching columns of one table —
			// with no tables at all, and leaving it unmarked would make its columns read
			// as the complete set.
			assertSchemaTables(t, byMeasure.Tables, wantMeasure)
			if last := len(byMeasure.Tables) - 1; last < 0 || !byMeasure.Tables[last].ColumnsTruncated {
				t.Errorf("SearchSchema(measure) returned %d of 250 columns and no entry saying its column list was cut: %v",
					schemaColumnCount(byMeasure.Tables), schemaTableIDs(byMeasure.Tables))
			}
			if byMeasure.Truncation != ByteBudgetTruncation {
				t.Errorf("SearchSchema(measure) truncation = %q after returning %d of 250 columns, want %q", byMeasure.Truncation, schemaColumnCount(byMeasure.Tables), ByteBudgetTruncation)
			}
			assertSchemaOrder(t, byColumn.Tables)
			assertSchemaOrder(t, byMeasure.Tables)
			assertOnlyTheLastTableCanBeMarked(t, byColumn.Tables)
			assertOnlyTheLastTableCanBeMarked(t, byMeasure.Tables)
		})
	}
}

func TestSearchSchemaDoesNotCrossMySQLDatabases(t *testing.T) {
	h := schemaFixtureHarness(t, gate.MySQL, fixtureDatabase)
	h.settings.RowCap = 300
	ledgerExecutor := executorForEnvironment(t, aliasEnvironment("mytest", h.spec, fixtureSecondDatabase))
	const ledgerAlias = "mytest.ledger"
	ledger, err := ledgerExecutor.SearchSchema(context.Background(), ledgerAlias, "title")
	if err != nil {
		t.Fatalf("SearchSchema(%s, title) = %v", ledgerAlias, err)
	}
	wantTitle, _ := schemaWithinBudget(schemaFixtureMatches(gate.MySQL, fixtureSecondDatabase, "title"))
	assertSchemaTables(t, ledger.Tables, wantTitle)
	wide, err := ledgerExecutor.SearchSchema(context.Background(), ledgerAlias, "measure")
	if err != nil {
		t.Fatalf("SearchSchema(%s, measure) = %v", ledgerAlias, err)
	}
	// The measure search is stopped by the byte budget partway through the wide
	// table's 250 columns; what this test is about is that those columns are
	// ledger's and are reachable only through an alias bound to ledger.
	wantMeasure, _ := schemaWithinBudget(schemaFixtureMatches(gate.MySQL, fixtureSecondDatabase, "measure"))
	assertSchemaTables(t, wide.Tables, wantMeasure)

	result, err := h.SearchSchema(context.Background(), h.alias, "measure")
	if err != nil {
		t.Fatalf("SearchSchema(measure) = %v", err)
	}
	if len(result.Tables) != 0 {
		t.Fatalf("testbed search returned %v; measure columns exist only in reachable ledger", schemaTableIDs(result.Tables))
	}
}

// TestSearchSchemaUsesConfiguredSessionBounds establishes the part that a
// catalog query cannot safely provoke: SearchSchema takes the same ordinary
// deadline path as Execute (unit-tested below), and the connection it uses has
// the server-side query and lock bounds in force. A fixture catalog query is too
// small to turn deliberately into a timeout without changing its fixed SQL.
func TestSearchSchemaUsesConfiguredSessionBounds(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			if _, err := h.SearchSchema(context.Background(), h.alias, "archive"); err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}

			switch engine {
			case gate.PostgreSQL:
				// The settings are read with current_setting rather than with
				// SHOW because the gate's read-show rule is scoped to MySQL, and
				// this surface's rule is that the statement changes while the
				// ruleset never does. current_setting is on the safe-function
				// allowlist and reports the same text SHOW would.
				//
				// Each value is compared to this alias's own configured bound, the
				// way the MySQL branch below does. "not empty and not 0" would stay
				// green if the mapping at internal/db/postgres.go's RuntimeParams
				// broke and left the server's own default in force, which is the one
				// failure this half exists to catch.
				for _, tt := range []struct {
					statement string
					want      string
				}{
					{"SELECT current_setting('statement_timeout')", postgresDurationSetting(h.Settings().QueryTimeout)},
					{"SELECT current_setting('lock_timeout')", postgresDurationSetting(h.Settings().LockTimeout)},
				} {
					result, err := h.Execute(context.Background(), h.alias, tt.statement, nil)
					if err != nil {
						t.Fatalf("Execute(%q) = %v", tt.statement, err)
					}
					if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
						t.Fatalf("Execute(%q) rows = %#v, want one setting", tt.statement, result.Rows)
					}
					if value := fixtureCatalogValue(result.Rows[0][0]); value != tt.want {
						t.Errorf("%s = %q, want %q: the schema-search session does not carry this alias's configured bound", tt.statement, value, tt.want)
					}
				}
			case gate.MySQL:
				result, err := h.Execute(context.Background(), h.alias,
					"SELECT @@max_execution_time AS met, @@innodb_lock_wait_timeout AS ilwt, @@lock_wait_timeout AS lwt", nil)
				if err != nil {
					t.Fatalf("read MySQL session bounds: %v", err)
				}
				if len(result.Rows) != 1 || len(result.Rows[0]) != len(result.Columns) {
					t.Fatalf("MySQL session bounds = %#v with columns %v, want one complete row", result.Rows, result.Columns)
				}
				got := map[string]any{}
				for i, name := range result.Columns {
					got[name] = result.Rows[0][i]
				}
				for _, tt := range []struct {
					variable string
					column   string
					want     int64
				}{
					{"@@max_execution_time", "met", milliseconds(h.Settings().QueryTimeout)},
					{"@@innodb_lock_wait_timeout", "ilwt", seconds(h.Settings().LockTimeout)},
					{"@@lock_wait_timeout", "lwt", seconds(h.Settings().LockTimeout)},
				} {
					value, ok := asInt64(got[tt.column])
					if !ok || value != tt.want {
						t.Errorf("%s = %#v, want %d", tt.variable, got[tt.column], tt.want)
					}
				}
			}
		})
	}
}

func TestSearchSchemaReportsTruncation(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			h.settings.RowCap = 2
			result, err := h.SearchSchema(context.Background(), h.alias, "archive")
			if err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}
			if result.Truncation != RowCapTruncation || result.RowCap != 2 {
				t.Errorf("SearchSchema(archive) truncation = %q at row cap %d, want %q at 2", result.Truncation, result.RowCap, RowCapTruncation)
			}
			// The row cap can leave a name-matched table with no matching columns and
			// no byte-budget marker, which is exactly the ambiguity the named cause
			// closes.
			if len(result.Tables) != 1 || len(result.Tables[0].Columns) != 0 || result.Tables[0].ColumnsTruncated {
				t.Errorf("SearchSchema(archive) tables = %#v, want a row-cap-cut name match with no byte-budget marker", result.Tables)
			}
			if result.ByteBudget != SchemaResultBudget {
				t.Errorf("SearchSchema(archive) reports byte budget %d, want %d", result.ByteBudget, SchemaResultBudget)
			}
		})
	}
}

// TestSearchSchemaSharedColumnPatternCannotReturnTheCatalog is acceptance
// criterion 4's absolute half — no value of pattern returns the whole catalog —
// against the case that broke it. Every fixture table carries recorded_at, so the
// legal two-character pattern "re" matches a column in every one of them: nothing
// is near the row cap, every table qualifies, and before [SchemaResultBudget]
// existed the answer was the catalog reached from the column side.
//
// It runs at the bounds this package ships with rather than the deliberately small
// ones a test run configures, and says so if the cap could not deliver every
// matching row: a cap that stopped the read first would hide the hole this grades
// behind a truncation that means something else.
func TestSearchSchemaSharedColumnPatternCannotReturnTheCatalog(t *testing.T) {
	const pattern = "re"
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			database := fixtureDatabase
			if engine == gate.MySQL {
				// ledger, because MySQL's 256-column archive is there and PostgreSQL's
				// is in testbed: the shared column matches in every table either way,
				// and the wide table is what makes the overrun unmissable.
				database = fixtureSecondDatabase
			}
			h := schemaShippedBoundsHarness(t, engine, database)
			if rows := schemaFixtureMatchedRows(engine, database, pattern); h.Settings().RowCap < rows {
				t.Fatalf("the shipped row cap of %d cannot deliver the %d catalog rows %q matches, so this would grade the cap and not the byte budget", h.Settings().RowCap, rows, pattern)
			}

			result, err := h.SearchSchema(context.Background(), h.alias, pattern)
			if err != nil {
				t.Fatalf("SearchSchema(%q) = %v", pattern, err)
			}
			if result.Truncation != ByteBudgetTruncation {
				t.Errorf("SearchSchema(%q) truncation = %q after returning %d tables and %d columns, want %q", pattern, result.Truncation, len(result.Tables), schemaColumnCount(result.Tables), ByteBudgetTruncation)
			}
			if result.ByteBudget != SchemaResultBudget {
				t.Errorf("SearchSchema(%q) reports byte budget %d, want %d", pattern, result.ByteBudget, SchemaResultBudget)
			}

			want, truncated := schemaWithinBudget(schemaFixtureMatches(engine, database, pattern))
			if !truncated {
				t.Fatalf("%q no longer overruns the budget over this fixture, so this test has stopped grading criterion 4's hole", pattern)
			}
			assertSchemaTables(t, result.Tables, want)
			assertSchemaOrder(t, result.Tables)
			assertOnlyTheLastTableCanBeMarked(t, result.Tables)

			// The three properties the budget is spent to keep true.
			every := schemaFixtureTableIDs(engine, database)
			if len(result.Tables) >= len(every) {
				t.Errorf("SearchSchema(%q) returned %d of this database's %d tables: a pattern the tool accepts returns the catalog", pattern, len(result.Tables), len(every))
			}
			for _, table := range result.Tables {
				// No table name contains this pattern, so every entry here matched by a
				// column of its own and an empty list would mean the budget dropped one.
				// Unmarked, that entry would be indistinguishable from a name match.
				if len(table.Columns) == 0 && !table.ColumnsTruncated {
					t.Errorf("%s.%s came back with no columns, which is the shape that means the table name matched; the budget dropped its columns instead", table.Schema, table.Table)
				}
				if len(table.Columns) == 0 && table.ColumnsTruncated {
					t.Errorf("%s.%s was opened by the budget with no room for the column that matched in it, which the charging rule is supposed to prevent for a column-only match", table.Schema, table.Table)
				}
			}
			if cost := schemaBudgetCost(result.Tables); cost > SchemaResultBudget {
				t.Errorf("the answer spends %d bytes of the %d-byte budget", cost, SchemaResultBudget)
			}
			t.Logf("%q over %d fixture tables: %d tables, %d columns, %d bytes of budget, %d bytes assembled",
				pattern, len(every), len(result.Tables), schemaColumnCount(result.Tables), schemaBudgetCost(result.Tables), schemaJSONSize(t, result))
		})
	}
}

// TestSearchSchemaAssembledTablesStayWithinTheBudget is a cheap guard that what
// this package assembles is no larger than the budget it charged itself for. It is
// deliberately NOT acceptance criterion 9's measurement: an agent never receives
// this value. internal/mcp maps it into its own field names and the SDK emits it
// both as structured content and as a duplicate JSON text block, so the wire form
// is roughly twice what is measured here — which is why criterion 9's 4 KB and
// 20 KB bounds are graded in internal/mcp/mcp_integration_test.go, over this same
// fixture, on the form the agent actually gets.
//
// What it does establish is the accounting in internal/db/schema.go: the per-entry
// costs there over-estimate the JSON they stand for, so a result that spent its
// whole budget must still serialise to less than the budget. If that ever inverts,
// the ceiling internal/mcp asserts is being derived from a number that no longer
// bounds anything.
func TestSearchSchemaAssembledTablesStayWithinTheBudget(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			database := fixtureDatabase
			if engine == gate.MySQL {
				database = fixtureSecondDatabase
			}
			h := schemaFixtureHarness(t, engine, database)
			// The configured test-suite cap is deliberately low. Raise it only for
			// this measurement, so that what stops the worst case is the byte budget
			// rather than a cap no deployment runs.
			h.settings.RowCap = 300

			one, err := h.SearchSchema(context.Background(), h.alias, "archive")
			if err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}
			assertSchemaTableIDs(t, one.Tables, schemaArchiveTableIDs(engine, database))
			oneSize := schemaJSONSize(t, one.Tables)
			// A proportionality guard on the call this surface exists for, not
			// criterion 9's 4 KB: a search naming one table costs a couple of hundred
			// bytes here, and anything approaching a kilobyte means an entry grew a
			// field nobody accounted for.
			if oneSize >= 1024 {
				t.Errorf("a table-name search assembles %d bytes of tables for %d entries, want well under 1024", oneSize, len(one.Tables))
			}

			worst, err := h.SearchSchema(context.Background(), h.alias, "measure")
			if err != nil {
				t.Fatalf("SearchSchema(measure) = %v", err)
			}
			if worst.Truncation != ByteBudgetTruncation {
				t.Fatalf("the 250-column measure search truncation = %q, want %q so this remains the byte-budget worst case", worst.Truncation, ByteBudgetTruncation)
			}
			worstSize := schemaJSONSize(t, worst.Tables)
			t.Logf("worst assembled schema-search result on %s: %d bytes of tables (%d with the execution facts) for %d tables and %d matching columns, against a %d-byte budget it charged %d bytes to",
				engine, worstSize, schemaJSONSize(t, worst), len(worst.Tables), schemaColumnCount(worst.Tables), worst.ByteBudget, schemaBudgetCost(worst.Tables))
			if worstSize > SchemaResultBudget {
				t.Errorf("a result the budget stopped assembles to %d bytes of tables, more than the %d-byte budget that stopped it", worstSize, SchemaResultBudget)
			}
		})
	}
}

func TestSearchSchemaExcludesPostgreSQLSystemSchemas(t *testing.T) {
	h := schemaFixtureHarness(t, gate.PostgreSQL, fixtureDatabase)
	result, err := h.SearchSchema(context.Background(), h.alias, "stat")
	if err != nil {
		t.Fatalf("SearchSchema(stat) = %v", err)
	}
	for _, table := range result.Tables {
		if table.Schema == "pg_catalog" || table.Schema == "information_schema" {
			t.Errorf("SearchSchema(stat) returned system table %s.%s", table.Schema, table.Table)
		}
	}
}

// schemaFixtureHarness selects an alias bound to one fixture database. MySQL's
// second database needs a derived executor because CI intentionally configures
// only testbed; recreating the alias through the normal configuration path keeps
// the test about connection scope, rather than giving the query extra reach.
func schemaFixtureHarness(t *testing.T, engine gate.Engine, database string) harness {
	t.Helper()
	if engine == gate.PostgreSQL {
		if database != fixtureDatabase {
			t.Fatalf("the PostgreSQL fixture has no schema-search database %q", database)
		}
		return wideFixtureHarness(t, engine)
	}

	h := setUp(t, engine)
	if h.spec.Database == database {
		return h
	}
	if engine != gate.MySQL || database != fixtureSecondDatabase {
		t.Fatalf("configured %s alias %q is bound to %q, want fixture database %q", engine, h.alias, h.spec.Database, database)
	}
	e := executorForEnvironment(t, aliasEnvironment("schemafixture", h.spec, database))
	for _, alias := range e.engineAliases(engine) {
		c, _ := e.connFor(alias)
		if c.spec().Database == database {
			return harness{Executor: e, alias: alias, spec: c.spec()}
		}
	}
	t.Fatalf("no %s alias is bound to fixture database %q", engine, database)
	return harness{}
}

// schemaShippedBoundsHarness reaches the same fixture database over a connection
// declared with no setting variable at all, so the bounds that apply are the ones
// this package ships with rather than the small ones a test run configures.
//
// A test about the byte budget needs that. The budget is only what stops an answer
// once the row cap is large enough to deliver every matching row; under CI's cap of
// 50 a shared-column pattern is stopped by the cap long before, and a result that
// is truncated for the wrong reason grades nothing.
func schemaShippedBoundsHarness(t *testing.T, engine gate.Engine, database string) harness {
	t.Helper()
	base := schemaFixtureHarness(t, engine, database)
	e := executorForEnvironment(t, aliasEnvironment("schemabudget", base.spec, database))
	for _, alias := range e.engineAliases(engine) {
		c, _ := e.connFor(alias)
		if c.spec().Database == database {
			return harness{Executor: e, alias: alias, spec: c.spec()}
		}
	}
	t.Fatalf("no %s alias is bound to fixture database %q", engine, database)
	return harness{}
}

// schemaFixtureMatches is the answer a search for pattern would return over the
// wide fixture if no bound applied: the fixture's checked-in declaration, filtered
// the way the three catalog statements filter it and ordered the way they order it.
//
// Deriving the expectation from the declaration rather than from the result is what
// lets a truncated case still be graded exactly — which columns of which tables, in
// which order — instead of degrading into an assertion about a count.
func schemaFixtureMatches(engine gate.Engine, database, pattern string) []SchemaTable {
	pattern = strings.ToLower(pattern)
	out := make([]SchemaTable, 0)
	for _, table := range wideFixtureTables(engine) {
		// On MySQL a schema is a database and a search never leaves the one the alias
		// is bound to; on PostgreSQL both fixture schemas live in fixtureDatabase.
		if engine == gate.MySQL && table.schema != database {
			continue
		}
		matched := make([]SchemaColumn, 0)
		for _, column := range table.columns {
			if strings.Contains(strings.ToLower(column.name), pattern) {
				matched = append(matched, SchemaColumn{Name: column.name, DataType: column.dataType, Nullable: column.nullable})
			}
		}
		if len(matched) == 0 && !strings.Contains(strings.ToLower(table.name), pattern) {
			continue
		}
		slices.SortFunc(matched, func(a, b SchemaColumn) int { return strings.Compare(a.Name, b.Name) })
		out = append(out, SchemaTable{Schema: table.schema, Table: table.name, Columns: matched})
	}
	slices.SortStableFunc(out, func(a, b SchemaTable) int {
		if a.Schema != b.Schema {
			return strings.Compare(a.Schema, b.Schema)
		}
		return strings.Compare(a.Table, b.Table)
	})
	return out
}

// schemaFixtureMatchedRows is how many flat catalog rows a pattern produces before
// grouping: every column of a table whose name matched, and the matching columns of
// the rest. It is what a test compares the row cap against when it needs the byte
// budget, and not the cap, to be what stopped the answer.
func schemaFixtureMatchedRows(engine gate.Engine, database, pattern string) int {
	pattern = strings.ToLower(pattern)
	rows := 0
	for _, table := range wideFixtureTables(engine) {
		if engine == gate.MySQL && table.schema != database {
			continue
		}
		if strings.Contains(strings.ToLower(table.name), pattern) {
			rows += len(table.columns)
			continue
		}
		for _, column := range table.columns {
			if strings.Contains(strings.ToLower(column.name), pattern) {
				rows++
			}
		}
	}
	return rows
}

// schemaWithinBudget trims an unbounded expectation the way schemaTables spends
// [SchemaResultBudget] over it, using that function's own per-entry costs so an
// expectation follows the budget rather than restating a column count a changed
// budget would silently invalidate.
//
// It models the two shapes these searches produce: a table matched by name alone,
// charged on its own, and a table's matching columns, the first of which is charged
// together with the entry that holds it — which is why a table never appears here
// with an empty column list unless that is what it means. A table matched by name
// *and* by column would open its entry on whichever of its columns the catalog
// returns first; no pattern these tests use does both at once, so that ordering is
// not modelled.
//
// ColumnsTruncated is derived from where the cut fell rather than from the product's
// rule for setting it: an entry that had already been emitted when the budget ran out
// is holding part of its column list and says so, and an entry that never opened is
// simply absent, so nothing before it is marked. An expectation built the other way
// round — by copying whichever entry schemaTables happened to mark — would agree with
// any implementation, including one that marked every entry or none.
func schemaWithinBudget(want []SchemaTable) ([]SchemaTable, bool) {
	out := make([]SchemaTable, 0, len(want))
	spent := 0
	for _, table := range want {
		entry := schemaTableBytes + len(table.Schema) + len(table.Table)
		if len(table.Columns) == 0 {
			if spent+entry > SchemaResultBudget {
				return out, true
			}
			spent += entry
			out = append(out, SchemaTable{Schema: table.Schema, Table: table.Table, Columns: make([]SchemaColumn, 0)})
			continue
		}
		for i, column := range table.Columns {
			cost := schemaColumnBytes + len(column.Name) + len(column.DataType)
			if i == 0 {
				cost += entry
			}
			if spent+cost > SchemaResultBudget {
				if i > 0 {
					out[len(out)-1].ColumnsTruncated = true
				}
				return out, true
			}
			spent += cost
			if i == 0 {
				out = append(out, SchemaTable{Schema: table.Schema, Table: table.Table, Columns: make([]SchemaColumn, 0, len(table.Columns))})
			}
			last := len(out) - 1
			out[last].Columns = append(out[last].Columns, column)
		}
	}
	return out, false
}

// schemaBudgetCost is what a returned result charged against the budget, computed
// with the package's own per-entry constants.
func schemaBudgetCost(tables []SchemaTable) int {
	cost := 0
	for _, table := range tables {
		cost += schemaTableBytes + len(table.Schema) + len(table.Table)
		for _, column := range table.Columns {
			cost += schemaColumnBytes + len(column.Name) + len(column.DataType)
		}
	}
	return cost
}

// postgresDurationSetting renders a duration the way current_setting reports one of
// PostgreSQL's millisecond-unit parameters back.
//
// internal/db/postgres.go puts statement_timeout and lock_timeout into the startup
// packet as a plain integer count of milliseconds, and the server prints such a
// value in the largest unit that divides it exactly (guc.c's
// convert_int_from_base_unit): 4000 comes back as "4s", 4500 as "4500ms".
func postgresDurationSetting(d time.Duration) string {
	ms := milliseconds(d)
	for _, unit := range []struct {
		suffix string
		size   int64
	}{
		{"d", 24 * 60 * 60 * 1000},
		{"h", 60 * 60 * 1000},
		{"min", 60 * 1000},
		{"s", 1000},
	} {
		if ms%unit.size == 0 {
			return strconv.FormatInt(ms/unit.size, 10) + unit.suffix
		}
	}
	return strconv.FormatInt(ms, 10) + "ms"
}

func schemaTableIDs(tables []SchemaTable) []string {
	out := make([]string, len(tables))
	for i, table := range tables {
		out[i] = table.Schema + "." + table.Table
	}
	return out
}

func schemaFixtureTableIDs(engine gate.Engine, database string) []string {
	var schemas []string
	switch engine {
	case gate.PostgreSQL:
		schemas = []string{"atelier", "harbor"}
	case gate.MySQL:
		schemas = []string{database}
	default:
		return nil
	}

	// SearchSchema returns rows ordered by schema then table name, and
	// assertSchemaTableIDs compares position by position, so both loops have to
	// run in that order. wideFixtureTableNames is in the fixture's thematic
	// order, which is not name order, and it is copied rather than sorted in
	// place because wideFixtureTables derives each table's shape from a name's
	// ordinal in it.
	slices.Sort(schemas)
	names := slices.Clone(wideFixtureTableNames)
	slices.Sort(names)

	out := make([]string, 0, len(schemas)*len(names))
	for _, schema := range schemas {
		for _, table := range names {
			out = append(out, schema+"."+table)
		}
	}
	return out
}

// schemaArchiveTableIDs is written already in the schema-then-table order the
// comparison needs; a schema added here has to keep it that way.
func schemaArchiveTableIDs(engine gate.Engine, database string) []string {
	if engine == gate.PostgreSQL {
		return []string{"atelier.archive", "harbor.archive"}
	}
	return []string{database + ".archive"}
}

// assertSchemaTables compares a result against a whole expected answer: the same
// tables in the same order, each carrying the same columns with the same types and
// nullability, and each saying the same thing about whether that column list is all
// of them. It replaces the per-table lookups this file used before the byte budget
// existed, which could only name one table at a time and had no way to say where a
// truncated answer should stop.
func assertSchemaTables(t *testing.T, got, want []SchemaTable) {
	t.Helper()
	assertSchemaTableIDs(t, got, schemaTableIDs(want))
	for i := range want {
		assertSchemaColumns(t, got[i].Columns, want[i].Columns)
		if got[i].ColumnsTruncated != want[i].ColumnsTruncated {
			t.Errorf("%s.%s columns_truncated = %v over %d columns, want %v",
				got[i].Schema, got[i].Table, got[i].ColumnsTruncated, len(got[i].Columns), want[i].ColumnsTruncated)
		}
	}
}

func assertSchemaTableIDs(t *testing.T, tables []SchemaTable, want []string) {
	t.Helper()
	got := schemaTableIDs(tables)
	seen := make(map[string]struct{}, len(got))
	for _, id := range got {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("schema search returned duplicate table entry %q: %v", id, got)
		}
		seen[id] = struct{}{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("schema search tables = %v, want exactly %v", got, want)
	}
}

func assertSchemaColumns(t *testing.T, got, want []SchemaColumn) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("schema search columns = %#v, want %#v", got, want)
	}
}

// assertOnlyTheLastTableCanBeMarked is the structural half of the marker's meaning,
// independent of any budget arithmetic: the answer is a prefix of the ordered rows,
// so the only table whose column list can have been cut is the one the cut fell in,
// and that is always the last. A marker anywhere else would mean an entry was
// completed after the budget had already stopped inside it.
func assertOnlyTheLastTableCanBeMarked(t *testing.T, tables []SchemaTable) {
	t.Helper()
	for i := 0; i < len(tables)-1; i++ {
		if tables[i].ColumnsTruncated {
			t.Errorf("%s.%s reports a cut column list although %d entries follow it",
				tables[i].Schema, tables[i].Table, len(tables)-1-i)
		}
	}
}

func assertSchemaOrder(t *testing.T, tables []SchemaTable) {
	t.Helper()
	for i := 1; i < len(tables); i++ {
		previous, current := tables[i-1], tables[i]
		if previous.Schema > current.Schema || (previous.Schema == current.Schema && previous.Table > current.Table) {
			t.Errorf("tables are not in schema/table order: %v then %v", previous, current)
		}
	}
	for _, table := range tables {
		for i := 1; i < len(table.Columns); i++ {
			if table.Columns[i-1].Name > table.Columns[i].Name {
				t.Errorf("columns for %s.%s are not in name order: %s then %s", table.Schema, table.Table, table.Columns[i-1].Name, table.Columns[i].Name)
			}
		}
	}
}

func schemaJSONSize(t *testing.T, value any) int {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) = %v", value, err)
	}
	return len(encoded)
}

func schemaColumnCount(tables []SchemaTable) int {
	total := 0
	for _, table := range tables {
		total += len(table.Columns)
	}
	return total
}
