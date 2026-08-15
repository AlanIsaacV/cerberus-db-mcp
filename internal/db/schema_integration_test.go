//go:build integration

package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

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
			}

			byColumn, err := h.SearchSchema(context.Background(), h.alias, "title")
			if err != nil {
				t.Fatalf("SearchSchema(title) = %v", err)
			}
			assertSchemaTableIDs(t, byColumn.Tables, schemaFixtureTableIDs(engine, database))
			archive, ok := findSchemaTable(byColumn.Tables, schemaWideTableSchema(engine, database), "archive")
			if !ok {
				t.Fatalf("column search returned no archive table: %v", schemaTableIDs(byColumn.Tables))
			}
			assertSchemaColumns(t, archive.Columns, []SchemaColumn{{
				Name:     "title",
				DataType: fixtureType(engine, "character varying", "varchar"),
				Nullable: false,
			}})

			byMeasure, err := h.SearchSchema(context.Background(), h.alias, "measure")
			if err != nil {
				t.Fatalf("SearchSchema(measure) = %v", err)
			}
			assertSchemaTableIDs(t, byMeasure.Tables, []string{schemaWideTableID(engine, database)})
			wide, ok := findSchemaTable(byMeasure.Tables, schemaWideTableSchema(engine, database), "archive")
			if !ok {
				t.Fatalf("measure search returned no wide archive table: %v", schemaTableIDs(byMeasure.Tables))
			}
			assertSchemaColumns(t, wide.Columns, schemaMeasureColumns(engine))
			assertSchemaOrder(t, byColumn.Tables)
			assertSchemaOrder(t, byMeasure.Tables)
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
	assertSchemaTableIDs(t, ledger.Tables, schemaFixtureTableIDs(gate.MySQL, fixtureSecondDatabase))
	wide, err := ledgerExecutor.SearchSchema(context.Background(), ledgerAlias, "measure")
	if err != nil {
		t.Fatalf("SearchSchema(%s, measure) = %v", ledgerAlias, err)
	}
	assertSchemaTableIDs(t, wide.Tables, []string{schemaWideTableID(gate.MySQL, fixtureSecondDatabase)})
	archive, ok := findSchemaTable(wide.Tables, fixtureSecondDatabase, "archive")
	if !ok {
		t.Fatalf("ledger measure search returned no wide archive table: %v", schemaTableIDs(wide.Tables))
	}
	assertSchemaColumns(t, archive.Columns, schemaMeasureColumns(gate.MySQL))

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
				for _, statement := range []string{"SHOW statement_timeout", "SHOW lock_timeout"} {
					result, err := h.Execute(context.Background(), h.alias, statement, nil)
					if err != nil {
						t.Fatalf("Execute(%q) = %v", statement, err)
					}
					if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
						t.Fatalf("Execute(%q) rows = %#v, want one setting", statement, result.Rows)
					}
					if value := fixtureCatalogValue(result.Rows[0][0]); value == "" || value == "0" {
						t.Errorf("%s = %q, so the schema-search session has no bound", statement, value)
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
			if !result.Truncated || result.RowCap != 2 {
				t.Errorf("SearchSchema(archive) truncation = %v at row cap %d, want true at 2", result.Truncated, result.RowCap)
			}
		})
	}
}

func TestSearchSchemaSerializedSizeStaysBounded(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			database := fixtureDatabase
			if engine == gate.MySQL {
				database = fixtureSecondDatabase
			}
			h := schemaFixtureHarness(t, engine, database)
			// The configured test-suite cap is deliberately low. Raise it only for
			// this measurement so the full 250-column worst case is serialised.
			h.settings.RowCap = 300

			one, err := h.SearchSchema(context.Background(), h.alias, "archive")
			if err != nil {
				t.Fatalf("SearchSchema(archive) = %v", err)
			}
			assertSchemaTableIDs(t, one.Tables, schemaArchiveTableIDs(engine, database))
			oneSize := schemaJSONSize(t, one)
			if oneSize >= 4*1024 {
				t.Errorf("one-table search serialises to %d bytes, want under 4096", oneSize)
			}

			worst, err := h.SearchSchema(context.Background(), h.alias, "measure")
			if err != nil {
				t.Fatalf("SearchSchema(measure) = %v", err)
			}
			assertSchemaTableIDs(t, worst.Tables, []string{schemaWideTableID(engine, database)})
			wide, ok := findSchemaTable(worst.Tables, schemaWideTableSchema(engine, database), "archive")
			if !ok {
				t.Fatalf("worst-case measure search returned no wide archive table: %v", schemaTableIDs(worst.Tables))
			}
			assertSchemaColumns(t, wide.Columns, schemaMeasureColumns(engine))
			if worst.Truncated {
				t.Fatal("the 300-row cap truncated the 250-column measurement")
			}
			worstSize := schemaJSONSize(t, worst)
			t.Logf("worst schema-search result: %d bytes for %d tables and %d matching columns", worstSize, len(worst.Tables), schemaColumnCount(worst.Tables))
			if worstSize >= 20*1024 {
				t.Errorf("worst schema search serialises to %d bytes, want under 20480", worstSize)
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

	out := make([]string, 0, len(schemas)*len(wideFixtureTableNames))
	for _, schema := range schemas {
		for _, table := range wideFixtureTableNames {
			out = append(out, schema+"."+table)
		}
	}
	return out
}

func schemaArchiveTableIDs(engine gate.Engine, database string) []string {
	if engine == gate.PostgreSQL {
		return []string{"atelier.archive", "harbor.archive"}
	}
	return []string{database + ".archive"}
}

func schemaWideTableSchema(engine gate.Engine, database string) string {
	if engine == gate.PostgreSQL {
		return "harbor"
	}
	return database
}

func schemaWideTableID(engine gate.Engine, database string) string {
	return schemaWideTableSchema(engine, database) + ".archive"
}

func schemaMeasureColumns(engine gate.Engine) []SchemaColumn {
	columns := make([]SchemaColumn, 0, 250)
	for i := 1; i <= 250; i++ {
		columns = append(columns, SchemaColumn{
			Name:     fmt.Sprintf("measure_%03d", i),
			DataType: fixtureMeasureType(engine, i),
			Nullable: i%3 != 0,
		})
	}
	return columns
}

func findSchemaTable(tables []SchemaTable, schema, name string) (SchemaTable, bool) {
	for _, table := range tables {
		if table.Schema == schema && table.Table == name {
			return table, true
		}
	}
	return SchemaTable{}, false
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
