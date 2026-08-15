//go:build integration

package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

const fixtureWideColumnCount = 256

var wideFixtureTableNames = []string{
	"archive", "beacon", "canvas", "docket", "ember", "folio", "grotto", "harvest", "island", "juncture",
	"keystone", "lantern", "meadow", "nexus", "orchard", "pavilion", "quarry", "rivulet", "signal_post", "terrace",
	"uplink", "vessel", "waypoint", "yearbook", "zenith", "alcove", "bastion", "cairn", "drift", "estuary",
	"foundry", "gallery", "horizon", "inlet", "journey", "kiosk", "lookout", "mosaic", "notion", "outpost",
	"pier", "quiver", "roost", "summit", "thicket", "union_hall", "veranda", "workshop", "yonder", "zephyr",
}

type wideFixtureColumn struct {
	name     string
	dataType string
	nullable bool
}

type wideFixtureTable struct {
	schema     string
	name       string
	columns    []wideFixtureColumn
	primaryKey []string
	indexName  string
}

// TestWideSchemaFixture reads every fixture table's metadata from the engines'
// catalogs. The expectations are intentionally explicit rather than inferred from
// the SQL files: the fixture is useful only if the init client actually created
// the shape the checked-in declarations name.
func TestWideSchemaFixture(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := wideFixtureHarness(t, engine)
			tables := wideFixtureTables(engine)
			if len(tables) != 100 {
				t.Fatalf("fixture declaration has %d tables, want 100", len(tables))
			}
			assertWideFixtureTableCounts(t, h, engine)

			wideTables := 0
			types := map[string]bool{}
			hasNullable := false
			hasNonNullable := false
			hasSingleColumnPrimaryKey := false
			hasMultiColumnPrimaryKey := false
			hasIndexedNonKeyColumn := false
			hasUnindexedNonKeyColumn := false

			for _, table := range tables {
				actualColumns := fixtureColumnsFromCatalog(t, h, table)
				if len(actualColumns) != len(table.columns) {
					t.Fatalf("%s.%s has %d catalog columns, want %d", table.schema, table.name, len(actualColumns), len(table.columns))
				}
				for i, want := range table.columns {
					got := actualColumns[i]
					if got != want {
						t.Errorf("%s.%s column %d = %+v, want %+v", table.schema, table.name, i+1, got, want)
					}
					types[got.dataType] = true
					if got.nullable {
						hasNullable = true
					} else {
						hasNonNullable = true
					}
				}

				primaryKey := fixturePrimaryKeyFromCatalog(t, h, engine, table)
				if !sameFixtureStrings(primaryKey, table.primaryKey) {
					t.Errorf("%s.%s primary key = %v, want %v", table.schema, table.name, primaryKey, table.primaryKey)
				}
				if len(primaryKey) == 1 {
					hasSingleColumnPrimaryKey = true
				}
				if len(primaryKey) > 1 {
					hasMultiColumnPrimaryKey = true
				}

				indexes := fixtureIndexesFromCatalog(t, h, engine, table)
				wantIndex := []string{table.indexName, "title"}
				if !sameFixtureStrings(indexes, wantIndex) {
					t.Errorf("%s.%s non-primary indexes = %v, want %v", table.schema, table.name, indexes, wantIndex)
				}
				indexedColumns := make(map[string]bool, len(indexes)/2)
				for i := 1; i < len(indexes); i += 2 {
					indexedColumns[indexes[i]] = true
				}
				primaryKeyColumns := make(map[string]bool, len(primaryKey))
				for _, column := range primaryKey {
					primaryKeyColumns[column] = true
				}
				for _, column := range table.columns {
					if primaryKeyColumns[column.name] {
						continue
					}
					if indexedColumns[column.name] {
						hasIndexedNonKeyColumn = true
					} else {
						hasUnindexedNonKeyColumn = true
					}
				}
				if len(table.columns) >= fixtureWideColumnCount {
					wideTables++
				}
			}

			if !hasNullable || !hasNonNullable {
				t.Error("the catalog does not show both nullable and non-nullable fixture columns")
			}
			if len(types) < 4 {
				t.Errorf("the catalog shows %d fixture column types, want at least 4: %v", len(types), types)
			}
			if !hasSingleColumnPrimaryKey || !hasMultiColumnPrimaryKey {
				t.Error("the catalog does not show both single-column and multi-column fixture primary keys")
			}
			if !hasIndexedNonKeyColumn || !hasUnindexedNonKeyColumn {
				t.Error("the catalog does not show both indexed and unindexed non-key fixture columns")
			}
			if wideTables != 1 {
				t.Errorf("the catalog has %d deliberately wide fixture tables, want exactly 1", wideTables)
			}
		})
	}
}

// TestWideSchemaReadThroughExecutor names a concrete fixture table on each
// engine and reads it through Execute. The fixture has no rows by design; a
// successful empty result still proves that the executor can resolve the table.
func TestWideSchemaReadThroughExecutor(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := wideFixtureHarness(t, engine)
			statement := "SELECT title FROM atelier.archive"
			if engine == gate.MySQL {
				statement = "SELECT title FROM testbed.archive"
			}
			result, err := h.Execute(context.Background(), h.alias, statement, nil)
			if err != nil {
				t.Fatalf("Execute(%q) = %v", statement, err)
			}
			if len(result.Columns) != 1 || result.Columns[0] != "title" {
				t.Errorf("Execute(%q) columns = %v, want [title]", statement, result.Columns)
			}
		})
	}
}

// wideFixtureHarness selects the connection that reaches the database in which
// the PostgreSQL fixture lives. setUp deliberately takes the first alias for
// general integration tests, but a fixture test must not turn alias ordering
// into an assumption about its database.
func wideFixtureHarness(t *testing.T, engine gate.Engine) harness {
	t.Helper()
	if engine != gate.PostgreSQL {
		return setUp(t, engine)
	}

	required := engineIsRequired(t, engine)
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

	for _, alias := range e.engineAliases(engine) {
		c, _ := e.connFor(alias)
		if c.spec().Database == fixtureDatabase {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, err := e.Execute(ctx, alias, "SELECT 1", nil); err != nil {
				if errors.Is(err, ErrUnavailable) {
					skipOrFail(t, required, engine, fmt.Sprintf("alias %q (%s) is configured but not reachable: %v", alias, engine, err))
				}
				t.Fatalf("the configured %s alias %q rejected SELECT 1: %v", engine, alias, err)
			}
			return harness{Executor: e, alias: alias, spec: c.spec()}
		}
	}
	// Through skipOrFail rather than t.Skipf, because this is the skip most able to
	// hide something: a configured, reachable PostgreSQL server whose alias list has
	// simply stopped naming the fixture database silences every wide-fixture
	// assertion behind a green run. When CERBERUS_TEST_REQUIRE_ENGINES names
	// PostgreSQL, that is a failure and not an absence.
	skipOrFail(t, required, engine, fmt.Sprintf("no PostgreSQL alias is configured for the fixture database %q; include it in CERBERUS_DB_*_DATABASES", fixtureDatabase))
	return harness{}
}

func wideFixtureTables(engine gate.Engine) []wideFixtureTable {
	var schemas []string
	switch engine {
	case gate.PostgreSQL:
		schemas = []string{"atelier", "harbor"}
	case gate.MySQL:
		schemas = []string{fixtureDatabase, fixtureSecondDatabase}
	default:
		return nil
	}

	tables := make([]wideFixtureTable, 0, len(schemas)*len(wideFixtureTableNames))
	for _, schema := range schemas {
		for ordinal, name := range wideFixtureTableNames {
			wide := name == "archive" && ((engine == gate.PostgreSQL && schema == "harbor") || (engine == gate.MySQL && schema == fixtureSecondDatabase))
			columns, primaryKey := wideFixtureShape(engine, ordinal, wide)
			tables = append(tables, wideFixtureTable{
				schema:     schema,
				name:       name,
				columns:    columns,
				primaryKey: primaryKey,
				indexName:  "ix_" + name + "_title",
			})
		}
	}
	return tables
}

func wideFixtureShape(engine gate.Engine, ordinal int, wide bool) ([]wideFixtureColumn, []string) {
	shared := []wideFixtureColumn{
		{name: "title", dataType: fixtureType(engine, "character varying", "varchar"), nullable: false},
		{name: "note", dataType: "text", nullable: true},
		{name: "amount", dataType: fixtureType(engine, "numeric", "decimal"), nullable: false},
		{name: "active", dataType: fixtureType(engine, "boolean", "tinyint"), nullable: false},
		{name: "recorded_at", dataType: fixtureType(engine, "timestamp with time zone", "timestamp"), nullable: false},
	}
	if wide {
		columns := append([]wideFixtureColumn{{name: "id", dataType: "bigint", nullable: false}}, shared...)
		for i := 1; i <= 250; i++ {
			columns = append(columns, wideFixtureColumn{
				name:     fmt.Sprintf("measure_%03d", i),
				dataType: fixtureMeasureType(engine, i),
				nullable: i%3 != 0,
			})
		}
		return columns, []string{"id"}
	}
	if ordinal%2 == 0 {
		return append([]wideFixtureColumn{{name: "id", dataType: "bigint", nullable: false}}, shared...), []string{"id"}
	}
	columns := []wideFixtureColumn{
		{name: "area_code", dataType: fixtureType(engine, "character varying", "varchar"), nullable: false},
		{name: "series_no", dataType: fixtureType(engine, "integer", "int"), nullable: false},
	}
	return append(columns, shared...), []string{"area_code", "series_no"}
}

func fixtureType(engine gate.Engine, postgres, mysql string) string {
	if engine == gate.PostgreSQL {
		return postgres
	}
	return mysql
}

func fixtureMeasureType(engine gate.Engine, ordinal int) string {
	postgres := []string{"integer", "bigint", "numeric", "text"}
	mysql := []string{"int", "bigint", "decimal", "text"}
	if engine == gate.PostgreSQL {
		return postgres[(ordinal-1)%len(postgres)]
	}
	return mysql[(ordinal-1)%len(mysql)]
}

func assertWideFixtureTableCounts(t *testing.T, h harness, engine gate.Engine) {
	t.Helper()
	fixtureNames := "'" + strings.Join(wideFixtureTableNames, "', '") + "'"
	statement := fmt.Sprintf("SELECT table_schema, count(*) FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema IN ('atelier', 'harbor') AND table_name IN (%s) GROUP BY table_schema ORDER BY table_schema", fixtureNames)
	expected := map[string]string{"atelier": "50", "harbor": "50"}
	if engine == gate.MySQL {
		statement = fmt.Sprintf("SELECT table_schema, count(*) FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema IN ('testbed', 'ledger') AND table_name IN (%s) GROUP BY table_schema ORDER BY table_schema", fixtureNames)
		expected = map[string]string{fixtureDatabase: "50", fixtureSecondDatabase: "50"}
	}
	result, err := h.Execute(context.Background(), h.alias, statement, nil)
	if err != nil {
		t.Fatalf("catalog table count = %v", err)
	}
	actual := map[string]string{}
	for _, row := range result.Rows {
		if len(row) != 2 {
			t.Fatalf("catalog table count row = %v, want two values", row)
		}
		actual[fixtureCatalogValue(row[0])] = fixtureCatalogValue(row[1])
	}
	for schema, want := range expected {
		if actual[schema] != want {
			t.Errorf("catalog has %s tables in %s, want %s", actual[schema], schema, want)
		}
	}
}

func fixtureColumnsFromCatalog(t *testing.T, h harness, table wideFixtureTable) []wideFixtureColumn {
	t.Helper()
	columns := make([]wideFixtureColumn, 0)
	for offset := 0; ; offset += h.Settings().RowCap {
		statement := fmt.Sprintf("SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = '%s' AND table_name = '%s' ORDER BY ordinal_position LIMIT %d OFFSET %d", table.schema, table.name, h.Settings().RowCap, offset)
		result, err := h.Execute(context.Background(), h.alias, statement, nil)
		if err != nil {
			t.Fatalf("catalog columns for %s.%s at offset %d = %v", table.schema, table.name, offset, err)
		}
		for _, row := range result.Rows {
			if len(row) != 3 {
				t.Fatalf("catalog column row for %s.%s = %v, want three values", table.schema, table.name, row)
			}
			columns = append(columns, wideFixtureColumn{
				name:     fixtureCatalogValue(row[0]),
				dataType: fixtureCatalogValue(row[1]),
				nullable: fixtureCatalogValue(row[2]) == "YES",
			})
		}
		if len(result.Rows) < h.Settings().RowCap {
			return columns
		}
	}
}

func fixturePrimaryKeyFromCatalog(t *testing.T, h harness, engine gate.Engine, table wideFixtureTable) []string {
	t.Helper()
	statement := fmt.Sprintf("SELECT column_name FROM information_schema.key_column_usage WHERE constraint_schema = '%s' AND table_name = '%s' AND constraint_name = 'PRIMARY' ORDER BY ordinal_position", table.schema, table.name)
	if engine == gate.PostgreSQL {
		statement = fmt.Sprintf("SELECT kcu.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_catalog = kcu.constraint_catalog AND tc.constraint_schema = kcu.constraint_schema AND tc.constraint_name = kcu.constraint_name WHERE tc.table_schema = '%s' AND tc.table_name = '%s' AND tc.constraint_type = 'PRIMARY KEY' ORDER BY kcu.ordinal_position", table.schema, table.name)
	}
	return fixtureCatalogStrings(t, h, statement, table, "primary key")
}

func fixtureIndexesFromCatalog(t *testing.T, h harness, engine gate.Engine, table wideFixtureTable) []string {
	t.Helper()
	statement := fmt.Sprintf("SELECT index_name, column_name FROM information_schema.statistics WHERE table_schema = '%s' AND table_name = '%s' AND index_name <> 'PRIMARY' ORDER BY index_name, seq_in_index", table.schema, table.name)
	if engine == gate.PostgreSQL {
		statement = fmt.Sprintf("SELECT index_class.relname, attribute.attname FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class table_class ON table_class.oid = i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = table_class.relnamespace JOIN pg_catalog.pg_class index_class ON index_class.oid = i.indexrelid JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = table_class.oid AND attribute.attnum = ANY(i.indkey) WHERE n.nspname = '%s' AND table_class.relname = '%s' AND NOT i.indisprimary ORDER BY index_class.relname, array_position(i.indkey::smallint[], attribute.attnum)", table.schema, table.name)
	}
	return fixtureCatalogStrings(t, h, statement, table, "indexes")
}

func fixtureCatalogStrings(t *testing.T, h harness, statement string, table wideFixtureTable, kind string) []string {
	t.Helper()
	result, err := h.Execute(context.Background(), h.alias, statement, nil)
	if err != nil {
		t.Fatalf("catalog %s for %s.%s = %v", kind, table.schema, table.name, err)
	}
	values := make([]string, 0, len(result.Rows)*2)
	for _, row := range result.Rows {
		for _, value := range row {
			values = append(values, fixtureCatalogValue(value))
		}
	}
	return values
}

func fixtureCatalogValue(value any) string {
	if bytes, ok := value.([]byte); ok {
		return string(bytes)
	}
	return fmt.Sprint(value)
}

func sameFixtureStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
