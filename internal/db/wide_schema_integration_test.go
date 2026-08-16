//go:build integration

package db

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

const (
	fixtureWideColumnCount = 256
	// The composite-keyed wide table: its two key columns and the five shared ones,
	// then 250 filler columns of its own family.
	fixtureWideCompositeColumnCount = 257
)

// The tables tools/wide-schema gives an index or key shape of their own. They are
// named here rather than matched by pattern because every assertion about a shape
// has to name the table that carries it.
const (
	fixtureMultiColumnIndexTable = "multi_column_index_probe"
	fixtureMultiIndexTable       = "multi_index_probe"
	fixtureWideCompositeTable    = "wide_composite_key_probe"
)

// wideFixtureTableNames is in the generator's order, which is thematic and not
// sorted: wideFixtureShape derives a table's default key from its ordinal here, so
// reordering it changes the fixture. The three shaped tables are appended last for
// the same reason.
var wideFixtureTableNames = []string{
	"archive", "beacon", "canvas", "docket", "ember", "folio", "grotto", "harvest", "island", "juncture",
	"keystone", "lantern", "meadow", "nexus", "orchard", "pavilion", "quarry", "rivulet", "signal_post", "terrace",
	"uplink", "vessel", "waypoint", "yearbook", "zenith", "alcove", "bastion", "cairn", "drift", "estuary",
	"foundry", "gallery", "horizon", "inlet", "journey", "kiosk", "lookout", "mosaic", "notion", "outpost",
	"pier", "quiver", "roost", "summit", "thicket", "union_hall", "veranda", "workshop", "yonder", "zephyr",
	fixtureMultiColumnIndexTable, fixtureMultiIndexTable, fixtureWideCompositeTable,
}

type wideFixtureColumn struct {
	name     string
	dataType string
	nullable bool
}

// wideFixtureIndex is one secondary index as the catalog should report it: the
// key columns in key order, not as a set, and whether the engine calls it unique.
type wideFixtureIndex struct {
	name    string
	columns []string
	unique  bool
}

type wideFixtureTable struct {
	schema     string
	name       string
	columns    []wideFixtureColumn
	primaryKey []string
	indexes    []wideFixtureIndex
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
			if len(tables) != 106 {
				t.Fatalf("fixture declaration has %d tables, want 106", len(tables))
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
				if !sameFixtureIndexes(indexes, table.indexes) {
					t.Errorf("%s.%s non-primary indexes = %+v, want %+v", table.schema, table.name, indexes, table.indexes)
				}
				indexedColumns := make(map[string]bool, len(indexes))
				for _, index := range indexes {
					for _, column := range index.columns {
						indexedColumns[column] = true
					}
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
			// One archive, in the second schema only, plus the composite-keyed wide
			// table in each of the two.
			if wideTables != 3 {
				t.Errorf("the catalog has %d deliberately wide fixture tables, want exactly 3", wideTables)
			}
		})
	}
}

// TestWideFixtureIndexAndKeyVariety grades the shapes the fixture carries for the
// sake of a tool that has to report them: a multi-column index whose key order is
// not its columns' alphabetical order, a table carrying several indexes at once in
// both spellings of uniqueness, and a several-hundred-column table under a
// composite key whose key order is not its column order either.
//
// It names the tables rather than searching for the shapes, and it spells its
// expectations out instead of deriving them from wideFixtureShape. That is
// deliberate redundancy rather than a computation being avoided: the shaped cases
// in wideFixtureShape are hand-written literals too, so the index names, the key
// orders, the uniqueness flags, the 257-column count and the reversed primary key
// are each written by hand in two places. Two independent statements of one
// fixture shape mean an editor who changes one and not the other gets a failure
// instead of silent agreement, which is what you want from a fixture that other
// tests take their expectations from. It proves nothing by itself — it is a
// choice — and its price is that a shape change has to be made in both places.
//
// One body covers both engines. Only the catalog read differs between them, and it
// is behind fixtureIndexesFromCatalog — see there for why uniqueness in particular
// cannot be compared in the engines' own terms.
func TestWideFixtureIndexAndKeyVariety(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := wideFixtureHarness(t, engine)
			for _, schema := range wideFixtureSchemas(engine) {
				t.Run(schema, func(t *testing.T) {
					assertFixtureMultiColumnIndex(t, h, engine, schema)
					assertFixtureIndexSet(t, h, engine, schema)
					assertFixtureWideCompositeKey(t, h, engine, schema)
				})
			}
		})
	}
}

func assertFixtureMultiColumnIndex(t *testing.T, h harness, engine gate.Engine, schema string) {
	t.Helper()
	table := wideFixtureTable{schema: schema, name: fixtureMultiColumnIndexTable}
	want := []wideFixtureIndex{{
		name:    "ix_" + fixtureMultiColumnIndexTable + "_recorded_at_title_amount",
		columns: []string{"recorded_at", "title", "amount"},
		unique:  false,
	}}

	// Without this the positional comparison below would pass an implementation
	// that sorted the key columns, and nothing would say so.
	sorted := slices.Clone(want[0].columns)
	slices.Sort(sorted)
	if slices.Equal(sorted, want[0].columns) {
		t.Fatalf("%s's index columns %v are in alphabetical order, so this test can no longer tell key order from a sort", fixtureMultiColumnIndexTable, want[0].columns)
	}

	got := fixtureIndexesFromCatalog(t, h, engine, table)
	if !sameFixtureIndexes(got, want) {
		t.Errorf("%s.%s indexes = %+v, want %+v", schema, table.name, got, want)
	}
}

func assertFixtureIndexSet(t *testing.T, h harness, engine gate.Engine, schema string) {
	t.Helper()
	table := wideFixtureTable{schema: schema, name: fixtureMultiIndexTable}
	// In index-name order, which is what both catalog reads return. uq_ is the
	// index behind the UNIQUE constraint declared in CREATE TABLE and ux_ the one
	// created as a UNIQUE INDEX; both engines name the first after the constraint,
	// which is why it can be asserted by name at all.
	want := []wideFixtureIndex{
		{name: "ix_" + fixtureMultiIndexTable + "_title", columns: []string{"title"}, unique: false},
		{name: "uq_" + fixtureMultiIndexTable + "_batch_code", columns: []string{"batch_code"}, unique: true},
		{name: "ux_" + fixtureMultiIndexTable + "_serial_code", columns: []string{"serial_code"}, unique: true},
	}

	got := fixtureIndexesFromCatalog(t, h, engine, table)
	if !sameFixtureIndexes(got, want) {
		t.Errorf("%s.%s indexes = %+v, want %+v", schema, table.name, got, want)
	}

	// Read from what the catalog said rather than from the expectation, so that an
	// engine reporting every index the same way fails here even if the comparison
	// above were ever loosened.
	unique := 0
	for _, index := range got {
		if index.unique {
			unique++
		}
	}
	if unique == 0 || unique == len(got) {
		t.Errorf("the catalog calls %d of %s.%s's %d indexes unique, so it does not distinguish a unique index from a non-unique one", unique, schema, table.name, len(got))
	}
}

func assertFixtureWideCompositeKey(t *testing.T, h harness, engine gate.Engine, schema string) {
	t.Helper()
	table := wideFixtureTable{schema: schema, name: fixtureWideCompositeTable}

	columns := fixtureColumnsFromCatalog(t, h, table)
	if len(columns) != fixtureWideCompositeColumnCount {
		t.Errorf("%s.%s has %d catalog columns, want %d", schema, table.name, len(columns), fixtureWideCompositeColumnCount)
	}

	// The reverse of the order these two columns are declared in, so an answer that
	// reported the table's column order instead of the key's is wrong here.
	want := []string{"series_no", "area_code"}
	got := fixturePrimaryKeyFromCatalog(t, h, engine, table)
	if !sameFixtureStrings(got, want) {
		t.Errorf("%s.%s primary key = %v, want %v", schema, table.name, got, want)
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

// wideFixtureSchemas is where the fixture lives on an engine, in the order the
// generator writes it: on PostgreSQL two schemas of one database, on MySQL two
// databases, because a MySQL schema is a database.
func wideFixtureSchemas(engine gate.Engine) []string {
	switch engine {
	case gate.PostgreSQL:
		return []string{"atelier", "harbor"}
	case gate.MySQL:
		return []string{fixtureDatabase, fixtureSecondDatabase}
	default:
		return nil
	}
}

func wideFixtureTables(engine gate.Engine) []wideFixtureTable {
	schemas := wideFixtureSchemas(engine)
	if len(schemas) == 0 {
		return nil
	}

	tables := make([]wideFixtureTable, 0, len(schemas)*len(wideFixtureTableNames))
	for _, schema := range schemas {
		for ordinal, name := range wideFixtureTableNames {
			wide := name == "archive" && ((engine == gate.PostgreSQL && schema == "harbor") || (engine == gate.MySQL && schema == fixtureSecondDatabase))
			table := wideFixtureShape(engine, name, ordinal, wide)
			table.schema = schema
			tables = append(tables, table)
		}
	}
	return tables
}

// wideFixtureShape mirrors tools/wide-schema's declaration of one table. The three
// shaped tables are spelled out here in full rather than derived, because a
// declaration that computed the same thing the generator computes would agree with
// a generator that had drifted.
//
// Every index list is in index-name order, which is the order both catalog reads
// return and therefore the order the comparison is positional in.
//
// The three shaped cases below are also stated as literals in
// TestWideFixtureIndexAndKeyVariety, on purpose; changing a shape here means
// changing it there too.
func wideFixtureShape(engine gate.Engine, name string, ordinal int, wide bool) wideFixtureTable {
	varchar := fixtureType(engine, "character varying", "varchar")
	id := wideFixtureColumn{name: "id", dataType: "bigint", nullable: false}
	shared := []wideFixtureColumn{
		{name: "title", dataType: varchar, nullable: false},
		{name: "note", dataType: "text", nullable: true},
		{name: "amount", dataType: fixtureType(engine, "numeric", "decimal"), nullable: false},
		{name: "active", dataType: fixtureType(engine, "boolean", "tinyint"), nullable: false},
		{name: "recorded_at", dataType: fixtureType(engine, "timestamp with time zone", "timestamp"), nullable: false},
	}
	composite := []wideFixtureColumn{
		{name: "area_code", dataType: varchar, nullable: false},
		{name: "series_no", dataType: fixtureType(engine, "integer", "int"), nullable: false},
	}
	// The filler family differs between the two wide tables on purpose: measure_
	// columns exist in exactly one MySQL database, which is what a search test uses
	// to show that a search cannot cross databases.
	filler := func(prefix string, columns []wideFixtureColumn) []wideFixtureColumn {
		for i := 1; i <= 250; i++ {
			columns = append(columns, wideFixtureColumn{
				name:     fmt.Sprintf("%s_%03d", prefix, i),
				dataType: fixtureMeasureType(engine, i),
				nullable: i%3 != 0,
			})
		}
		return columns
	}
	table := wideFixtureTable{name: name}

	switch name {
	case fixtureMultiColumnIndexTable:
		table.columns = append([]wideFixtureColumn{id}, shared...)
		table.primaryKey = []string{"id"}
		table.indexes = []wideFixtureIndex{{
			name:    "ix_" + name + "_recorded_at_title_amount",
			columns: []string{"recorded_at", "title", "amount"},
		}}
	case fixtureMultiIndexTable:
		table.columns = append([]wideFixtureColumn{id}, shared...)
		table.columns = append(table.columns,
			wideFixtureColumn{name: "serial_code", dataType: varchar, nullable: false},
			wideFixtureColumn{name: "batch_code", dataType: varchar, nullable: false},
		)
		table.primaryKey = []string{"id"}
		table.indexes = []wideFixtureIndex{
			{name: "ix_" + name + "_title", columns: []string{"title"}},
			{name: "uq_" + name + "_batch_code", columns: []string{"batch_code"}, unique: true},
			{name: "ux_" + name + "_serial_code", columns: []string{"serial_code"}, unique: true},
		}
	case fixtureWideCompositeTable:
		table.columns = filler("gauge", append(append([]wideFixtureColumn{}, composite...), shared...))
		// Deliberately the reverse of the declaration order of those columns.
		table.primaryKey = []string{"series_no", "area_code"}
		table.indexes = []wideFixtureIndex{{name: "ix_" + name + "_title", columns: []string{"title"}}}
	default:
		switch {
		case wide:
			table.columns = filler("measure", append([]wideFixtureColumn{id}, shared...))
			table.primaryKey = []string{"id"}
		case ordinal%2 == 0:
			table.columns = append([]wideFixtureColumn{id}, shared...)
			table.primaryKey = []string{"id"}
		default:
			table.columns = append(append([]wideFixtureColumn{}, composite...), shared...)
			table.primaryKey = []string{"area_code", "series_no"}
		}
		table.indexes = []wideFixtureIndex{{name: "ix_" + name + "_title", columns: []string{"title"}}}
	}
	return table
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
	expected := map[string]string{"atelier": "53", "harbor": "53"}
	if engine == gate.MySQL {
		statement = fmt.Sprintf("SELECT table_schema, count(*) FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema IN ('testbed', 'ledger') AND table_name IN (%s) GROUP BY table_schema ORDER BY table_schema", fixtureNames)
		expected = map[string]string{fixtureDatabase: "53", fixtureSecondDatabase: "53"}
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

// fixtureIndexesFromCatalog reads a table's non-primary indexes out of the engine's
// own catalog: each index's name, its key columns in key order rather than as a
// set, and whether the engine calls it unique.
//
// The read is per-engine and the normalisation belongs to it, so that one
// assertion body can grade both engines. The two catalogs do not merely spell
// uniqueness differently — PostgreSQL's pg_index.indisunique is true for a unique
// index while MySQL's information_schema.statistics.non_unique is 0 for one — so a
// reader that carried either engine's raw value across to the other would report
// every index backwards. Anything but the two values each engine is known to
// return fails the test rather than being coerced.
//
// On PostgreSQL, array_position(i.indkey::smallint[], attribute.attnum) stands in
// for unnest(i.indkey) WITH ORDINALITY, which is the idiomatic way to put pg_index
// key columns in key order and which this project's gate refuses: at
// internal/gate/gate.go:387 a read keyword at depth zero begins a second statement
// unless a set operator or a WITH body explains it, and WITH ORDINALITY is neither,
// so a live fixture run came back "the statement is not provably a read: a second
// statement begins here" — gotcha 01KZZ2QD48Y79R83DT69G6633T. The construct appears
// nowhere in this repository, so whoever next writes a catalog query here will
// reach for it, watch the gate deny, and rediscover that from scratch. It is also
// the precedent every such refusal has followed so far: when a catalog construct is
// not admissible, the statement changes and the gate's ruleset does not.
func fixtureIndexesFromCatalog(t *testing.T, h harness, engine gate.Engine, table wideFixtureTable) []wideFixtureIndex {
	t.Helper()
	statement := fmt.Sprintf("SELECT index_name, column_name, non_unique FROM information_schema.statistics WHERE table_schema = '%s' AND table_name = '%s' AND index_name <> 'PRIMARY' ORDER BY index_name, seq_in_index", table.schema, table.name)
	if engine == gate.PostgreSQL {
		statement = fmt.Sprintf("SELECT index_class.relname, attribute.attname, i.indisunique FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class table_class ON table_class.oid = i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = table_class.relnamespace JOIN pg_catalog.pg_class index_class ON index_class.oid = i.indexrelid JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = table_class.oid AND attribute.attnum = ANY(i.indkey) WHERE n.nspname = '%s' AND table_class.relname = '%s' AND NOT i.indisprimary ORDER BY index_class.relname, array_position(i.indkey::smallint[], attribute.attnum)", table.schema, table.name)
	}

	indexes := make([]wideFixtureIndex, 0)
	for _, row := range fixtureCatalogRows(t, h, statement, table, "indexes") {
		if len(row) != 3 {
			t.Fatalf("catalog index row for %s.%s = %v, want three values", table.schema, table.name, row)
		}
		unique := fixtureIndexIsUnique(t, engine, row[2])
		if len(indexes) == 0 || indexes[len(indexes)-1].name != row[0] {
			indexes = append(indexes, wideFixtureIndex{name: row[0], unique: unique})
		}
		last := &indexes[len(indexes)-1]
		if last.unique != unique {
			t.Fatalf("catalog reports %s.%s index %s as unique=%v on one column and %v on another", table.schema, table.name, last.name, last.unique, unique)
		}
		last.columns = append(last.columns, row[1])
	}
	return indexes
}

func fixtureIndexIsUnique(t *testing.T, engine gate.Engine, reported string) bool {
	t.Helper()
	switch engine {
	case gate.PostgreSQL:
		switch reported {
		case "true", "t":
			return true
		case "false", "f":
			return false
		}
	case gate.MySQL:
		switch reported {
		case "0":
			return true
		case "1":
			return false
		}
	}
	t.Fatalf("%s reports index uniqueness as %q, which is neither of the two values this engine is known to return", engine, reported)
	return false
}

func fixtureCatalogStrings(t *testing.T, h harness, statement string, table wideFixtureTable, kind string) []string {
	t.Helper()
	values := make([]string, 0)
	for _, row := range fixtureCatalogRows(t, h, statement, table, kind) {
		values = append(values, row...)
	}
	return values
}

func fixtureCatalogRows(t *testing.T, h harness, statement string, table wideFixtureTable, kind string) [][]string {
	t.Helper()
	result, err := h.Execute(context.Background(), h.alias, statement, nil)
	if err != nil {
		t.Fatalf("catalog %s for %s.%s = %v", kind, table.schema, table.name, err)
	}
	rows := make([][]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		values := make([]string, 0, len(row))
		for _, value := range row {
			values = append(values, fixtureCatalogValue(value))
		}
		rows = append(rows, values)
	}
	return rows
}

func fixtureCatalogValue(value any) string {
	if bytes, ok := value.([]byte); ok {
		return string(bytes)
	}
	return fmt.Sprint(value)
}

func sameFixtureIndexes(got, want []wideFixtureIndex) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i].name != want[i].name || got[i].unique != want[i].unique {
			return false
		}
		if !sameFixtureStrings(got[i].columns, want[i].columns) {
			return false
		}
	}
	return true
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
