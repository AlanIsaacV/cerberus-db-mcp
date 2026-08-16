// wide-schema regenerates the checked-in catalog-navigation fixtures.
//
// Run from the repository root:
//
//	go run ./tools/wide-schema
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	wideTable = "archive"

	// The tables named for the index or key property they carry, so a test can
	// name one table instead of searching the fixture for a shape.
	multiColumnIndexTable = "multi_column_index_probe"
	multiIndexTable       = "multi_index_probe"
	wideCompositeTable    = "wide_composite_key_probe"
)

// The filler that makes a table wide, and how many of them. archive keeps the
// measure_ family it has always had; the composite-keyed wide table uses another
// one because measure_ columns living in exactly one database on MySQL is the
// witness a search test uses to show that a search cannot cross databases.
const (
	fillerColumns       = 250
	measureFiller       = "measure"
	wideCompositeFiller = "gauge"
)

var tableNames = []string{
	"archive", "beacon", "canvas", "docket", "ember", "folio", "grotto", "harvest", "island", "juncture",
	"keystone", "lantern", "meadow", "nexus", "orchard", "pavilion", "quarry", "rivulet", "signal_post", "terrace",
	"uplink", "vessel", "waypoint", "yearbook", "zenith", "alcove", "bastion", "cairn", "drift", "estuary",
	"foundry", "gallery", "horizon", "inlet", "journey", "kiosk", "lookout", "mosaic", "notion", "outpost",
	"pier", "quiver", "roost", "summit", "thicket", "union_hall", "veranda", "workshop", "yonder", "zephyr",
	multiColumnIndexTable, multiIndexTable, wideCompositeTable,
}

// indexSpec is a secondary index as the fixture declares it: key columns in the
// order they are written, which is the order a reader has to preserve.
type indexSpec struct {
	name    string
	columns []string
	unique  bool
}

// tableShape is what a table is made of, in the terms both engines share. The
// column types differ between them and are filled in by each renderer; the keys
// and the indexes do not differ at all, which is what lets one test body assert
// them on either engine.
type tableShape struct {
	compositeKey bool
	// keyOrder overrides the order the primary key's columns are declared in. Empty
	// means the columns in the order the table declares them.
	keyOrder []string
	// filler is the column-name family that makes the table wide, empty for a table
	// that is not.
	filler string
	// extraColumns are whole declarations rather than names because they are
	// spelled identically on both engines; anything whose type differs belongs in
	// the per-engine shared-column writers.
	extraColumns     []string
	uniqueConstraint string
	indexes          []indexSpec
}

// shapedTables are the tables that exist for one index or key property each,
// rather than for the ordinal-alternating default every other fixture table
// gets. They are deliberately few: each one is something a describe tool has to
// report, not a sweep over the shapes an engine can express.
//
// The unique index and the unique constraint sit on the same table on purpose.
// Both engines implement a unique constraint as an index, and putting the two
// forms side by side is what lets a reader of the catalog be graded on telling
// them apart — or on deciding they need not be told apart. The constraint is
// named explicitly because an unnamed one makes each engine invent its own index
// name, which would split every assertion about it in two.
var shapedTables = map[string]tableShape{
	multiColumnIndexTable: {
		indexes: []indexSpec{{
			// Declared in an order that is neither alphabetical nor its reverse, so
			// a reader that sorts the columns instead of reading key order is wrong
			// visibly rather than by coincidence.
			name:    "ix_" + multiColumnIndexTable + "_recorded_at_title_amount",
			columns: []string{"recorded_at", "title", "amount"},
		}},
	},
	multiIndexTable: {
		extraColumns: []string{
			"serial_code VARCHAR(40) NOT NULL",
			"batch_code VARCHAR(40) NOT NULL",
		},
		uniqueConstraint: "CONSTRAINT uq_" + multiIndexTable + "_batch_code UNIQUE (batch_code)",
		indexes: []indexSpec{
			{name: "ix_" + multiIndexTable + "_title", columns: []string{"title"}},
			{name: "ux_" + multiIndexTable + "_serial_code", columns: []string{"serial_code"}, unique: true},
		},
	},
	wideCompositeTable: {
		compositeKey: true,
		// Keyed in the opposite order to the columns' declaration, which is what
		// separates a reader that reports key order from one that reports the
		// table's own column order and happens to agree with it everywhere else in
		// this fixture.
		keyOrder: []string{"series_no", "area_code"},
		filler:   wideCompositeFiller,
		indexes:  []indexSpec{{name: "ix_" + wideCompositeTable + "_title", columns: []string{"title"}}},
	},
}

// shapeFor is the single answer to what a table looks like: its named shape where
// it has one, and otherwise the default this fixture has always had — a primary
// key alternating with the ordinal and one non-unique index on title.
//
// A shaped table declares its own width through its filler field, so wide reaches
// only the default shape and is discarded for anything in shapedTables. That costs
// nothing today because the sole table the renderers flag wide is archive and
// archive is not shaped — an invariant two unrelated declarations hold between
// them. Giving archive a shape, or giving a shaped probe a width, would make the
// flag go quiet instead of conflicting, and the DDL would change with nothing
// pointing at why.
func shapeFor(table string, ordinal int, wide bool) tableShape {
	if shape, ok := shapedTables[table]; ok {
		return shape
	}
	shape := tableShape{
		compositeKey: !wide && ordinal%2 == 1,
		indexes:      []indexSpec{{name: "ix_" + table + "_title", columns: []string{"title"}}},
	}
	if wide {
		shape.filler = measureFiller
	}
	return shape
}

// writeKeyLines closes a CREATE TABLE body. The primary key is last among the
// columns and the unique constraint last of all, so the constraint a test names
// is where a reader of the DDL looks for it.
func writeKeyLines(b *strings.Builder, shape tableShape) {
	key := shape.keyOrder
	if len(key) == 0 {
		key = []string{"id"}
		if shape.compositeKey {
			key = []string{"area_code", "series_no"}
		}
	}
	fmt.Fprintf(b, "  PRIMARY KEY (%s)", strings.Join(key, ", "))
	if shape.uniqueConstraint != "" {
		fmt.Fprintf(b, ",\n  %s", shape.uniqueConstraint)
	}
	b.WriteString("\n")
}

func writeIndexes(b *strings.Builder, shape tableShape, target string) {
	for _, index := range shape.indexes {
		unique := ""
		if index.unique {
			unique = "UNIQUE "
		}
		fmt.Fprintf(b, "CREATE %sINDEX %s ON %s (%s);\n", unique, index.name, target, strings.Join(index.columns, ", "))
	}
	b.WriteString("\n")
}

func main() {
	files := map[string]string{
		filepath.Join("deploy", "postgres-init", "03-wide-schema.sql"): renderPostgreSQL(),
		filepath.Join("deploy", "mysql-init", "03-wide-schema.sql"):    renderMySQL(),
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

func header(engine string) string {
	return "-- Generated by tools/wide-schema for " + engine + ". DO NOT EDIT.\n" +
		"-- Regenerate from the repository root with: go run ./tools/wide-schema\n" +
		"--\n" +
		"-- This is schema only: it deliberately contains no rows or foreign keys. Its\n" +
		"-- size is what makes catalog navigation real rather than a one-object happy path,\n" +
		"-- but the fixture must still be safe for every test that shares these databases.\n" +
		"--\n" +
		"-- The 256-column archive table is deliberately in the second schema each engine\n" +
		"-- exposes: harbor follows atelier in PostgreSQL, and ledger follows MySQL's\n" +
		"-- testbed database. A resolver that reads only the first schema would\n" +
		"-- otherwise find enough ordinary tables to look healthy while never reaching the\n" +
		"-- wide-table path this fixture is here to exercise.\n" +
		"--\n" +
		"-- The shapes are consequently not symmetric. PostgreSQL schemas are namespaces\n" +
		"-- inside testbed, while a MySQL schema is a database; more than one schema there\n" +
		"-- must be testbed and ledger, not two names nested in testbed. Keeping that\n" +
		"-- distinction visible prevents a cross-engine abstraction from hiding it.\n" +
		"--\n" +
		"-- Three tables are named for an index or key property rather than thematically:\n" +
		"-- multi_column_index_probe, multi_index_probe and wide_composite_key_probe. Each\n" +
		"-- exists so that a reader of the catalog can be graded on one thing -- key order\n" +
		"-- in a multi-column index, several indexes on one table including both spellings\n" +
		"-- of uniqueness, and a several-hundred-column table under a composite key. They\n" +
		"-- are in every schema and database here, unlike archive's width, because a test\n" +
		"-- that names one of them should not also have to know which schema it landed in.\n" +
		"--\n" +
		"-- PostgreSQL's init connection is its image superuser, so SET ROLE cerberus below\n" +
		"-- is load-bearing rather than cosmetic. Without it that superuser owns the named\n" +
		"-- schemas and their tables, while the test login merely connects and cannot read\n" +
		"-- the fixture; creating them as cerberus makes its ownership the permission grant.\n\n"
}

func renderPostgreSQL() string {
	var b strings.Builder
	b.WriteString(header("PostgreSQL"))
	b.WriteString("\\connect testbed\n\n")
	b.WriteString("-- The test login owns these objects, so the executor can read them.\n")
	b.WriteString("SET ROLE cerberus;\n\n")
	for _, schema := range []string{"atelier", "harbor"} {
		fmt.Fprintf(&b, "CREATE SCHEMA %s;\n\n", schema)
		for i, table := range tableNames {
			writePostgreSQLTable(&b, schema, table, i, schema == "harbor" && table == wideTable)
		}
	}
	return b.String()
}

func writePostgreSQLTable(b *strings.Builder, schema, table string, ordinal int, wide bool) {
	qualified := schema + "." + table
	shape := shapeFor(table, ordinal, wide)
	fmt.Fprintf(b, "CREATE TABLE %s (\n", qualified)
	if shape.compositeKey {
		b.WriteString("  area_code VARCHAR(12) NOT NULL,\n")
		b.WriteString("  series_no INTEGER NOT NULL,\n")
	} else {
		b.WriteString("  id BIGINT NOT NULL,\n")
	}
	writePostgreSQLSharedColumns(b)
	if shape.filler != "" {
		for i := 1; i <= fillerColumns; i++ {
			fmt.Fprintf(b, "  %s_%03d %s%s,\n", shape.filler, i, postgreSQLFillerType(i), nullableSuffix(i))
		}
	}
	for _, column := range shape.extraColumns {
		fmt.Fprintf(b, "  %s,\n", column)
	}
	writeKeyLines(b, shape)
	b.WriteString(");\n")
	writeIndexes(b, shape, qualified)
}

func writePostgreSQLSharedColumns(b *strings.Builder) {
	b.WriteString("  title VARCHAR(160) NOT NULL,\n")
	b.WriteString("  note TEXT,\n")
	b.WriteString("  amount NUMERIC(12, 2) NOT NULL,\n")
	b.WriteString("  active BOOLEAN NOT NULL,\n")
	b.WriteString("  recorded_at TIMESTAMPTZ NOT NULL,\n")
}

func postgreSQLFillerType(i int) string {
	return []string{"INTEGER", "BIGINT", "NUMERIC(12, 2)", "TEXT"}[(i-1)%4]
}

func nullableSuffix(i int) string {
	if i%3 == 0 {
		return " NOT NULL"
	}
	return ""
}

func renderMySQL() string {
	var b strings.Builder
	b.WriteString(header("MySQL"))
	for _, database := range []string{"testbed", "ledger"} {
		fmt.Fprintf(&b, "USE %s;\n\n", database)
		for i, table := range tableNames {
			writeMySQLTable(&b, table, i, database == "ledger" && table == wideTable)
		}
	}
	return b.String()
}

func writeMySQLTable(b *strings.Builder, table string, ordinal int, wide bool) {
	shape := shapeFor(table, ordinal, wide)
	fmt.Fprintf(b, "CREATE TABLE %s (\n", table)
	if shape.compositeKey {
		b.WriteString("  area_code VARCHAR(12) NOT NULL,\n")
		b.WriteString("  series_no INTEGER NOT NULL,\n")
	} else {
		b.WriteString("  id BIGINT NOT NULL,\n")
	}
	writeMySQLSharedColumns(b)
	if shape.filler != "" {
		for i := 1; i <= fillerColumns; i++ {
			fmt.Fprintf(b, "  %s_%03d %s%s,\n", shape.filler, i, mySQLFillerType(i), nullableSuffix(i))
		}
	}
	for _, column := range shape.extraColumns {
		fmt.Fprintf(b, "  %s,\n", column)
	}
	writeKeyLines(b, shape)
	b.WriteString(");\n")
	writeIndexes(b, shape, table)
}

func writeMySQLSharedColumns(b *strings.Builder) {
	b.WriteString("  title VARCHAR(160) NOT NULL,\n")
	b.WriteString("  note TEXT,\n")
	b.WriteString("  amount DECIMAL(12, 2) NOT NULL,\n")
	b.WriteString("  active BOOLEAN NOT NULL,\n")
	b.WriteString("  recorded_at TIMESTAMP NOT NULL,\n")
}

func mySQLFillerType(i int) string {
	return []string{"INTEGER", "BIGINT", "DECIMAL(12, 2)", "TEXT"}[(i-1)%4]
}
