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

	// namesakePrefix is the substring one table shares with several of its own
	// columns, and namesakeTable is that table. Together they are the only way this
	// fixture can answer one pattern with a table and a handful of that table's
	// columns: internal/db/schema.go returns an empty column list for a table matched
	// by its name alone, so a pattern has to reach the name and the columns at once.
	//
	// The prefix must stay absent from every other identifier here or the pattern
	// stops naming one table -- not in tableNames, not in the shared columns, and not
	// in the measure_ or gauge_ filler families.
	namesakePrefix = "namesake"
	namesakeTable  = namesakePrefix + "_probe"
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
	multiColumnIndexTable, multiIndexTable, wideCompositeTable, namesakeTable,
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
	namesakeTable: {
		// Four prefixed columns in a table of ten. The call this table exists for is
		// the cheap one an agent makes to find its way, so the answer it comes back
		// with has to stay small enough to be worth making.
		extraColumns: []string{
			namesakePrefix + "_code VARCHAR(40) NOT NULL",
			namesakePrefix + "_label VARCHAR(80) NOT NULL",
			namesakePrefix + "_state VARCHAR(24)",
			namesakePrefix + "_rank INTEGER NOT NULL",
		},
		// On a prefixed column rather than on title, so that the seeded rows below sit
		// under a primary key and one other indexed column: a restriction on either
		// can then be shown to drop rows.
		indexes: []indexSpec{{
			name:    "ix_" + namesakeTable + "_" + namesakePrefix + "_code",
			columns: []string{namesakePrefix + "_code"},
		}},
	},
}

// seededTable is the one table in this fixture that is not empty, and seedRows is
// what it holds, in every schema and database the fixture is written into.
//
// It carries rows because the agent sequence measured against this fixture ends in
// a query written from what describe_table answered, and a query answered with no
// rows contributes almost nothing to the total: the measurement would flatter the
// sequence it exists to grade. Nothing else here gains rows -- see the header.
//
// The keys are five consecutive values rather than one repeated, so that a strict
// restriction on the key genuinely drops rows. A restriction against the smallest
// key the table holds is a tautology and grades nothing.
const seededTable = namesakeTable

// seedRow is one row of seededTable. amount is the literal digits both engines
// store rather than a Go float, whose formatting would otherwise decide what the
// DDL says. An empty note or state is the row that stores SQL NULL there, which is
// what makes those columns nullable in fact and not only in the catalog.
type seedRow struct {
	id         int
	title      string
	note       string
	amount     string
	active     bool
	recordedAt string
	code       string
	label      string
	state      string
	rank       int
}

// seedColumns names what the INSERT fills, in the order seededTable declares its
// columns. It is written out rather than derived from the shape above: deriving it
// would mean splitting whole column declarations on whitespace, which goes wrong
// silently, while a mistake in this list stops the engine's init script.
var seedColumns = []string{
	"id", "title", "note", "amount", "active", "recorded_at",
	namesakePrefix + "_code", namesakePrefix + "_label", namesakePrefix + "_state", namesakePrefix + "_rank",
}

// No value below contains an apostrophe, because writeSeedRows writes literals and
// does not escape them. The values are also plain ASCII and their decimals carry
// the column's own scale, so that what the two engines return differs as little as
// a measurement in bytes can bear.
var seedRows = []seedRow{
	{id: 1, title: "alpha entry", note: "the first seeded row", amount: "10.50", active: true, recordedAt: "2026-03-01 09:00:00", code: "NS-0001", label: "alpha namesake", state: "open", rank: 10},
	{id: 2, title: "bravo entry", note: "", amount: "20.75", active: false, recordedAt: "2026-03-02 09:00:00", code: "NS-0002", label: "bravo namesake", state: "open", rank: 20},
	{id: 3, title: "charlie entry", note: "the third seeded row", amount: "31.00", active: true, recordedAt: "2026-03-03 09:00:00", code: "NS-0003", label: "charlie namesake", state: "held", rank: 30},
	{id: 4, title: "delta entry", note: "the fourth seeded row", amount: "42.25", active: false, recordedAt: "2026-03-04 09:00:00", code: "NS-0004", label: "delta namesake", state: "", rank: 40},
	{id: 5, title: "echo entry", note: "the fifth seeded row", amount: "53.60", active: true, recordedAt: "2026-03-05 09:00:00", code: "NS-0005", label: "echo namesake", state: "closed", rank: 50},
}

// writeSeedRows fills seededTable at target.
//
// utcOffset is the only thing the two engines are not given identically: a
// PostgreSQL TIMESTAMPTZ takes its instant from the offset written into the
// literal, while a MySQL TIMESTAMP reads a bare literal in the session time zone,
// which is UTC in this fixture's container and in CI's service container. Both
// therefore hold the same instant and hand back the same text, which is what makes
// a byte measurement over these rows comparable across the engines.
func writeSeedRows(b *strings.Builder, target, utcOffset string) {
	fmt.Fprintf(b, "INSERT INTO %s\n  (%s)\nVALUES\n", target, strings.Join(seedColumns, ", "))
	for i, row := range seedRows {
		terminator := ","
		if i == len(seedRows)-1 {
			terminator = ";"
		}
		fmt.Fprintf(b, "  (%d, %s, %s, %s, %s, '%s%s', %s, %s, %s, %d)%s\n",
			row.id, sqlText(row.title), sqlText(row.note), row.amount, sqlBool(row.active),
			row.recordedAt, utcOffset, sqlText(row.code), sqlText(row.label), sqlText(row.state), row.rank, terminator)
	}
	b.WriteString("\n")
}

// sqlText writes a literal, or NULL for the empty string. It does not escape
// anything: the values above are chosen so that nothing needs escaping, and keeping
// it that way is cheaper than a quoting layer in a generator whose whole input is
// written above it.
func sqlText(value string) string {
	if value == "" {
		return "NULL"
	}
	return "'" + value + "'"
}

func sqlBool(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
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
		"-- This is schema and, in exactly one table, rows: namesake_probe carries five\n" +
		"-- seeded rows in every schema and database here, because the agent sequence this\n" +
		"-- fixture is measured by ends in a query whose bytes say something only if it\n" +
		"-- returns something. Every other table is empty and there are no foreign keys\n" +
		"-- anywhere, because the fixture must still be safe for every test that shares\n" +
		"-- these databases. Its size is what makes catalog navigation real rather than a\n" +
		"-- one-object happy path.\n" +
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
		"-- Four tables are named for a property they carry rather than thematically:\n" +
		"-- multi_column_index_probe, multi_index_probe, wide_composite_key_probe and\n" +
		"-- namesake_probe. Each exists so that a reader of the catalog can be graded on\n" +
		"-- one thing -- key order in a multi-column index, several indexes on one table\n" +
		"-- including both spellings of uniqueness, a several-hundred-column table under a\n" +
		"-- composite key, and a table whose own name recurs in four of its ten column\n" +
		"-- names. That last one is what lets a single search pattern name a table and come\n" +
		"-- back with a handful of that table's columns: a table matched by its name alone\n" +
		"-- is answered with no columns at all, so no other table here can produce that\n" +
		"-- call. They are in every schema and database here, unlike archive's width,\n" +
		"-- because a test that names one of them should not also have to know which schema\n" +
		"-- it landed in.\n" +
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
	if table == seededTable {
		writeSeedRows(b, qualified, "+00")
	}
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
	if table == seededTable {
		writeSeedRows(b, table, "")
	}
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
