package db

import (
	"fmt"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// DescribeTable is the bounded catalog answer used to write a useful SELECT. Key
// and index detail is charged before columns because a short list of columns is
// still honest only when it retains the information that prevents a degenerate
// query.
type DescribeTable struct {
	Alias      string
	Engine     gate.Engine
	Decision   gate.Decision
	Tables     []TableDescription
	Truncation Truncation
	RowCap     int
	ByteBudget int
	Elapsed    time.Duration
}

type TableDescription struct {
	Schema     string
	Table      string
	Columns    []SchemaColumn
	PrimaryKey []string
	Indexes    []TableIndex
	// ColumnsTruncated is true when the shared describe result budget stopped
	// this table's column list short. Columns is then only a prefix of the
	// columns the catalog returned for this table, and an empty Columns slice
	// says nothing about whether the table has visible columns.
	//
	// The mark belongs on the entry where the cut lands rather than every entry
	// after it. describeTables returns a strict table-prefix at that point, so
	// no later empty list reaches the caller with the same ambiguous shape.
	ColumnsTruncated bool
}

type TableIndex struct {
	Name    string
	Columns []string
	Unique  bool
}

// describeResultBudget deliberately shares search_schema's half-wire budget.
// The SDK renders this value twice, so raising it independently would silently
// move describe_table past the surface's ceiling.
const describeResultBudget = SchemaResultBudget

// These over-estimates cover every describe-specific field that part 3 renders.
// describeTableBytes includes the per-entry columns_truncated marker, so that
// adding the ambiguity-resolving field does not reopen the wire-budget hole.
const (
	describeTableBytes  = 112
	describeColumnBytes = 48
	describeKeyBytes    = 8
	// {"name":"","columns":[],"unique":false}, is 40 bytes. The trailing
	// comma is charged too: it is present between index entries, and keeps this
	// per-entry cost an over-estimate for the final entry.
	describeIndexBytes = 40
)

type describeStatements struct{ columns, primaryKey, indexes string }

func describeFor(engine gate.Engine) (describeStatements, bool) {
	switch engine {
	case gate.PostgreSQL:
		return describeStatements{postgresDescribeColumns, postgresDescribePrimaryKey, postgresDescribeIndexes}, true
	case gate.MySQL:
		return describeStatements{mysqlDescribeColumns, mysqlDescribePrimaryKey, mysqlDescribeIndexes}, true
	case gate.SQLServer:
		return describeStatements{sqlServerDescribeColumns, sqlServerDescribePrimaryKey, sqlServerDescribeIndexes}, true
	default:
		return describeStatements{}, false
	}
}

func describeTables(engine gate.Engine, columns, keys, indexes [][]any, budget int) ([]TableDescription, bool, error) {
	out := make([]TableDescription, 0)
	byName := make(map[string]int)
	add := func(schema, table string) *TableDescription {
		key := schema + "\x00" + table
		if at, ok := byName[key]; ok {
			return &out[at]
		}
		byName[key] = len(out)
		out = append(out, TableDescription{Schema: schema, Table: table, Columns: make([]SchemaColumn, 0), PrimaryKey: make([]string, 0), Indexes: make([]TableIndex, 0)})
		return &out[len(out)-1]
	}
	for _, row := range columns {
		if len(row) != 5 {
			continue
		}
		schema, a := schemaText(row[0])
		table, b := schemaText(row[1])
		column, c := schemaText(row[2])
		dataType, d := schemaText(row[3])
		nullable, e := schemaBool(row[4])
		if !a || !b || !c || !d || !e {
			continue
		}
		add(schema, table).Columns = append(add(schema, table).Columns, SchemaColumn{Name: column, DataType: dataType, Nullable: nullable})
	}
	for _, row := range keys {
		if len(row) != 3 {
			continue
		}
		schema, a := schemaText(row[0])
		table, b := schemaText(row[1])
		column, c := schemaText(row[2])
		if !a || !b || !c {
			continue
		}
		add(schema, table).PrimaryKey = append(add(schema, table).PrimaryKey, column)
	}
	for _, row := range indexes {
		if len(row) != 5 {
			continue
		}
		schema, a := schemaText(row[0])
		table, b := schemaText(row[1])
		name, c := schemaText(row[2])
		column, d := schemaText(row[3])
		if !a || !b || !c || !d {
			continue
		}
		unique, ok := describeIndexUnique(engine, row[4])
		if !ok {
			return nil, false, fmt.Errorf("%s returned an unknown index uniqueness value", engine)
		}
		entry := add(schema, table)
		if len(entry.Indexes) == 0 || entry.Indexes[len(entry.Indexes)-1].Name != name {
			entry.Indexes = append(entry.Indexes, TableIndex{Name: name, Columns: make([]string, 0), Unique: unique})
		}
		index := &entry.Indexes[len(entry.Indexes)-1]
		if index.Unique != unique {
			return nil, false, fmt.Errorf("%s returned inconsistent uniqueness for index %q", engine, name)
		}
		index.Columns = append(index.Columns, column)
	}

	spent := 0
	for _, table := range out {
		cost := describeTableBytes + len(table.Schema) + len(table.Table)
		for _, column := range table.PrimaryKey {
			cost += describeKeyBytes + len(column)
		}
		for _, index := range table.Indexes {
			cost += describeIndexBytes + len(index.Name)
			for _, column := range index.Columns {
				cost += describeKeyBytes + len(column)
			}
		}
		if spent+cost > budget {
			return nil, false, fmt.Errorf("primary key and index detail exceed the describe result budget")
		}
		spent += cost
	}
	for i := range out {
		// The catalog's columns were retained only while the key and index reads
		// settled their fixed cost. Rebuild a charged prefix after those costs.
		original := out[i].Columns
		out[i].Columns = make([]SchemaColumn, 0, len(original))
		for _, column := range original {
			cost := describeColumnBytes + len(column.Name) + len(column.DataType)
			if spent+cost > budget {
				// A result cut inside this table must not leave later tables holding
				// their original, uncharged columns. Returning through this entry
				// makes the answer a strict prefix of the ordered catalog result;
				// the per-entry mark distinguishes its short (even empty) column
				// list from a genuine empty catalog list.
				out[i].ColumnsTruncated = true
				return out[:i+1], true, nil
			}
			spent += cost
			out[i].Columns = append(out[i].Columns, column)
		}
	}
	return out, false, nil
}

func describeIndexUnique(engine gate.Engine, value any) (bool, bool) {
	switch engine {
	case gate.PostgreSQL:
		v, ok := value.(bool)
		return v, ok
	case gate.MySQL:
		// statistics.non_unique is a BIGINT. go-sql-driver consequently returns a
		// typed integer here, not the textual 0/1 that Execute later renders.
		// MySQL alone uses the inverse polarity: zero means unique.
		v, ok := schemaBool(value)
		if !ok {
			return false, false
		}
		return !v, true
	case gate.SQLServer:
		// sys.indexes.is_unique is a BIT with ordinary (not MySQL-inverted)
		// polarity: one means unique.
		return schemaBool(value)
	}
	return false, false
}
