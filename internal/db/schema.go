package db

import (
	"strings"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// SchemaSearch is the grouped answer to [Executor.SearchSchema]. It carries the
// same execution facts as [DatabaseList], while Tables contains only names and
// column metadata from the database the selected alias is bound to.
type SchemaSearch struct {
	Alias    string
	Engine   gate.Engine
	Decision gate.Decision
	Tables   []SchemaTable
	// Truncated is true when either bound stopped the answer short: the row cap on
	// the flat catalog rows before they are grouped, or [SchemaResultBudget] on the
	// grouped result. Either way a returned table can hold only part of its matching
	// column list, so callers must report it rather than treating Tables as
	// complete.
	Truncated bool
	RowCap    int
	// ByteBudget is the budget that applied, reported for the reason RowCap is: a
	// bound the agent is not told about is a bound it cannot calibrate a narrower
	// pattern against.
	ByteBudget int
	Elapsed    time.Duration
}

// SchemaTable is one matching table. Columns contains only columns whose names
// match the requested substring. A table that matched by its own name alone has
// an empty, non-nil Columns slice.
type SchemaTable struct {
	Schema  string
	Table   string
	Columns []SchemaColumn
}

// SchemaColumn is the metadata a schema search returns for a matching column.
type SchemaColumn struct {
	Name     string
	DataType string
	Nullable bool
}

// SchemaResultBudget is the most bytes one search result's tables may occupy. It
// is what makes "no pattern returns the whole catalog" true rather than nearly
// true, and it is a constant rather than a setting for the same reason.
//
// The row cap alone does not close that hole. Every table in a schema may share
// one column name — an audit timestamp, a tenant id — so a two-character pattern
// can match a few hundred flat catalog rows, far below the 1000-row default cap,
// and still group into one entry per table in the database. That is the catalog,
// arrived at from the other side. A byte bound is the only one of the three
// candidates that holds whatever the schema happens to look like: a longer
// minimum pattern does not (the shared column still matches), and a per-table
// column cap bounds columns while still returning every table.
//
// The value. What the agent receives is roughly twice what this package
// assembles, because internal/mcp returns a typed value and the SDK emits it both
// as structured content and as a duplicate JSON text block — see the gotcha
// recorded against [SchemaSearch] and internal/mcp's searchSchema. 8 KiB here is
// therefore about 16.5 KiB on the wire including the JSON-RPC envelope, under the
// 20 KB ceiling this surface is graded against with room for the accounting below
// being an estimate rather than a measurement.
//
// It is not configurable. The row cap is, because it trades completeness against
// load on somebody else's server and an operator owns that trade; this trades
// completeness against the agent's context, which is a property of the surface
// rather than of the deployment — and a bound an operator can raise is a bound
// that can be raised back past the point where the catalog fits inside it.
const SchemaResultBudget = 8 << 10

// The per-entry cost the budget is spent in, counted as the JSON internal/mcp
// renders these values into: 38 bytes of punctuation and field names for a table
// entry, 44 for a column, plus one separator each. Both are rounded up to 48, so
// the accounting over-estimates — a name carrying a few characters JSON has to
// escape still spends more budget than it costs on the wire, and the ceiling
// above keeps margin for the rest.
const (
	schemaTableBytes  = 48
	schemaColumnBytes = 48
)

// schemaSearch is one dialect's fixed catalog statement. The sole bound value is
// a LIKE pattern prepared by schemaPattern; its text is never incorporated into
// statement.
type schemaSearch struct {
	statement string
}

func schemaSearchFor(engine gate.Engine) (schemaSearch, bool) {
	switch engine {
	case gate.PostgreSQL:
		return schemaSearch{statement: postgresSchemaSearch}, true
	case gate.MySQL:
		return schemaSearch{statement: mysqlSchemaSearch}, true
	case gate.SQLServer:
		return schemaSearch{statement: sqlServerSchemaSearch}, true
	default:
		return schemaSearch{}, false
	}
}

// schemaPattern validates a plain substring and turns it into one literal LIKE
// pattern. ! is the constant escape character in all three statements, so a
// caller cannot use %, _, or ! to widen the search beyond its literal text.
func schemaPattern(pattern string) (string, bool) {
	pattern = strings.TrimSpace(pattern)
	if len([]rune(pattern)) < 2 {
		return "", false
	}
	escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(pattern)
	return "%" + escaped + "%", true
}

// schemaTables groups the flat rows each catalog statement returns, spending at
// most budget bytes on the result and reporting whether the budget stopped it.
// All three statements order by schema, table and column, and preserving that
// order here keeps the answer deterministic without a second sorting path.
//
// Where the budget bites is decided rather than incidental:
//
//   - It stops the whole grouping, so the answer is a prefix of the ordered rows.
//     Skipping the entry that did not fit and continuing with later smaller ones
//     would return a set no ordering explains.
//   - A table entry and the column that opens it are charged together, so a table
//     is never added without room for a column in it. An entry with no columns is
//     the documented shape of a table that matched by name alone, and the budget
//     must not manufacture that claim about a table whose columns it dropped.
//   - Within a table it stops at a column, not at the table boundary. Stopping at
//     the boundary would return nothing at all for a search whose first matching
//     table is wide — the 256-column case this surface exists for — and a partial
//     column list under Truncated is the same contract the row cap already has.
func schemaTables(rows [][]any, budget int) ([]SchemaTable, bool) {
	out := make([]SchemaTable, 0)
	byName := make(map[string]int)
	spent := 0
	for _, row := range rows {
		if len(row) != 7 {
			continue
		}
		schema, ok := schemaText(row[0])
		if !ok {
			continue
		}
		table, ok := schemaText(row[1])
		if !ok {
			continue
		}
		tableNameMatched, ok := schemaBool(row[5])
		if !ok {
			continue
		}
		columnNameMatched, ok := schemaBool(row[6])
		if !ok {
			continue
		}
		if !tableNameMatched && !columnNameMatched {
			continue
		}

		// The column is read before anything is added to the result, so that the two
		// costs can be charged together below. The table-match rows deliberately
		// include every column of a matching table, so that a table whose name
		// matches but none of whose columns do is still represented; those
		// non-matching columns must not enter the result.
		var column SchemaColumn
		hasColumn := false
		if columnNameMatched {
			column, hasColumn = schemaColumnOf(row)
			if !hasColumn && !tableNameMatched {
				// The only thing that matched was a column this driver's values did not
				// decode, so the row says nothing about a table.
				continue
			}
		}

		key := schema + "\x00" + table
		index, found := byName[key]

		cost := 0
		if !found {
			cost += schemaTableBytes + len(schema) + len(table)
		}
		if hasColumn {
			cost += schemaColumnBytes + len(column.Name) + len(column.DataType)
		}
		if spent+cost > budget {
			return out, true
		}
		spent += cost

		if !found {
			index = len(out)
			byName[key] = index
			out = append(out, SchemaTable{Schema: schema, Table: table, Columns: make([]SchemaColumn, 0)})
		}
		if hasColumn {
			out[index].Columns = append(out[index].Columns, column)
		}
	}
	return out, false
}

func schemaColumnOf(row []any) (SchemaColumn, bool) {
	name, ok := schemaText(row[2])
	if !ok {
		return SchemaColumn{}, false
	}
	dataType, ok := schemaText(row[3])
	if !ok {
		return SchemaColumn{}, false
	}
	nullable, ok := schemaBool(row[4])
	if !ok {
		return SchemaColumn{}, false
	}
	return SchemaColumn{Name: name, DataType: dataType, Nullable: nullable}, true
}

func schemaText(v any) (string, bool) {
	switch value := v.(type) {
	case string:
		return value, true
	case []byte:
		return string(value), true
	default:
		return "", false
	}
}

func schemaBool(v any) (bool, bool) {
	switch value := v.(type) {
	case bool:
		return value, true
	case int:
		return schemaIntegerBool(int64(value))
	case int8:
		return schemaIntegerBool(int64(value))
	case int16:
		return schemaIntegerBool(int64(value))
	case int32:
		return schemaIntegerBool(int64(value))
	case int64:
		return schemaIntegerBool(value)
	case uint:
		return schemaUnsignedIntegerBool(uint64(value))
	case uint8:
		return schemaUnsignedIntegerBool(uint64(value))
	case uint16:
		return schemaUnsignedIntegerBool(uint64(value))
	case uint32:
		return schemaUnsignedIntegerBool(uint64(value))
	case uint64:
		return schemaUnsignedIntegerBool(value)
	case string:
		switch strings.ToLower(value) {
		case "1", "true", "yes":
			return true, true
		case "0", "false", "no":
			return false, true
		}
	case []byte:
		return schemaBool(string(value))
	}
	return false, false
}

func schemaIntegerBool(value int64) (bool, bool) {
	if value == 0 {
		return false, true
	}
	if value == 1 {
		return true, true
	}
	return false, false
}

func schemaUnsignedIntegerBool(value uint64) (bool, bool) {
	if value == 0 {
		return false, true
	}
	if value == 1 {
		return true, true
	}
	return false, false
}
