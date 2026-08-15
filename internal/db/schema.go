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
	// Truncated applies to the flat catalog rows before they are grouped. A true
	// value can therefore mean that a returned table has only part of its matching
	// column list; callers must report it rather than treating Tables as complete.
	Truncated bool
	RowCap    int
	Elapsed   time.Duration
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

// schemaTables groups the flat rows each catalog statement returns. All three
// statements order by schema, table and column, and preserving that order here
// keeps the answer deterministic without a second sorting path.
func schemaTables(rows [][]any) []SchemaTable {
	out := make([]SchemaTable, 0)
	byName := make(map[string]int)
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

		key := schema + "\x00" + table
		index, found := byName[key]
		if !found {
			index = len(out)
			byName[key] = index
			out = append(out, SchemaTable{Schema: schema, Table: table, Columns: make([]SchemaColumn, 0)})
		}
		// The table-match rows deliberately include every column, so that a table
		// whose name matches but none of whose columns do is still represented. Do
		// not include those non-matching columns in the grouped result.
		if !columnNameMatched {
			continue
		}
		column, ok := schemaText(row[2])
		if !ok {
			continue
		}
		dataType, ok := schemaText(row[3])
		if !ok {
			continue
		}
		nullable, ok := schemaBool(row[4])
		if !ok {
			continue
		}
		out[index].Columns = append(out[index].Columns, SchemaColumn{Name: column, DataType: dataType, Nullable: nullable})
	}
	return out
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
