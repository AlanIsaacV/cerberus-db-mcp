package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

func TestEveryDescribeStatementTheGateAllows(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	for _, engine := range gate.Engines() {
		d, ok := describeFor(engine)
		if !ok {
			t.Fatalf("no describe statements for %s", engine)
		}
		for _, statement := range []string{d.columns, d.primaryKey, d.indexes} {
			if decision := g.Validate(engine, statement, nil); decision.Verdict != gate.Allow {
				t.Errorf("%s statement verdict = %s (%s/%s), want allow", engine, decision.Verdict, decision.Reason, decision.RuleID)
			}
		}
	}
}

func TestDescribeTablesSpendsKeyAndIndexesBeforeColumns(t *testing.T) {
	columns := [][]any{{"public", "wide", "first", "text", false}, {"public", "wide", "second", "text", false}}
	keys := [][]any{{"public", "wide", "first"}}
	indexes := [][]any{{"public", "wide", "ix_second", "second", false}}
	tables, cut, err := describeTables(gate.PostgreSQL, columns, keys, indexes, describeTableBytes+len("public")+len("wide")+describeKeyBytes+len("first")+describeIndexBytes+len("ix_second")+describeKeyBytes+len("second"))
	if err != nil || !cut {
		t.Fatalf("describeTables = (%v, %v, %v), want byte cut", tables, cut, err)
	}
	if len(tables) != 1 || len(tables[0].PrimaryKey) != 1 || len(tables[0].Indexes) != 1 || len(tables[0].Columns) != 0 {
		t.Fatalf("bounded description = %#v, want complete key/indexes and no columns", tables)
	}
}

func TestDescribeTablesBoundsColumnsAcrossEveryEntry(t *testing.T) {
	columns := [][]any{
		{"atelier", "wide", "first", "text", false},
		{"harbor", "wide", "first", "text", false},
		{"vault", "wide", "first", "text", false},
	}
	entryCost := func(schema string) int { return describeTableBytes + len(schema) + len("wide") }
	columnCost := describeColumnBytes + len("first") + len("text")
	budget := entryCost("atelier") + entryCost("harbor") + entryCost("vault") + columnCost

	tables, cut, err := describeTables(gate.PostgreSQL, columns, nil, nil, budget)
	if err != nil || !cut {
		t.Fatalf("describeTables = (%#v, %v, %v), want a multi-entry byte cut", tables, cut, err)
	}
	if len(tables) != 2 {
		t.Fatalf("bounded tables = %#v, want the charged prefix ending at harbor", tables)
	}
	if got := describeResultCharge(tables); got > budget {
		t.Errorf("returned descriptions charge %d bytes, want at most budget %d", got, budget)
	}
	if got := tables[0].Columns; len(got) != 1 || got[0].Name != "first" {
		t.Errorf("first entry columns = %#v, want its charged column", got)
	}
	if got := tables[1].Columns; len(got) != 0 {
		t.Errorf("cut entry columns = %#v, want no uncharged tail", got)
	}
}

func TestDescribeTablesMarksOnlyTheEntryWhereColumnsAreCut(t *testing.T) {
	columns := [][]any{
		{"atelier", "wide", "first", "text", false},
		{"harbor", "wide", "first", "text", false},
		{"harbor", "wide", "second", "text", false},
	}
	entryCost := 2 * (describeTableBytes + len("atelier") + len("wide"))
	// The second entry's schema has the same length as atelier, so its fixed
	// charge is identical. The first column fits; the next one is the cut.
	entryCost += len("harbor") - len("atelier")
	columnCost := describeColumnBytes + len("first") + len("text")
	budget := entryCost + 2*columnCost

	tables, cut, err := describeTables(gate.PostgreSQL, columns, nil, nil, budget)
	if err != nil || !cut {
		t.Fatalf("describeTables = (%#v, %v, %v), want a byte cut in harbor", tables, cut, err)
	}
	if len(tables) != 2 || tables[0].ColumnsTruncated || !tables[1].ColumnsTruncated {
		t.Fatalf("column truncation marks = %#v, want only harbor marked", tables)
	}
	if got := tables[1].Columns; len(got) != 1 || got[0].Name != "first" {
		t.Errorf("harbor columns = %#v, want the charged prefix", got)
	}
}

func describeResultCharge(tables []TableDescription) int {
	spent := 0
	for _, table := range tables {
		spent += describeTableBytes + len(table.Schema) + len(table.Table)
		for _, column := range table.PrimaryKey {
			spent += describeKeyBytes + len(column)
		}
		for _, index := range table.Indexes {
			spent += describeIndexBytes + len(index.Name)
			for _, column := range index.Columns {
				spent += describeKeyBytes + len(column)
			}
		}
		for _, column := range table.Columns {
			spent += describeColumnBytes + len(column.Name) + len(column.DataType)
		}
	}
	return spent
}

func TestDescribeIndexUniqueRejectsUnknownCatalogValues(t *testing.T) {
	for _, test := range []struct {
		engine gate.Engine
		value  any
	}{{gate.PostgreSQL, "true"}, {gate.MySQL, "2"}, {gate.SQLServer, int64(2)}} {
		if _, ok := describeIndexUnique(test.engine, test.value); ok {
			t.Errorf("%s accepted unknown uniqueness value %#v", test.engine, test.value)
		}
	}
}

func TestDescribeTablesRefusesToCutKeyOrIndexDetail(t *testing.T) {
	_, _, err := describeTables(gate.PostgreSQL, nil, [][]any{{"public", "wide", "first"}}, [][]any{{"public", "wide", "ix_second", "second", true}}, 1)
	if err == nil {
		t.Fatal("describeTables accepted a budget too small for key and index detail")
	}
}

func TestDescribeIndexUniqueAcceptsTypedMySQLNonUnique(t *testing.T) {
	for _, tt := range []struct {
		value any
		want  bool
	}{{int64(0), true}, {int64(1), false}, {uint8(0), true}, {uint8(1), false}} {
		got, ok := describeIndexUnique(gate.MySQL, tt.value)
		if !ok || got != tt.want {
			t.Errorf("describeIndexUnique(MySQL, %#v) = (%v, %v), want (%v, true)", tt.value, got, ok, tt.want)
		}
	}
}

func TestDescribeTableRefusalNeverQueriesAConnection(t *testing.T) {
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"version":1,"remove_rules":["read-with"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(overlay)
	if err != nil {
		t.Fatal(err)
	}
	c := &schemaTestConn{alias: AliasSpec{Alias: "pg", Engine: gate.PostgreSQL}}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"pg": c}}
	_, err = e.DescribeTable(context.Background(), "pg", "anything", "")
	var dbErr *Error
	if !errors.As(err, &dbErr) || dbErr.Kind != KindRefused {
		t.Fatalf("DescribeTable = %v, want gate refusal", err)
	}
	if c.queries != 0 {
		t.Fatalf("refused describe borrowed a connection %d times", c.queries)
	}
}

func TestDescribeTableNoDatabaseRefusesBeforeQuery(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatal(err)
	}
	c := &schemaTestConn{alias: AliasSpec{Alias: "pg", Engine: gate.PostgreSQL}}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"pg": c}}
	_, err = e.DescribeTable(context.Background(), "pg", "anything", "")
	var dbErr *Error
	if !errors.As(err, &dbErr) || dbErr.Kind != KindInvalidArgument {
		t.Fatalf("DescribeTable = %v, want no-database invalid argument", err)
	}
	if c.queries != 0 {
		t.Fatalf("no-database describe borrowed a connection %d times", c.queries)
	}
}
