//go:build integration

package db

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

func TestDescribeTableReturnsKeysAndIndexesInCatalogOrder(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			h.settings.RowCap = 300
			result, err := h.DescribeTable(context.Background(), h.alias, "multi_index_probe", "")
			if err != nil {
				t.Fatalf("DescribeTable(multi_index_probe) = %v", err)
			}
			if len(result.Tables) == 0 {
				t.Fatal("DescribeTable returned no table")
			}
			for _, table := range result.Tables {
				if len(table.Columns) != 8 || !slices.Equal(table.PrimaryKey, []string{"id"}) {
					t.Errorf("%s.%s columns/key = %d/%v, want 8/[id]", table.Schema, table.Table, len(table.Columns), table.PrimaryKey)
				}
				for _, column := range table.Columns {
					if column.Name == "" || column.DataType == "" {
						t.Errorf("%s.%s has incomplete column metadata %#v", table.Schema, table.Table, column)
					}
					wantNullable := column.Name == "note"
					if column.Nullable != wantNullable {
						t.Errorf("%s nullable = %v, want %v", column.Name, column.Nullable, wantNullable)
					}
				}
				if len(table.Indexes) != 3 {
					t.Errorf("%s.%s indexes = %#v, want three", table.Schema, table.Table, table.Indexes)
					continue
				}
				want := []TableIndex{{Name: "ix_multi_index_probe_title", Columns: []string{"title"}, Unique: false}, {Name: "uq_multi_index_probe_batch_code", Columns: []string{"batch_code"}, Unique: true}, {Name: "ux_multi_index_probe_serial_code", Columns: []string{"serial_code"}, Unique: true}}
				if !slices.EqualFunc(table.Indexes, want, func(a, b TableIndex) bool {
					return a.Name == b.Name && a.Unique == b.Unique && slices.Equal(a.Columns, b.Columns)
				}) {
					t.Errorf("%s.%s indexes = %#v, want %#v", table.Schema, table.Table, table.Indexes, want)
				}
			}
			ordered, err := h.DescribeTable(context.Background(), h.alias, "multi_column_index_probe", "")
			if err != nil || len(ordered.Tables) == 0 {
				t.Fatalf("DescribeTable(multi_column_index_probe) = %v, %v", ordered, err)
			}
			if !slices.Equal(ordered.Tables[0].Indexes[0].Columns, []string{"recorded_at", "title", "amount"}) {
				t.Errorf("index columns = %v", ordered.Tables[0].Indexes[0].Columns)
			}
		})
	}
}

func TestDescribeTableReportsEachTruncationCause(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			h.settings.RowCap = 300
			whole, err := h.DescribeTable(context.Background(), h.alias, "multi_index_probe", "")
			if err != nil || whole.Truncation != NoTruncation {
				t.Fatalf("complete describe = %#v, %v", whole, err)
			}
			h.settings.RowCap = 50
			rowCut, err := h.DescribeTable(context.Background(), h.alias, "wide_composite_key_probe", "")
			if err != nil || rowCut.Truncation != RowCapTruncation {
				t.Fatalf("row-capped describe = %#v, %v", rowCut, err)
			}
			h.settings.RowCap = 300
			budgetCut, err := h.DescribeTable(context.Background(), h.alias, "wide_composite_key_probe", "")
			if err != nil || budgetCut.Truncation != ByteBudgetTruncation {
				t.Fatalf("budget-capped describe = %#v, %v", budgetCut, err)
			}
		})
	}
}

func TestDescribeTableUnqualifiedPostgresReturnsEverySchema(t *testing.T) {
	h := schemaFixtureHarness(t, gate.PostgreSQL, fixtureDatabase)
	result, err := h.DescribeTable(context.Background(), h.alias, "multi_column_index_probe", "")
	if err != nil {
		t.Fatalf("DescribeTable = %v", err)
	}
	if len(result.Tables) != 2 || result.Tables[0].Schema != "atelier" || result.Tables[1].Schema != "harbor" {
		t.Errorf("unqualified result = %#v, want atelier and harbor", result.Tables)
	}
}

func TestDescribeTableUnqualifiedPostgresBoundsTheTwoSchemaWideResult(t *testing.T) {
	h := schemaFixtureHarness(t, gate.PostgreSQL, fixtureDatabase)
	// The fixture's two copies together have 514 catalog rows, so the shipped cap
	// leaves the byte budget as the bound this test exercises.
	h.settings.RowCap = 1000
	result, err := h.DescribeTable(context.Background(), h.alias, "wide_composite_key_probe", "")
	if err != nil {
		t.Fatalf("DescribeTable(wide_composite_key_probe) = %v", err)
	}
	if result.Truncation != ByteBudgetTruncation {
		t.Fatalf("truncation = %q, want byte budget", result.Truncation)
	}
	if got := describeResultCharge(result.Tables); got > result.ByteBudget {
		t.Errorf("returned descriptions charge %d bytes, want at most budget %d", got, result.ByteBudget)
	}
	if len(result.Tables) != 1 || result.Tables[0].Schema != "atelier" {
		t.Fatalf("bounded tables = %#v, want the catalog prefix ending in atelier", result.Tables)
	}
	table := result.Tables[0]
	if !table.ColumnsTruncated || len(table.Columns) == 0 || len(table.Columns) >= 257 {
		t.Errorf("atelier columns = %#v, want a marked, non-empty prefix", table.Columns)
	}
	if !slices.Equal(table.PrimaryKey, []string{"series_no", "area_code"}) || len(table.Indexes) != 1 {
		t.Errorf("bounded key/index detail = %#v, want the complete wide-table detail", table)
	}
}

func TestDescribeTableRefusesAnAliasWithoutDatabase(t *testing.T) {
	// PostgreSQL rejects a database-less alias while loading configuration: pgx is
	// bound to one database and omitting it would silently select the user name.
	// MySQL (and SQL Server, without a fixture) reaches DescribeTable's later
	// guard, so restricting this test is coverage of the reachable behaviour.
	for _, engine := range []gate.Engine{gate.MySQL} {
		t.Run(string(engine), func(t *testing.T) {
			base := schemaFixtureHarness(t, engine, fixtureDatabase)
			e := executorForEnvironment(t, aliasEnvironment("describeempty", base.spec, ""))
			_, err := e.DescribeTable(context.Background(), "describeempty", "multi_index_probe", "")
			var dbErr *Error
			if !errors.As(err, &dbErr) || dbErr.Kind != KindInvalidArgument {
				t.Fatalf("DescribeTable empty database = %v, want invalid argument", err)
			}
		})
	}
}

func TestDescribeTableKeepsKeyAndIndexesWhenColumnsAreBounded(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			result, err := h.DescribeTable(context.Background(), h.alias, "wide_composite_key_probe", "")
			if err != nil {
				t.Fatalf("DescribeTable(wide_composite_key_probe) = %v", err)
			}
			if len(result.Tables) == 0 {
				t.Fatal("DescribeTable returned no table")
			}
			table := result.Tables[0]
			if len(table.Columns) >= 257 || !slices.Equal(table.PrimaryKey, []string{"series_no", "area_code"}) || len(table.Indexes) != 1 {
				t.Errorf("bounded result = %#v", table)
			}
			if result.Truncation != RowCapTruncation {
				t.Errorf("truncation = %q, want row cap", result.Truncation)
			}
		})
	}
}

func TestDescribeTableBindsLiteralNames(t *testing.T) {
	for _, engine := range containerEngines {
		t.Run(string(engine), func(t *testing.T) {
			h := schemaFixtureHarness(t, engine, fixtureDatabase)
			result, err := h.DescribeTable(context.Background(), h.alias, "multi%_index'probe", "")
			if err != nil {
				t.Fatalf("DescribeTable literal name = %v", err)
			}
			if len(result.Tables) != 0 {
				t.Errorf("literal non-table matched %#v", result.Tables)
			}
		})
	}
}
