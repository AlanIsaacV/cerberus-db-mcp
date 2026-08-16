//go:build integration

// The sequence measured in this file is the one an agent walks to find a table
// and its columns in a schema it has never seen: list the databases, search the
// catalog for an approximate name, describe the one table that came back, then
// read it. What is graded is the sum of what those four calls cost the agent's
// context, because no single call being small says anything about a path made of
// four of them.
//
// It is the CI-runnable twin of TestSQLServerAgentSequenceCostOnTheWire, which
// measures the identical sequence against a real SQL Server that exists only
// behind a VPN. That test can never run in a job; this one runs on every push
// against deploy/compose.test.yaml, and the two report figures that are directly
// comparable because both are summed by the same sequenceMeter over the same four
// calls.
//
// What the two share — the meter, the ceiling, the bounds assertions, the
// key-column lookups, the namesake fixture contract — lives in
// mcp_integration_test.go with the rest of this package's shared test apparatus.
// What is missing from this file is the machinery that exists only because that
// one may not write a third party's identifiers into this repository: the
// fixture's names are checked in, so they are named as literals and the statement
// below is written out rather than assembled around quoting rules for a name
// nobody here is allowed to know.
package mcp

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
)

// TestAgentSequenceCostOnTheWire walks the four calls and fails if together they
// cost the agent more than agentSequenceCeiling.
//
// The row cap is raised to the shipped default rather than left at the low one CI
// configures. The bound this is about is the byte budget, and a cap of 50 cuts the
// catalog answers long before the budget is reached — the measurement would then be
// of the cap, and would fall as the fixture grew rather than rise.
func TestAgentSequenceCostOnTheWire(t *testing.T) {
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			rowCap := shippedRowCap(t)
			h := wideSchemaSearchHarness(t, engine, testIdentity(), func(s *db.Settings) { s.RowCap = rowCap })
			schema := describeFixtureSchema(engine)
			meter := &sequenceMeter{t: t}
			// Every per-call line names the engine because .github/workflows/ci.yml
			// greps them into the job summary, where the four lines this binary logs
			// per engine are otherwise indistinguishable from the other engine's four.
			// The name goes in the label rather than in [sequenceMeter.measure]'s
			// wording, which the SQL Server sequence shares and which has no engine to
			// name.
			onEngine := func(tool string) string { return tool + " on " + string(engine) }

			databases := meter.measure(onEngine("list_databases"), h.listDatabases(t))
			if names, ok := databases["databases"].([]any); !ok || len(names) == 0 {
				t.Errorf("list_databases returned %s, want the databases this login can see", jsonOf(t, databases["databases"]))
			}
			assertRowBoundIsOnTheWire(t, h, databases, "list_databases")

			search := meter.measure(onEngine("search_schema"), h.searchSchema(t, namesakePattern))
			assertNamesakeSearchFoundTheTableAndItsColumns(t, engine, search, schema)
			assertCatalogBoundsAreOnTheWire(t, h, search, "search_schema")

			described := meter.measure(onEngine("describe_table"), h.describeTable(t, namesakeTable, schema))
			assertCatalogBoundsAreOnTheWire(t, h, described, "describe_table")
			target := oneDescribedTable(t, described, schema, namesakeTable)

			// The statement is written from the description that just arrived and from the
			// pattern the agent already chose: the key column is the one describe_table
			// reported, and the projection is the columns the search matched. That is the
			// whole point of the sequence — the agent reads the columns it went looking
			// for and not the table.
			sel := namesakeSelectFromDescription(t, target)
			t.Logf("execute_query statement built from describe_table: %s", sel.statement)
			res := h.call(t, ToolExecuteQuery, map[string]any{"alias": h.alias, "statement": sel.statement})
			if res.IsError {
				t.Fatalf("the SELECT written from describe_table failed: %s", resultText(t, res))
			}
			query := meter.measure(onEngine("execute_query"), res)
			rows := assertTheRestrictionLeftRowsAndDroppedRows(t, sel, query)
			t.Logf("execute_query returned columns %s and %d rows: %s", jsonOf(t, query["columns"]), len(rows), jsonOf(t, query["rows"]))
			assertRowBoundIsOnTheWire(t, h, query, "execute_query")

			meter.reportAgainstTheCeiling(fmt.Sprintf("on %s at row cap %d", engine, rowCap))
		})
	}
}

// namesakeSelectFromDescription writes the fourth call's statement out of the
// third call's answer.
//
// The restriction is strict and its bound is a literal from the fixture's own
// seeded rows, which is what makes it grade anything: against a non-nullable key,
// "id >= 1" or "id >= MIN(id)" admits every row, so a run would show the key column
// is projectable and orderable while showing nothing about restricting on it. The
// limit is the whole seeded row count on purpose — it is larger than any answer the
// restriction can produce, so what cut the result is provably the predicate and not
// the bound.
//
// Nothing is quoted. Every fixture identifier is emitted unquoted by the generator
// and is legal bare on PostgreSQL and MySQL alike, so a name here that needs
// quoting is a fixture that changed rather than a case to escape around — which is
// why the names are checked rather than wrapped. That is also why the returned
// describedSelect carries no quoted spellings: only the SQL Server sequence, which
// reads a window of key values back, has anything to do with them.
func namesakeSelectFromDescription(t *testing.T, table map[string]any) describedSelect {
	t.Helper()
	qualified := plainIdentifier(t, stringField(t, table, "schema")) + "." + plainIdentifier(t, stringField(t, table, "table"))

	key := leadingKeyColumn(t, table)
	if key != namesakeKeyColumn {
		t.Fatalf("the description's leading key column is %q, want %q: %s", key, namesakeKeyColumn, jsonOf(t, table))
	}

	projected := []string{plainIdentifier(t, key)}
	columns, ok := table["columns"].([]any)
	if !ok {
		t.Fatalf("the description carries no columns array: %s", jsonOf(t, table))
	}
	for _, raw := range columns {
		column, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a described column is %s, want an object", jsonOf(t, raw))
		}
		name, _ := column["name"].(string)
		if strings.Contains(name, namesakePattern) {
			projected = append(projected, plainIdentifier(t, name))
		}
	}
	if got, want := len(projected)-1, len(namesakeMatchedColumns); got != want {
		t.Fatalf("describe_table listed %d columns carrying %q, want %d: %s", got, namesakePattern, want, jsonOf(t, table["columns"]))
	}

	return describedSelect{
		statement: "SELECT " + strings.Join(projected, ", ") +
			" FROM " + qualified +
			" WHERE " + key + " > " + strconv.Itoa(namesakeKeyFloor) +
			" ORDER BY " + key +
			" LIMIT " + strconv.Itoa(namesakeSeededRows),
		keyColumn: key,
	}
}

// plainIdentifier passes through a name that needs no quoting on either engine and
// fails the run on anything else, because the statement is assembled from values
// that arrived over the wire and an unexpected name there must stop the test rather
// than become part of a statement.
func plainIdentifier(t *testing.T, name string) string {
	t.Helper()
	if name == "" {
		t.Fatal("an empty identifier cannot go into a statement")
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		t.Fatalf("the identifier %q is not a bare lowercase fixture name; the fixture emits unquoted identifiers, so this is a change to tools/wide-schema rather than a name to quote", name)
	}
	return name
}

// assertTheRestrictionLeftRowsAndDroppedRows is acceptance criterion 2 and the
// half of it that stops the criterion being satisfiable by a tautology.
//
// Rows came back, so the measured total carries real result bytes rather than an
// empty result set. Fewer came back than the table holds, and they are exactly the
// keys above the floor in order, so the predicate is what removed the rest — a
// restriction that dropped nothing would be indistinguishable from no restriction
// at all, and the byte figure would be a figure about a different query.
func assertTheRestrictionLeftRowsAndDroppedRows(t *testing.T, sel describedSelect, query map[string]any) []any {
	t.Helper()
	rows, ok := query["rows"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("the SELECT written from describe_table returned no rows, so the sequence measured an empty result: %s", jsonOf(t, query))
	}
	if len(rows) >= namesakeSeededRows {
		t.Errorf("the restricted read returned %d of the %d seeded rows, so restricting on %q dropped nothing: %s",
			len(rows), namesakeSeededRows, sel.keyColumn, jsonOf(t, query["rows"]))
	}
	if query["truncated"] != false {
		t.Errorf("truncated = %#v, want false: with a handful of rows under the shipped row cap, anything else means the answer was cut by a bound rather than by the restriction", query["truncated"])
	}

	at := keyColumnIndex(t, query, sel.keyColumn)
	for i, raw := range rows {
		row, ok := raw.([]any)
		if !ok || at >= len(row) {
			t.Fatalf("row %d is %s, want a value for every column the result names", i, jsonOf(t, raw))
		}
		if got, want := jsonOf(t, row[at]), strconv.Itoa(namesakeKeyFloor+1+i); got != want {
			t.Errorf("row %d has %s = %s, want %s: the answer is not the seeded keys above %d in order",
				i, sel.keyColumn, got, want, namesakeKeyFloor)
		}
	}
	t.Logf("the restriction %s > %d left %d of the %d seeded rows", sel.keyColumn, namesakeKeyFloor, len(rows), namesakeSeededRows)
	return rows
}
