package db

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// TestEveryEngineHasASchemaSearchStatementTheGateAllows includes SQL Server even
// though this repository has no SQL Server fixture. A fixed statement that the
// gate refused would otherwise leave that engine with a tool that can never run.
func TestEveryEngineHasASchemaSearchStatementTheGateAllows(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			s, ok := schemaSearchFor(engine)
			if !ok || s.statement == "" {
				t.Fatalf("no schema search statement is defined for %s", engine)
			}
			if decision := g.Validate(engine, s.statement, nil); decision.Verdict != gate.Allow {
				t.Fatalf("the gate answers %q for %q (reason %s, rule %s, pending %v); the statement has to change, not the ruleset",
					decision.Verdict, s.statement, decision.Reason, decision.RuleID, decision.Pending)
			}
		})
	}
}

func TestSchemaPatternIsALiteralSubstring(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		want    string
		valid   bool
	}{
		{pattern: "arch", want: "%arch%", valid: true},
		{pattern: " ARCH ", want: "%ARCH%", valid: true},
		{pattern: "%_!", want: "%!%!_!!%", valid: true},
		{pattern: "a"},
		{pattern: "  "},
	} {
		got, ok := schemaPattern(tt.pattern)
		if ok != tt.valid || got != tt.want {
			t.Errorf("schemaPattern(%q) = (%q, %v), want (%q, %v)", tt.pattern, got, ok, tt.want, tt.valid)
		}
	}
}

func TestSchemaBoolAcceptsDriverBooleanEncodings(t *testing.T) {
	for _, tt := range []struct {
		value any
		want  bool
		ok    bool
	}{
		{value: true, want: true, ok: true},
		{value: "0", want: false, ok: true},
		{value: []byte("1"), want: true, ok: true},
		{value: int64(0), want: false, ok: true},
		{value: int64(1), want: true, ok: true},
		{value: uint8(0), want: false, ok: true},
		{value: uint8(1), want: true, ok: true},
		{value: int64(2), ok: false},
		{value: uint64(2), ok: false},
	} {
		got, ok := schemaBool(tt.value)
		if got != tt.want || ok != tt.ok {
			t.Errorf("schemaBool(%T(%v)) = (%v, %v), want (%v, %v)", tt.value, tt.value, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSearchSchemaRefusesShortPatternsBeforeAQuery(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	c := &schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: gate.PostgreSQL}}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"warehouse": c}}

	for _, pattern := range []string{"", " ", "a", " a "} {
		_, err := e.SearchSchema(context.Background(), "warehouse", pattern)
		var dbErr *Error
		if !errors.As(err, &dbErr) {
			t.Fatalf("SearchSchema(%q) = %v, want a *db.Error", pattern, err)
		}
		if dbErr.Kind != KindInvalidArgument || dbErr.Op != "search-schema" {
			t.Errorf("SearchSchema(%q) error = %+v, want an invalid-argument search-schema error", pattern, dbErr)
		}
		if strings.Contains(dbErr.Agent(), "not provably a read") {
			t.Errorf("SearchSchema(%q) agent error = %q, must not misdescribe the statement as not a read", pattern, dbErr.Agent())
		}
	}
	if c.queries != 0 {
		t.Errorf("short patterns reached query %d times", c.queries)
	}
}

func TestSearchSchemaRefusesAliasesWithoutADatabaseBeforeAQuery(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			c := &schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: engine}}
			e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"warehouse": c}}

			_, err := e.SearchSchema(context.Background(), "warehouse", "archive")
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("SearchSchema() = %v, want a *db.Error", err)
			}
			if dbErr.Kind != KindInvalidArgument || dbErr.Op != "search-schema" {
				t.Errorf("SearchSchema() error = %+v, want an invalid-argument search-schema error", dbErr)
			}
			if want := (&Error{Kind: KindInvalidArgument}).Agent(); dbErr.Agent() != want {
				t.Errorf("SearchSchema() agent error = %q, want %q", dbErr.Agent(), want)
			}
			if c.queries != 0 {
				t.Errorf("database-less alias reached query %d times", c.queries)
			}
		})
	}
}

// TestSearchSchemaShortPatternNeverReachesADriver is the end-to-end counterpart
// to the focused unit test above. With nothing listening, a query that escaped
// the validation would be an unavailable-database error rather than an
// invalid-argument error.
func TestSearchSchemaShortPatternNeverReachesADriver(t *testing.T) {
	e := executorOnDeadPorts(t)
	_, err := e.SearchSchema(context.Background(), "my", "a")
	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("SearchSchema() = %v, want a *db.Error", err)
	}
	if dbErr.Kind != KindInvalidArgument {
		t.Fatalf("SearchSchema() Kind = %q, want %q; a driver call would fail as unavailable", dbErr.Kind, KindInvalidArgument)
	}
}

// TestSearchSchemaIsRefusedWhenAnOverlayRemovesTheRuleThatAllowsIt is acceptance
// criterion 5's evidence that a statement the gate refuses never reaches a
// connection, in the shape
// [TestListDatabasesIsRefusedWhenAnOverlayRemovesTheRuleThatAllowsIt] already
// established for the other fixed statement this package owns.
//
// It is an ordinary unit test and not an integration one on purpose. The gate
// allows every engine's search statement — that is what
// [TestEveryEngineHasASchemaSearchStatementTheGateAllows] proves — so no server,
// however real, can make one of them be refused. A ruleset overlay is the only
// input that can, and an overlay behaves identically with and without a container.
// Moving this under the integration build tag would take the criterion's only
// evidence out of every run a developer makes.
//
// The overlay removes read-with, the rule the leading keyword of all three search
// statements depends on; it is what an operator tightening the ruleset against
// CTEs would do without realising this server's own catalog search is one. The
// refusal has to arrive instead of a dial failure — every alias here points at a
// dead port, so a KindUnavailable would mean the statement was carried to a
// connection with no rule allowing it.
//
// The two aliases together pin the ordering inside [Executor.SearchSchema]: the
// MySQL alias is bound to no database and is asked for a one-character pattern,
// and each of those is a refusal of its own, so a gate check moved after either
// one reports KindInvalidArgument here.
func TestSearchSchemaIsRefusedWhenAnOverlayRemovesTheRuleThatAllowsIt(t *testing.T) {
	neutraliseForeignVariables(t)
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"version": 1, "remove_rules": ["read-with"]}`), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	g, err := gate.New(overlay)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	cfg, err := LoadConfigFrom(deadPortEnvironment(t, map[string]gate.Engine{"pg": gate.PostgreSQL, "my": gate.MySQL}))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)

	for _, tt := range []struct {
		name    string
		alias   string
		pattern string
	}{
		{name: "an alias and a pattern the executor would otherwise accept", alias: pgAlias, pattern: "archive"},
		{name: "the gate answers before the argument refusals", alias: "my", pattern: "a"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := e.SearchSchema(context.Background(), tt.alias, tt.pattern)
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("SearchSchema() = %v, want a *db.Error", err)
			}
			if dbErr.Kind == KindUnavailable {
				t.Fatalf("the statement reached a connection with no rule allowing it: %s", dbErr.Detail)
			}
			if dbErr.Kind != KindRefused {
				t.Fatalf("Kind = %q, want the gate to have refused; detail: %s", dbErr.Kind, dbErr.Detail)
			}
			if dbErr.Op != "search-schema" {
				t.Errorf("Op = %q, so an operator's log names the wrong call", dbErr.Op)
			}
			if dbErr.Decision == nil {
				t.Fatal("the gate's decision is not carried on the error")
			}
			if dbErr.Detail != "" {
				t.Errorf("a refusal carries a driver detail, so something spoke to a driver: %s", dbErr.Detail)
			}
		})
	}
}

// TestSearchSchemaUsesTheOrdinaryStatementDeadline keeps catalog search on the
// same deadline path as Execute and ListDatabases. The server-side lock bound is
// connection configuration, exercised after a real schema search in the
// integration test; a fixed catalog statement cannot safely be made slow just
// to manufacture a timeout.
func TestSearchSchemaUsesTheOrdinaryStatementDeadline(t *testing.T) {
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			settings := pgSettings()
			c := &deadlineSchemaTestConn{schemaTestConn: schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: engine, Database: "OperationsWarehouse"}}}
			g, err := gate.New("")
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}
			e := &Executor{gate: g, settings: settings, conns: map[string]conn{"warehouse": c}}

			if _, err := e.SearchSchema(context.Background(), "warehouse", "archive"); err != nil {
				t.Fatalf("SearchSchema() = %v", err)
			}
			if c.deadline.IsZero() {
				t.Fatal("SearchSchema reached the driver without a deadline")
			}
			remaining := time.Until(c.deadline)
			want := settings.statementDeadline(engine)
			if remaining > want || remaining < want-time.Second {
				t.Errorf("SearchSchema driver deadline has %v remaining, want approximately %v", remaining, want)
			}
		})
	}
}

func TestSchemaTablesKeepsANameMatchedTableWithoutItsOtherColumns(t *testing.T) {
	rows := [][]any{
		{"atelier", "archive", "id", "bigint", false, true, false},
		{"atelier", "archive", "title", "character varying", false, true, false},
		{"harbor", "beacon", "measure", "numeric", true, false, true},
	}
	got, truncated := schemaTables(rows, SchemaResultBudget)
	if truncated {
		t.Error("three rows exhausted the byte budget")
	}
	// Both entries are complete, so neither marks itself: the empty list on archive is
	// the claim criterion 6 makes, and it is readable as that claim only here.
	want := []SchemaTable{
		{Schema: "atelier", Table: "archive", Columns: []SchemaColumn{}},
		{Schema: "harbor", Table: "beacon", Columns: []SchemaColumn{{Name: "measure", DataType: "numeric", Nullable: true}}},
	}
	if !slices.EqualFunc(got, want, func(a, b SchemaTable) bool {
		return a.Schema == b.Schema && a.Table == b.Table && a.ColumnsTruncated == b.ColumnsTruncated && slices.Equal(a.Columns, b.Columns)
	}) {
		t.Errorf("schemaTables() = %#v, want %#v", got, want)
	}
}

// TestTheByteBudgetMarksANameMatchedTableItCutTheColumnsOff is the boundary the
// marker exists for, and the one the charging rule cannot close. A table matched by
// its name is opened by a row whose column did not match, so its entry is added on
// its own; when the next row is the first column that did match and it no longer
// fits, the entry left behind is byte-for-byte the shape that means "this table
// matched by name and none of its columns did". Only ColumnsTruncated separates the
// two, and because a truncated answer is a prefix this lands on the last entry of
// every answer the budget stops there.
func TestTheByteBudgetMarksANameMatchedTableItCutTheColumnsOff(t *testing.T) {
	rows := [][]any{
		{"atelier", "archive", "id", "bigint", false, true, false},
		{"atelier", "archive", "archived_at", "timestamp", true, true, true},
	}
	// Room for the entry the first row opens, and not for the column the second
	// carries.
	budget := schemaTableBytes + len("atelier") + len("archive")
	got, truncated := schemaTables(rows, budget)
	if !truncated {
		t.Fatal("a matching column fitted a budget with room for the table entry alone")
	}
	if len(got) != 1 || len(got[0].Columns) != 0 {
		t.Fatalf("got %#v, want the archive entry with no column in it", got)
	}
	if !got[0].ColumnsTruncated {
		t.Error("the budget dropped a matching column and left an entry that claims none matched")
	}
}

// TestASharedColumnNameCannotReturnTheWholeCatalog is the defect this budget
// exists for, at the scale live verification found it: every table in the wide
// fixture carries one audit column, so a two-character pattern matches a few
// hundred flat rows — far under the row cap, which therefore never fires — and
// groups into an entry for every table in the database.
func TestASharedColumnNameCannotReturnTheWholeCatalog(t *testing.T) {
	const tables = 100
	rows := sharedColumnCatalogRows(tables)
	if cap := shippedRowCap(t); len(rows) >= cap {
		t.Fatalf("the fixture has %d rows and the shipped row cap is %d, so the row cap would truncate this and the budget would not be what is measured",
			len(rows), cap)
	}

	got, truncated := schemaTables(rows, SchemaResultBudget)
	if !truncated {
		t.Error("the budget did not report the answer as partial")
	}
	if len(got) >= tables {
		t.Errorf("the search returned %d of %d tables, which is the catalog", len(got), tables)
	}
	if len(got) == 0 {
		t.Error("the search returned no table at all, so the budget is too small to answer anything")
	}
	if size := wireBytes(t, got); size > SchemaResultBudget {
		t.Errorf("the result serialises to %d bytes, over the %d-byte budget the accounting is supposed to over-estimate", size, SchemaResultBudget)
	}
}

// TestTheByteBudgetLeavesTheWireFormUnderTheCeiling states the arithmetic the
// budget's value was chosen from, so that moving either number without the other
// fails here. The agent receives the result twice — as structured content and as
// the SDK's duplicate JSON text block — and 20 KB is what criterion 9 allows it.
func TestTheByteBudgetLeavesTheWireFormUnderTheCeiling(t *testing.T) {
	const (
		ceiling  = 20 << 10
		envelope = 1 << 10 // JSON-RPC framing, the result's own scalar fields, and margin
	)
	if worst := 2*SchemaResultBudget + envelope; worst > ceiling {
		t.Errorf("a full result reaches %d bytes on the wire, over the %d-byte ceiling", worst, ceiling)
	}
}

// TestTheByteBudgetStopsInsideAWideTable pins where truncation lands. The
// 256-column table is the case this surface exists for, so stopping at the table
// boundary would answer a search that matched it with nothing at all.
func TestTheByteBudgetStopsInsideAWideTable(t *testing.T) {
	rows := make([][]any, 0, 256)
	for i := range 256 {
		rows = append(rows, []any{"harbor", "archive", "measure_" + strconv.Itoa(i), "numeric", true, false, true})
	}

	// A budget that fits four columns and the table entry, and not the fifth.
	budget := schemaTableBytes + len("harbor") + len("archive") + 4*(schemaColumnBytes+len("measure_000")+len("numeric"))
	got, truncated := schemaTables(rows, budget)
	if !truncated {
		t.Fatal("256 columns fitted a four-column budget")
	}
	if len(got) != 1 {
		t.Fatalf("got %d tables, want the one table the rows describe", len(got))
	}
	if len(got[0].Columns) != 4 {
		t.Errorf("got %d columns, want the 4 the budget covers", len(got[0].Columns))
	}
	if !got[0].ColumnsTruncated {
		t.Error("the entry holding 4 of 256 columns does not say its column list is a prefix")
	}
}

// TestTheByteBudgetNeverOpensATableItCannotPutAColumnIn keeps the budget from
// manufacturing the one shape that means something else: an entry with no columns
// is how a table that matched by name alone is reported.
func TestTheByteBudgetNeverOpensATableItCannotPutAColumnIn(t *testing.T) {
	rows := [][]any{
		{"atelier", "beacon", "recorded_at", "timestamp", true, false, true},
		{"atelier", "canvas", "recorded_at", "timestamp", true, false, true},
	}
	budget := schemaTableBytes + len("atelier") + len("beacon") + schemaColumnBytes + len("recorded_at") + len("timestamp")
	got, truncated := schemaTables(rows, budget)
	if !truncated {
		t.Fatal("two tables fitted a one-table budget")
	}
	if len(got) != 1 || len(got[0].Columns) != 1 {
		t.Fatalf("got %#v, want only beacon with its one matching column", got)
	}
	// The cut fell on canvas's own entry, which was never opened, so beacon is a
	// complete statement about itself and must not be marked as anything else.
	if got[0].ColumnsTruncated {
		t.Error("beacon reports a cut column list although the budget stopped at the next table's entry")
	}
}

func TestSearchSchemaReportsTheBudgetItApplied(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	c := &catalogTestConn{
		schemaTestConn: schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: gate.PostgreSQL, Database: "testbed"}},
		rows:           sharedColumnCatalogRows(100),
	}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"warehouse": c}}

	search, err := e.SearchSchema(context.Background(), "warehouse", "re")
	if err != nil {
		t.Fatalf("SearchSchema() = %v", err)
	}
	if search.Truncation != ByteBudgetTruncation {
		t.Errorf("SearchSchema truncation = %q, want %q for a search the budget cut off", search.Truncation, ByteBudgetTruncation)
	}
	if search.ByteBudget != SchemaResultBudget {
		t.Errorf("ByteBudget = %d, want %d", search.ByteBudget, SchemaResultBudget)
	}
	if len(search.Tables) >= 100 {
		t.Errorf("SearchSchema returned %d tables, which is the whole catalog", len(search.Tables))
	}
}

func TestSearchSchemaLeavesASmallAnswerWhole(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	c := &catalogTestConn{
		schemaTestConn: schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: gate.PostgreSQL, Database: "testbed"}},
		rows: [][]any{
			{"atelier", "archive", "id", "bigint", false, true, false},
			{"atelier", "archive", "archived_at", "timestamp", true, true, true},
		},
	}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"warehouse": c}}

	search, err := e.SearchSchema(context.Background(), "warehouse", "archive")
	if err != nil {
		t.Fatalf("SearchSchema() = %v", err)
	}
	if search.Truncation != NoTruncation {
		t.Errorf("SearchSchema truncation = %q, want %q for one complete table", search.Truncation, NoTruncation)
	}
	if len(search.Tables) != 1 || len(search.Tables[0].Columns) != 1 {
		t.Errorf("Tables = %#v, want atelier.archive with its one matching column", search.Tables)
	}
}

// TestSearchSchemaNamesTheRowCap keeps the other half of the empty-column-list
// ambiguity visible without a container. A row cap cuts before schemaTables sees
// every flat row, so it cannot set ColumnsTruncated on the name-matched table it
// leaves behind; the top-level cause is the only truthful signal in that shape.
func TestSearchSchemaNamesTheRowCap(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	c := &catalogTestConn{
		schemaTestConn: schemaTestConn{alias: AliasSpec{Alias: "warehouse", Engine: gate.PostgreSQL, Database: "testbed"}},
		rows: [][]any{
			{"atelier", "archive", "id", "bigint", false, true, false},
		},
		truncated: true,
	}
	e := &Executor{gate: g, settings: pgSettings(), conns: map[string]conn{"warehouse": c}}

	search, err := e.SearchSchema(context.Background(), "warehouse", "archive")
	if err != nil {
		t.Fatalf("SearchSchema() = %v", err)
	}
	if search.Truncation != RowCapTruncation {
		t.Errorf("SearchSchema truncation = %q, want %q", search.Truncation, RowCapTruncation)
	}
	if len(search.Tables) != 1 || len(search.Tables[0].Columns) != 0 || search.Tables[0].ColumnsTruncated {
		t.Errorf("Tables = %#v, want a row-cap-cut name match with no byte-budget marker", search.Tables)
	}
}

// shippedRowCap is the cap a deployment that configures nothing runs under. The
// tests in this package use a much lower one, and the defect the budget closes is
// specifically that the shipped cap never fires on a search like this.
func shippedRowCap(t *testing.T) int {
	t.Helper()
	cfg, err := LoadConfigFrom(map[string]string{
		"CERBERUS_DB_ALIASES":             "warehouse",
		"CERBERUS_DB_WAREHOUSE_ENGINE":    "postgresql",
		"CERBERUS_DB_WAREHOUSE_HOST":      "db.internal.example",
		"CERBERUS_DB_WAREHOUSE_PORT":      "5432",
		"CERBERUS_DB_WAREHOUSE_DATABASES": "testbed",
		"CERBERUS_DB_WAREHOUSE_USER":      "reader",
		"CERBERUS_DB_WAREHOUSE_PASSWORD":  "not-in-any-error",
	})
	if err != nil {
		t.Fatalf("LoadConfigFrom() = %v", err)
	}
	return cfg.Settings.RowCap
}

// sharedColumnCatalogRows reproduces the wide fixture's shape: many narrow tables
// that all carry one audit column, which is what a two-character pattern matches
// in every one of them.
func sharedColumnCatalogRows(tables int) [][]any {
	rows := make([][]any, 0, tables*4)
	for i := range tables {
		table := "series_" + strconv.Itoa(i)
		rows = append(rows,
			[]any{"atelier", table, "recorded_at", "timestamp with time zone", true, false, true},
			[]any{"atelier", table, "released_at", "timestamp with time zone", true, false, true},
			[]any{"atelier", table, "region", "character varying", false, false, true},
		)
	}
	return rows
}

// wireBytes renders grouped tables the way internal/mcp does, so a test in this
// package can measure what the agent would receive without importing the package
// that imports this one.
func wireBytes(t *testing.T, tables []SchemaTable) int {
	t.Helper()
	type column struct {
		Name     string `json:"name"`
		DataType string `json:"data_type"`
		Nullable bool   `json:"nullable"`
	}
	type table struct {
		Schema           string   `json:"schema"`
		Table            string   `json:"table"`
		Columns          []column `json:"columns"`
		ColumnsTruncated bool     `json:"columns_truncated"`
	}
	out := make([]table, 0, len(tables))
	for _, source := range tables {
		entry := table{Schema: source.Schema, Table: source.Table, Columns: make([]column, 0, len(source.Columns)), ColumnsTruncated: source.ColumnsTruncated}
		for _, c := range source.Columns {
			entry.Columns = append(entry.Columns, column{Name: c.Name, DataType: c.DataType, Nullable: c.Nullable})
		}
		out = append(out, entry)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal tables: %v", err)
	}
	return len(encoded)
}

type schemaTestConn struct {
	alias   AliasSpec
	queries int
}

func (c *schemaTestConn) spec() AliasSpec { return c.alias }

func (c *schemaTestConn) query(_ context.Context, _ string, _ int, _ ...any) (*rowSet, error) {
	c.queries++
	return &rowSet{}, nil
}

// catalogTestConn answers with catalog rows a real statement would have returned,
// so that the budget can be exercised through the executor rather than only over
// the grouping function.
type catalogTestConn struct {
	schemaTestConn
	rows      [][]any
	truncated bool
}

func (c *catalogTestConn) query(_ context.Context, _ string, _ int, _ ...any) (*rowSet, error) {
	c.queries++
	return &rowSet{rows: c.rows, truncated: c.truncated}, nil
}

func (*schemaTestConn) close() {}

type deadlineSchemaTestConn struct {
	schemaTestConn
	deadline time.Time
}

func (c *deadlineSchemaTestConn) query(ctx context.Context, statement string, rowCap int, args ...any) (*rowSet, error) {
	var ok bool
	c.deadline, ok = ctx.Deadline()
	if !ok {
		c.deadline = time.Time{}
	}
	return c.schemaTestConn.query(ctx, statement, rowCap, args...)
}
