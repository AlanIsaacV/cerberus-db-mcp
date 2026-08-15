package db

import (
	"context"
	"errors"
	"slices"
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
	got := schemaTables(rows)
	want := []SchemaTable{
		{Schema: "atelier", Table: "archive", Columns: []SchemaColumn{}},
		{Schema: "harbor", Table: "beacon", Columns: []SchemaColumn{{Name: "measure", DataType: "numeric", Nullable: true}}},
	}
	if !slices.EqualFunc(got, want, func(a, b SchemaTable) bool {
		return a.Schema == b.Schema && a.Table == b.Table && slices.Equal(a.Columns, b.Columns)
	}) {
		t.Errorf("schemaTables() = %#v, want %#v", got, want)
	}
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
