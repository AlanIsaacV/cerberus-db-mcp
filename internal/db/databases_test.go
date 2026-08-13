package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// TestEveryEngineHasADiscoveryStatementTheGateAllows is the half of the
// list_databases mechanism that can be established without a database, and it is
// the half that matters most: a statement the gate refuses is a tool that cannot
// work, and the fix for that is never a change to the ruleset.
//
// It asks the real gate, built from the baseline with no overlay, which is why this
// is worth more than reading the statements. HAS_DBACCESS looked like the right
// predicate for SQL Server until this test said needs-approval on it.
func TestEveryEngineHasADiscoveryStatementTheGateAllows(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	// Driven from the gate's own engine list, so a fourth engine arrives here as a
	// failure rather than as a tool that silently has nothing to run.
	for _, engine := range gate.Engines() {
		t.Run(string(engine), func(t *testing.T) {
			d, ok := discoveryFor(engine)
			if !ok {
				t.Fatalf("no discovery statement is defined for %s", engine)
			}
			if d.statement == "" {
				t.Fatal("the discovery statement is empty")
			}
			if len(d.exclude) == 0 {
				t.Error("no system databases are excluded, and all three engines have some")
			}
			decision := g.Validate(engine, d.statement, nil)
			if decision.Verdict != gate.Allow {
				t.Fatalf("the gate answers %q for %q (reason %s, rule %s, pending %v); the statement has to change, not the ruleset",
					decision.Verdict, d.statement, decision.Reason, decision.RuleID, decision.Pending)
			}
		})
	}
}

// TestDiscoveryNamesDropTheSystemDatabases covers the mapping from a result set to
// the answer, over the shapes the three drivers actually produce: pgx and the SQL
// Server driver decode a name to a string, and the MySQL driver hands back []byte
// for every column — which [normalise] converts only when the bytes are valid
// UTF-8.
func TestDiscoveryNamesDropTheSystemDatabases(t *testing.T) {
	for _, tt := range []struct {
		name   string
		engine gate.Engine
		rows   [][]any
		want   []string
	}{
		{
			name:   "postgresql keeps what is not a template and not postgres",
			engine: gate.PostgreSQL,
			rows:   [][]any{{"postgres"}, {"crm"}, {"template1"}, {"ledger"}},
			want:   []string{"crm", "ledger"},
		},
		{
			name:   "mysql reads a name that arrived as bytes",
			engine: gate.MySQL,
			rows:   [][]any{{[]byte("information_schema")}, {[]byte("testbed")}, {"sys"}, {"mysql"}, {"performance_schema"}},
			want:   []string{"testbed"},
		},
		{
			name:   "sql server keeps what is not one of the four",
			engine: gate.SQLServer,
			rows:   [][]any{{"master"}, {"model"}, {"msdb"}, {"tempdb"}, {"OperationsWarehouse"}},
			want:   []string{"OperationsWarehouse"},
		},
		{
			name:   "the exclusion is case-sensitive, like every other name comparison here",
			engine: gate.SQLServer,
			rows:   [][]any{{"master"}, {"MASTER"}},
			want:   []string{"MASTER"},
		},
		{
			name:   "an empty result is an empty answer and not an error",
			engine: gate.MySQL,
			rows:   nil,
			want:   []string{},
		},
		{
			name:   "a cell that is not text is dropped rather than rendered",
			engine: gate.MySQL,
			rows:   [][]any{{nil}, {42}, {"testbed"}, {}},
			want:   []string{"testbed"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, ok := discoveryFor(tt.engine)
			if !ok {
				t.Fatalf("no discovery statement is defined for %s", tt.engine)
			}
			if got := d.names(tt.rows); !slices.Equal(got, tt.want) {
				t.Errorf("names() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestListDatabasesOnAnUnknownAliasTouchesNothing pins the first step of the
// method being the same as [Executor.Execute]'s: the alias is resolved before
// anything else, and the error carries no driver detail because nothing spoke to a
// driver.
func TestListDatabasesOnAnUnknownAliasTouchesNothing(t *testing.T) {
	e := executorOnDeadPorts(t)
	_, err := e.ListDatabases(context.Background(), "no-such-alias")
	if !errors.Is(err, ErrUnknownAlias) {
		t.Fatalf("ListDatabases() = %v, want ErrUnknownAlias", err)
	}
	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("ListDatabases() = %v, want a *db.Error", err)
	}
	if dbErr.Detail != "" {
		t.Errorf("the error carries a driver detail, so something spoke to a driver: %s", dbErr.Detail)
	}
	if dbErr.Op != "list-databases" {
		t.Errorf("Op = %q, so an operator's log names the wrong call", dbErr.Op)
	}
}

// TestListDatabasesIsRefusedWhenAnOverlayRemovesTheRuleThatAllowsIt is the other
// side of the same claim: the statement goes through the gate rather than around
// it, so the gate can stop it.
//
// The overlay is the only input that can change what the gate allows, and removing
// read-select is what an operator would do while tightening the rules without
// realising this server's own discovery statement depends on it. The refusal has to
// arrive instead of a dial failure — the alias's port is dead, so a KindUnavailable
// here would mean the statement was executed without any rule allowing it.
func TestListDatabasesIsRefusedWhenAnOverlayRemovesTheRuleThatAllowsIt(t *testing.T) {
	neutraliseForeignVariables(t)
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"version": 1, "remove_rules": ["read-select"]}`), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	g, err := gate.New(overlay)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	cfg, err := LoadConfigFrom(deadPortEnvironment(t, map[string]gate.Engine{"pg": gate.PostgreSQL}))
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)

	_, err = e.ListDatabases(context.Background(), pgAlias)
	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("ListDatabases() = %v, want a *db.Error", err)
	}
	if dbErr.Kind != KindRefused {
		t.Fatalf("Kind = %q, want the gate to have refused; detail: %s", dbErr.Kind, dbErr.Detail)
	}
	if dbErr.Op != "list-databases" {
		t.Errorf("Op = %q, so an operator's log names the wrong call", dbErr.Op)
	}
	if dbErr.Decision == nil {
		t.Fatal("the gate's decision is not carried on the error")
	}
	if dbErr.Detail != "" {
		t.Errorf("a refusal carries a driver detail, so something spoke to a driver: %s", dbErr.Detail)
	}
}

// TestListDatabasesReachesTheDriverOnEveryEngine is as far as this can honestly be
// taken without a server, and it is the step that would otherwise be assumed: the
// statement passes the gate, so the call has to fail at the socket rather than
// short of it. The real answers are acceptance criteria 7 and 9, against
// containers.
//
// It is the same argument the control case in TestRefusedStatementsNeverReachADriver
// makes: a refusal arriving here would look like a pass and mean the statement never
// left the process.
func TestListDatabasesReachesTheDriverOnEveryEngine(t *testing.T) {
	e := executorOnDeadPorts(t)
	for _, alias := range []string{pgAlias, "my", "ms"} {
		t.Run(alias, func(t *testing.T) {
			_, err := e.ListDatabases(context.Background(), alias)
			var dbErr *Error
			if !errors.As(err, &dbErr) {
				t.Fatalf("ListDatabases() = %v, want a *db.Error", err)
			}
			if dbErr.Kind == KindRefused || dbErr.Kind == KindNeedsApproval {
				t.Fatalf("the gate stopped this package's own statement: %v", dbErr)
			}
			if dbErr.Kind != KindUnavailable && dbErr.Kind != KindTimeout {
				t.Fatalf("Kind = %q, want the connection to have failed; detail: %s", dbErr.Kind, dbErr.Detail)
			}
			if dbErr.Op != "list-databases" {
				t.Errorf("Op = %q, so an operator's log names the wrong call", dbErr.Op)
			}
			// An unreachable database says nothing about the credential, the host or
			// the port on the agent's side — the same guarantee execute_query gives,
			// which is what criterion 9 will check against a real refusal.
			spec := e.conns[alias].spec()
			for _, value := range []string{spec.Host, spec.User, spec.Password.reveal(), spec.Database} {
				if value != "" && strings.Contains(dbErr.Agent(), value) {
					t.Errorf("the agent-facing message contains a configured value: %s", dbErr.Agent())
				}
			}
		})
	}
}
