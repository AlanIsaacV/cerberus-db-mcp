package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

func overlayFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "overlays", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return body
}

func writeOverlay(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
}

func TestDiffAgainstBaselineReportsEachChangeInItsOwnCategory(t *testing.T) {
	for _, tt := range []struct {
		name    string
		fixture string
		want    RulesetDiff
	}{
		{
			name:    "an overlay that changes nothing",
			fixture: "no-op.json",
			want: RulesetDiff{
				RulesAdded:               []RuleChange{},
				RulesRemoved:             []RuleChange{},
				RulesReplaced:            []RuleReplacement{},
				SafeFunctionsAdded:       map[gate.Engine][]string{},
				SafeFunctionsRemoved:     map[gate.Engine][]string{},
				NonFunctionKeywordsAdded: []string{},
			},
		},
		{
			name:    "an overlay that adds SQL Server user functions",
			fixture: "sqlserver-user-functions.json",
			want: RulesetDiff{
				RulesAdded:    []RuleChange{},
				RulesRemoved:  []RuleChange{},
				RulesReplaced: []RuleReplacement{},
				SafeFunctionsAdded: map[gate.Engine][]string{
					gate.SQLServer: {"dbo.fn_operacionesporcumplir", "dbo.fn_tblsaldosclientes"},
				},
				SafeFunctionsRemoved:     map[gate.Engine][]string{},
				NonFunctionKeywordsAdded: []string{},
			},
		},
		{
			name:    "an overlay that changes every category",
			fixture: "every-category.json",
			want: RulesetDiff{
				RulesAdded: []RuleChange{},
				RulesRemoved: []RuleChange{{ID: "read-show", RuleDefinition: RuleDefinition{
					Kind: "read_statement", Match: "show", Engines: []gate.Engine{gate.MySQL},
					Reason: "SHOW reports server and schema metadata",
				}}},
				RulesReplaced: []RuleReplacement{{
					ID: "fn-xp-regread",
					Baseline: RuleDefinition{
						Kind: "forbidden_function", Match: "xp_regread", Engines: gate.Engines(),
						Reason: "xp_regread reads the Windows registry",
					},
					InForce: RuleDefinition{
						Kind: "forbidden_function", Match: "xp_regread", Engines: []gate.Engine{gate.MySQL},
						Reason: "replaced by the overlay with a reason of its own",
					},
				}},
				SafeFunctionsAdded: map[gate.Engine][]string{
					gate.PostgreSQL: {"reporting.safe_total"},
				},
				SafeFunctionsRemoved: map[gate.Engine][]string{
					gate.SQLServer: {"parsename"},
				},
				NonFunctionKeywordsAdded: []string{"tablesample"},
				MaxStatementBytes:        &MaxStatementBytesChange{Baseline: 65536, InForce: 131072},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g, err := gate.New(filepath.Join("testdata", "overlays", tt.fixture))
			if err != nil {
				t.Fatalf("gate.New(%s) = %v", tt.fixture, err)
			}
			got, err := DiffAgainstBaseline(g.Ruleset())
			if err != nil {
				t.Fatalf("DiffAgainstBaseline = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("diff = %+v\nwant %+v", got, tt.want)
			}
			if got.Empty() != (tt.fixture == "no-op.json") {
				t.Fatalf("Empty() = %v for %s", got.Empty(), tt.fixture)
			}
		})
	}

	t.Run("a rule the overlay adds under a new ID is added, not replaced", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "overlay.json")
		writeOverlay(t, path, []byte(`{"version":1,"forbidden_functions":[{"id":"fn-overlay-only","match":"dbo.fn_never","reason":"added by the overlay"}]}`))
		g, err := gate.New(path)
		if err != nil {
			t.Fatalf("gate.New = %v", err)
		}
		got, err := DiffAgainstBaseline(g.Ruleset())
		if err != nil {
			t.Fatalf("DiffAgainstBaseline = %v", err)
		}
		want := []RuleChange{{ID: "fn-overlay-only", RuleDefinition: RuleDefinition{
			Kind: "forbidden_function", Match: "dbo.fn_never", Engines: gate.Engines(), Reason: "added by the overlay",
		}}}
		if !reflect.DeepEqual(got.RulesAdded, want) || len(got.RulesRemoved) != 0 || len(got.RulesReplaced) != 0 {
			t.Fatalf("diff = %+v, want only %+v added", got, want)
		}
	})
}

type logEvent struct {
	Level                  string          `json:"level"`
	Message                string          `json:"message"`
	Trigger                string          `json:"trigger"`
	OverlayPath            string          `json:"overlay_path"`
	Error                  string          `json:"error"`
	PreviousRulesetInForce *bool           `json:"previous_ruleset_in_force"`
	Diff                   *RulesetDiff    `json:"diff"`
	Exemptions             json.RawMessage `json:"exemptions"`
}

func reloadEvents(t *testing.T, captured testLog) []logEvent {
	t.Helper()
	var out []logEvent
	for _, line := range strings.Split(strings.TrimSpace(captured.String()), "\n") {
		if line == "" {
			continue
		}
		var e logEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if e.Trigger == gateLoadReload {
			out = append(out, e)
		}
	}
	return out
}

func hangUpAndWait(t *testing.T, captured testLog, runErr <-chan error) logEvent {
	t.Helper()
	before := len(reloadEvents(t, captured))
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("Run returned after SIGHUP: %v", err)
		default:
		}
		if events := reloadEvents(t, captured); len(events) > before {
			if len(events) != before+1 {
				t.Fatalf("one SIGHUP wrote %d reload events, want 1", len(events)-before)
			}
			return events[before]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reload event after SIGHUP: %s", captured.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSighupReloadsTheGateOverlayAndKeepsThePreviousRulesetOnRejection(t *testing.T) {
	neutraliseForeignVariables(t)
	path := filepath.Join(t.TempDir(), "overlay.json")
	userFunctions := overlayFixture(t, "sqlserver-user-functions.json")
	writeOverlay(t, path, userFunctions)

	g, err := gate.New(path)
	if err != nil {
		t.Fatalf("gate.New = %v", err)
	}
	e, err := db.New(g, &db.Config{Settings: testSettings(), Aliases: []db.AliasSpec{{
		Alias: "warehouse", Engine: gate.SQLServer, Host: "127.0.0.1", Port: deadPort(t),
		Database: "warehouse", User: "reader", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
	}}})
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}

	appLog := newLockedBuffer()
	ready := make(chan string, 1)
	srv, err := New(Deps{
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: 5 * time.Second, GateOverlay: path},
		Executor: e,
		Gate:     g,
		Log:      NewLogger(appLog).Level(zerolog.ErrorLevel),
		Audit:    NewAuditor(&bytes.Buffer{}),
		Ready:    func(addr string) { ready <- addr },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	select {
	case <-ready:
	case err := <-runErr:
		t.Fatalf("Run returned before it was serving: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Run never reported ready")
	}

	const userFunction = "SELECT * FROM dbo.fn_tblSaldosClientes(1)"
	const showTables = "SHOW TABLES"
	const write = "DROP TABLE t"
	if d := g.Validate(gate.SQLServer, userFunction, nil); d.Verdict != gate.Allow {
		t.Fatalf("under the user-function overlay %q = %s/%s, want allow", userFunction, d.Verdict, d.Reason)
	}

	t.Run("a valid change is applied and logged with its diff", func(t *testing.T) {
		writeOverlay(t, path, overlayFixture(t, "every-category.json"))
		event := hangUpAndWait(t, appLog, runErr)
		if event.Level != "info" || event.Message != "gate ruleset loaded: the overlay was applied on top of the baseline" || event.OverlayPath != path || event.Diff == nil {
			t.Fatalf("reload event = %+v, want an info load event that the error log level does not suppress, naming the path and carrying a diff", event)
		}
		want := map[gate.Engine][]string{gate.PostgreSQL: {"reporting.safe_total"}}
		if !reflect.DeepEqual(event.Diff.SafeFunctionsAdded, want) {
			t.Fatalf("logged safe functions added = %v, want %v", event.Diff.SafeFunctionsAdded, want)
		}
		if len(event.Exemptions) == 0 || string(event.Exemptions) == "null" {
			t.Fatalf("reload event carries no exemptions: %+v", event)
		}
		if d := g.Validate(gate.SQLServer, userFunction, nil); d.Verdict != gate.NeedsApproval {
			t.Fatalf("after reloading an overlay without the function %q = %s, want needs-approval", userFunction, d.Verdict)
		}
		if d := g.Validate(gate.MySQL, showTables, nil); d.Verdict == gate.Allow {
			t.Fatalf("after reloading an overlay that removes read-show %q = allow", showTables)
		}
	})

	writeOverlay(t, path, userFunctions)
	if event := hangUpAndWait(t, appLog, runErr); event.Level != "info" || event.Diff == nil {
		t.Fatalf("restoring the user-function overlay = %+v, want an info load event", event)
	}

	for _, tt := range []struct {
		name  string
		spoil func(t *testing.T)
	}{
		{"an invalid overlay is rejected", func(t *testing.T) { writeOverlay(t, path, []byte(`{"version":1,`)) }},
		{"a deleted overlay is rejected", func(t *testing.T) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove overlay: %v", err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := map[string]gate.Decision{
				userFunction: g.Validate(gate.SQLServer, userFunction, nil),
				write:        g.Validate(gate.SQLServer, write, nil),
			}
			tt.spoil(t)
			event := hangUpAndWait(t, appLog, runErr)
			if event.Level != "error" || event.OverlayPath != path || event.Error == "" {
				t.Fatalf("rejection event = %+v, want an error event with the path and the reason", event)
			}
			if event.PreviousRulesetInForce == nil || !*event.PreviousRulesetInForce || !strings.Contains(event.Message, "previous ruleset remains in force") {
				t.Fatalf("rejection event = %+v, want it to state that the previous ruleset remains in force", event)
			}
			if event.Diff != nil {
				t.Fatalf("rejection event carries a diff: %+v", event.Diff)
			}
			if d := g.Validate(gate.SQLServer, userFunction, nil); d.Verdict != gate.Allow || !reflect.DeepEqual(d, before[userFunction]) {
				t.Fatalf("after a rejected reload %q = %+v, want %+v", userFunction, d, before[userFunction])
			}
			if d := g.Validate(gate.SQLServer, write, nil); d.Verdict != gate.Deny || d.RuleID != before[write].RuleID {
				t.Fatalf("after a rejected reload %q = %+v, want %+v", write, d, before[write])
			}
		})
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run = %v, want a clean shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
