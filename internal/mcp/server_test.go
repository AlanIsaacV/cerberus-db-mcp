package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// No test in this package calls t.Parallel, and that is a rule rather than an
// oversight. [neutraliseForeignVariables] uses t.Setenv, which panics under
// t.Parallel, and the same constraint binds internal/db's suite for the same
// reason — see the comment on its own copy of this helper.

// neutraliseForeignVariables takes the variables internal/db refuses to start on
// out of play for one test.
//
// Every executor built here goes through db.New, which refuses to construct
// anything if PGSERVICE, PGSERVICEFILE or MSSQL_USE_EPA is set to a non-empty
// value and an alias uses the driver that reads it. That refusal is correct and
// this package must not work around it in production — but a suite whose result
// depends on whether the developer running it also uses psql is a suite that
// measures the wrong thing. Empty rather than unset, because empty is the state
// both drivers ignore and the state internal/db's own tolerance test pins.
func neutraliseForeignVariables(t *testing.T) {
	t.Helper()
	for _, name := range []string{"PGSERVICE", "PGSERVICEFILE", "MSSQL_USE_EPA"} {
		t.Setenv(name, "")
	}
}

// deadPort returns a TCP port with nothing behind it: bound, its number read,
// then released. A connection to it fails at the socket, which is what makes an
// executor usable in a test that must never reach a database.
func deadPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	_, portText, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", l.Addr(), err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port %q: %v", portText, err)
	}
	return port
}

// testSettings are the bounds the unreachable executors run under. The connect
// timeout is short because every one of these tests wants the dial to fail, not
// to be waited out.
func testSettings() db.Settings {
	return db.Settings{
		RowCap:         1000,
		QueryTimeout:   20 * time.Second,
		TimeoutGrace:   5 * time.Second,
		LockTimeout:    3 * time.Second,
		ConnectTimeout: 2 * time.Second,
		MaxConns:       2,
	}
}

// unreachableExecutor builds a real db.Executor whose aliases point at ports
// with nothing behind them.
//
// It is a real executor and a real gate, not a stand-in. db.New opens no
// connection and pings nothing, so the object under test is exactly the one the
// server holds in production — which is what makes a gate refusal observed
// through this executor the same refusal an agent would get. Anything that
// reaches a driver fails at the socket, and several tests below rely on that to
// tell "refused before a connection" from "refused after one".
func unreachableExecutor(t *testing.T, aliases ...db.AliasSpec) *db.Executor {
	t.Helper()
	neutraliseForeignVariables(t)
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	if len(aliases) == 0 {
		aliases = []db.AliasSpec{{
			Alias: "warehouse", Engine: gate.PostgreSQL, Host: "127.0.0.1", Port: deadPort(t),
			Database: "warehouse", User: "reader", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
		}}
	}
	e, err := db.New(g, &db.Config{Settings: testSettings(), Aliases: aliases})
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

// harness is one running server, a real MCP client connected to it, and the two
// log streams it writes.
type harness struct {
	session *sdk.ClientSession
	audit   *bytes.Buffer
	appLog  *bytes.Buffer
	url     string
}

// connect serves the package's own handler through httptest and connects the
// SDK's real Streamable HTTP client to it.
//
// The transport is the real one on both sides on purpose. A fake transport would
// let this suite assert on values that never crossed a wire, and every property
// these tests are for — that a schema is derived and reaches the client, that a
// refusal arrives as tool content rather than as a protocol error — is a
// property of what the client receives and not of what the handler returned.
func connect(t *testing.T, e *db.Executor, adjust ...func(*Deps)) *harness {
	t.Helper()
	h := &harness{audit: &bytes.Buffer{}, appLog: &bytes.Buffer{}}

	deps := Deps{
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: 5 * time.Second, Audit: AuditStdout},
		Executor: e,
		Log:      NewLogger(h.appLog),
		Audit:    NewAuditor(h.audit),
	}
	for _, a := range adjust {
		a(&deps)
	}

	srv, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)
	h.url = httpServer.URL + deps.Config.Path

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "cerberus-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             h.url,
		HTTPClient:           http.DefaultClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	h.session = session
	return h
}

// call runs a tool and fails the test if the call did not complete at the
// protocol level. A refusal is not a protocol failure — that distinction is what
// acceptance criterion 3 is about — so IsError is left for the caller to assert.
func (h *harness) call(t *testing.T, name string, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := h.session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s, %v) returned a protocol error: %v", name, args, err)
	}
	return res
}

// text is the tool result's first content block as a string.
func resultText(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("the tool result carries no content: %+v", res)
	}
	tc, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// structured decodes the result's structured content, which is what the SDK
// populates from the handler's typed output.
func structured(t *testing.T, res *sdk.CallToolResult) any {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured content %s: %v", raw, err)
	}
	return out
}

// auditEvents parses the audit stream written so far.
func (h *harness) auditEvents(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("the audit stream is not one JSON object per line: %v\n%s", err, line)
		}
		out = append(out, event)
	}
	return out
}

// TestToolsListIsExactlyTheTwoToolsWithDerivedSchemas is acceptance criterion 1.
//
// The schemas are asserted whole rather than by spot-checking a property, so
// that a field added to an input type — the shape a limit or a timeout argument
// would take — fails here instead of quietly becoming part of the contract.
func TestToolsListIsExactlyTheTwoToolsWithDerivedSchemas(t *testing.T) {
	h := connect(t, unreachableExecutor(t))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := h.session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := make(map[string]*sdk.Tool, len(list.Tools))
	for _, tool := range list.Tools {
		got[tool.Name] = tool
	}
	if len(got) != 2 || got[ToolListConnections] == nil || got[ToolExecuteQuery] == nil {
		names := make([]string, 0, len(list.Tools))
		for _, tool := range list.Tools {
			names = append(names, tool.Name)
		}
		t.Fatalf("tools/list = %v, want exactly %q and %q", names, ToolListConnections, ToolExecuteQuery)
	}

	// These are the schemas the SDK derived by reflection from ListConnectionsInput
	// and ExecuteQueryInput. Written out rather than recomputed from the same
	// types, because a test that derives its expectation the same way the code
	// does cannot notice the code changing.
	for name, wantJSON := range map[string]string{
		ToolListConnections: `{"additionalProperties":false,"type":"object"}`,
		ToolExecuteQuery: `{"additionalProperties":false,"type":"object",` +
			`"properties":{` +
			`"alias":{"type":"string","description":"which configured connection to run against, as named by list_connections"},` +
			`"statement":{"type":"string","description":"one read-only SQL statement in that connection's dialect; writes, DDL, permission changes and multiple statements are refused before they reach the database"}},` +
			`"required":["alias","statement"]}`,
	} {
		var want any
		if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
			t.Fatalf("the expectation for %q is not valid JSON: %v", name, err)
		}
		if !reflect.DeepEqual(got[name].InputSchema, want) {
			actual, _ := json.Marshal(got[name].InputSchema)
			t.Errorf("%q input schema =\n%s\nwant\n%s", name, actual, wantJSON)
		}
	}

	// A tool with no output schema would mean the SDK is not populating
	// StructuredContent, which is what a client reads the result out of.
	for _, name := range []string{ToolListConnections, ToolExecuteQuery} {
		if got[name].OutputSchema == nil {
			t.Errorf("%q has no output schema, so its result carries no structured content", name)
		}
	}
}

// TestListConnectionsReturnsAliasEngineAndBoundsAndNothingElse is acceptance
// criterion 6.
//
// The payload is compared whole against a literal, which is the only form of
// this assertion that fails when a field is *added*. Checking that the host is
// absent would pass forever against a payload that grew a "port" field instead.
func TestListConnectionsReturnsAliasEngineAndBoundsAndNothingElse(t *testing.T) {
	e := unreachableExecutor(t,
		db.AliasSpec{
			Alias: "warehouse", Engine: gate.PostgreSQL, Host: "db.internal.example", Port: deadPort(t),
			Database: "warehouse_prod", User: "reader", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
		},
		db.AliasSpec{
			Alias: "billing", Engine: gate.MySQL, Host: "mysql.internal.example", Port: deadPort(t),
			Database: "billing_prod", User: "readonly", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
		},
	)
	h := connect(t, e)

	res := h.call(t, ToolListConnections, nil)
	if res.IsError {
		t.Fatalf("list_connections failed: %s", resultText(t, res))
	}

	want := map[string]any{
		"connections": []any{
			map[string]any{
				"alias":         "warehouse",
				"engine":        "postgresql",
				"row_cap":       float64(testSettings().RowCap),
				"query_timeout": testSettings().QueryTimeout.String(),
			},
			map[string]any{
				"alias":         "billing",
				"engine":        "mysql",
				"row_cap":       float64(testSettings().RowCap),
				"query_timeout": testSettings().QueryTimeout.String(),
			},
		},
	}
	if got := structured(t, res); !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Errorf("list_connections payload =\n%s\nwant\n%s", gotJSON, wantJSON)
	}

	// The same assertion made against the raw text, because a client that reads
	// the content block rather than the structured content must not be told more.
	for _, forbidden := range []string{"db.internal.example", "mysql.internal.example", "reader", "readonly", "hunter2", "warehouse_prod", "billing_prod"} {
		if strings.Contains(resultText(t, res), forbidden) {
			t.Errorf("the content block contains %q", forbidden)
		}
	}
}

// TestRefusedStatementsArriveAsReadableToolErrors is acceptance criterion 3.
//
// Every case here runs against an executor whose only alias points at a dead
// port. That is what makes the assertion mean something: had the statement
// reached a driver, the answer would have been "the database is not reachable
// right now" rather than the gate's reason.
func TestRefusedStatementsArriveAsReadableToolErrors(t *testing.T) {
	h := connect(t, unreachableExecutor(t))

	for _, tt := range []struct {
		name      string
		statement string
		wantText  []string
	}{
		{
			name:      "a write",
			statement: "UPDATE invoices SET total = 0",
			wantText:  []string{"not provably a read", "forbidden-statement", "stmt-update"},
		},
		{
			name:      "a second statement",
			statement: "SELECT 1; SELECT 2",
			wantText:  []string{"not provably a read", "multiple-statements"},
		},
		{
			name:      "a write hidden in a CTE",
			statement: "WITH moved AS (INSERT INTO archive SELECT * FROM invoices RETURNING *) SELECT * FROM moved",
			wantText:  []string{"not provably a read", "forbidden-statement", "stmt-insert"},
		},
		{
			name:      "a permission change",
			statement: "GRANT SELECT ON invoices TO reader",
			wantText:  []string{"not provably a read", "forbidden-statement"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := h.call(t, ToolExecuteQuery, map[string]any{"alias": "warehouse", "statement": tt.statement})
			if !res.IsError {
				t.Fatalf("a refused statement returned a successful result: %+v", res)
			}
			text := resultText(t, res)
			for _, want := range tt.wantText {
				if !strings.Contains(text, want) {
					t.Errorf("the refusal text %q does not contain %q", text, want)
				}
			}
			if strings.Contains(text, "not reachable") {
				t.Errorf("the statement reached a driver: %q", text)
			}
		})
	}
}

// TestNeedsApprovalArrivesAsARefusalNamingThePendingRules is acceptance
// criterion 4's client-visible half. The other half — that no grant can be
// supplied from anywhere in this layer — is a property of the source and is
// checked in guards_test.go.
func TestNeedsApprovalArrivesAsARefusalNamingThePendingRules(t *testing.T) {
	h := connect(t, unreachableExecutor(t))

	// Two unknown functions, because Pending lists every ungranted obstacle and a
	// refusal that named only the first would make approval look like one step
	// when it is two.
	res := h.call(t, ToolExecuteQuery, map[string]any{
		"alias":     "warehouse",
		"statement": "SELECT cerberus_unknown_one(1), cerberus_unknown_two(2)",
	})
	if !res.IsError {
		t.Fatalf("a statement needing approval returned a successful result: %+v", res)
	}
	text := resultText(t, res)
	for _, want := range []string{
		"until a human grants",
		"pending",
		"function:cerberus_unknown_one",
		"function:cerberus_unknown_two",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal text %q does not contain %q", text, want)
		}
	}

	// The audit line carries the same ids, so the record says what a human would
	// have had to approve.
	events := h.auditEvents(t)
	last := events[len(events)-1]
	if last["verdict"] != string(gate.NeedsApproval) {
		t.Errorf("the audited verdict = %v, want %q", last["verdict"], gate.NeedsApproval)
	}
	pending, _ := json.Marshal(last["pending"])
	if want := `["function:cerberus_unknown_one","function:cerberus_unknown_two"]`; string(pending) != want {
		t.Errorf("the audited pending rules = %s, want %s", pending, want)
	}
}

// TestUnreachableDatabaseSaysNothingAboutTheConnection is the loopback half of
// acceptance criterion 5: the class that can be provoked without an engine.
// The classes that need a real engine to produce a real error are in
// mcp_integration_test.go.
func TestUnreachableDatabaseSaysNothingAboutTheConnection(t *testing.T) {
	port := deadPort(t)
	e := unreachableExecutor(t, db.AliasSpec{
		Alias: "warehouse", Engine: gate.PostgreSQL, Host: "127.0.0.1", Port: port,
		Database: "ledger", User: "reader", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
	})
	h := connect(t, e)

	res := h.call(t, ToolExecuteQuery, map[string]any{"alias": "warehouse", "statement": "SELECT 1"})
	if !res.IsError {
		t.Fatalf("a query to a dead port succeeded: %+v", res)
	}
	text := resultText(t, res)
	if text != "the database is not reachable right now" {
		t.Errorf("the client was told %q, which is not one of internal/db's fixed agent messages", text)
	}
	for _, forbidden := range []string{"ledger", "reader", "hunter2", "127.0.0.1", strconv.Itoa(port), "dial", "connection refused"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the client-visible text contains %q", forbidden)
		}
	}
	// The operator's side must not be empty, or the sanitisation was a discard.
	if !strings.Contains(h.appLog.String(), "database-unavailable") {
		t.Errorf("the application log does not record the failure: %s", h.appLog.String())
	}
}

// TestAnErrorThatIsNotADatabaseErrorSaysNothing covers the path taken when this
// layer has a defect: internal/db's errors are two-sided by construction, so
// anything else at the tool boundary is a bug here — and a bug must not be the
// route by which a Go error string, and whatever a wrapped driver put in it,
// reaches the agent.
func TestAnErrorThatIsNotADatabaseErrorSaysNothing(t *testing.T) {
	h := &harness{audit: &bytes.Buffer{}, appLog: &bytes.Buffer{}}
	srv, err := New(Deps{
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: time.Second, Audit: AuditStdout},
		Executor: unreachableExecutor(t),
		Log:      zerolog.New(h.appLog),
		Audit:    NewAuditor(h.audit),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	leaky := errors.New(`dial tcp 10.0.0.7:5432: connect: postgres://reader:hunter2@db.internal.example/ledger`)
	in := ExecuteQueryInput{Alias: "warehouse", Statement: "SELECT 1"}
	agentSide := srv.refuseOrFail(in, time.Millisecond, leaky).Error()

	if agentSide != internalFailure {
		t.Errorf("the agent was told %q, want the single internal message %q", agentSide, internalFailure)
	}
	for _, forbidden := range []string{"hunter2", "db.internal.example", "10.0.0.7", "5432", "ledger", "reader"} {
		if strings.Contains(agentSide, forbidden) {
			t.Errorf("the agent-facing message contains %q", forbidden)
		}
	}
	// The whole of it survives where the person debugging can see it.
	if !strings.Contains(h.appLog.String(), "hunter2") {
		t.Errorf("the application log dropped the error instead of recording it: %s", h.appLog.String())
	}
	// And the call is still audited, because a call that produced no audit line is
	// a call the log cannot account for.
	if events := h.auditEventsFor(t, ToolExecuteQuery); len(events) != 1 {
		t.Errorf("got %d audit events, want exactly 1", len(events))
	}
}

// auditEventsFor is auditEvents filtered to one tool.
func (h *harness) auditEventsFor(t *testing.T, tool string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range h.auditEvents(t) {
		if e["tool"] == tool {
			out = append(out, e)
		}
	}
	return out
}

// TestMiddlewareIsTheOnlySeamAndItWrapsTheEndpoint is the authentication seam.
// No token validation is built in this objective; what is built is the place one
// goes, and that place has to actually be in front of the handler.
func TestMiddlewareIsTheOnlySeamAndItWrapsTheEndpoint(t *testing.T) {
	e := unreachableExecutor(t)

	t.Run("the default is a no-op", func(t *testing.T) {
		h := connect(t, e)
		if res := h.call(t, ToolListConnections, nil); res.IsError {
			t.Fatalf("list_connections failed with no middleware: %s", resultText(t, res))
		}
	})

	t.Run("an injected middleware sees every request and can refuse", func(t *testing.T) {
		var calls int
		srv, err := New(Deps{
			Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: time.Second, Audit: AuditStdout},
			Executor: e,
			Audit:    NewAuditor(&bytes.Buffer{}),
			Middleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Header.Get("Authorization") == "" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r)
				})
			},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		httpServer := httptest.NewServer(srv.Handler())
		defer httpServer.Close()

		resp, err := http.Post(httpServer.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d: the middleware is not in front of the handler", resp.StatusCode, http.StatusUnauthorized)
		}
		if calls == 0 {
			t.Error("the middleware was never called")
		}
	})
}

// TestStatelessTransportRefusesGetAndDelete pins the SDK v1.7.0 behaviour this
// project accepted rather than escape-hatched: with Stateless set, the server
// ignores Mcp-Session-Id and answers 405 to GET and DELETE. It is written down
// as a test so that an SDK upgrade that changes it is a failure someone reads
// rather than a difference nobody notices.
func TestStatelessTransportRefusesGetAndDelete(t *testing.T) {
	h := connect(t, unreachableExecutor(t))
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, err := http.NewRequest(method, h.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Mcp-Session-Id", "a-session-this-server-does-not-keep")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want %d", method, h.url, resp.StatusCode, http.StatusMethodNotAllowed)
		}
	}
}

// TestALoopbackListenerRefusesAForeignHostHeader records a behaviour of the SDK
// that this objective inherits and that the deployment objective has to plan
// around.
//
// The SDK turns on DNS-rebinding protection by itself whenever the listener is on
// a loopback address, and answers 403 to any request whose Host header is not
// also loopback (streamable.go:324-334). This process binds loopback by default
// and is meant to be published through a Cloudflare Tunnel — and cloudflared
// forwards the public hostname in Host unless its ingress rule sets
// httpHostHeader. Left alone, that combination is a 403 on every call, from a
// protection nobody remembers turning on.
//
// It is not disabled here. A server with no authentication of its own should not
// also ship an off-switch for the one control it does have; what it should do is
// make the constraint findable, which is what this test is.
func TestALoopbackListenerRefusesAForeignHostHeader(t *testing.T) {
	h := connect(t, unreachableExecutor(t))

	req, err := http.NewRequest(http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Host = "cerberus.example.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d for a non-loopback Host header, want %d; if the SDK changed this, the tunnel's httpHostHeader note in this test is stale",
			resp.StatusCode, http.StatusForbidden)
	}
}

// TestNewRefusesToBuildWithoutItsGuarantees covers the construction mistakes
// that would leave a guarantee unenforced: no executor is a server with nothing
// to serve, no auditor is a server that answers calls without recording them,
// and an unusable configuration is one that must not become a listener.
func TestNewRefusesToBuildWithoutItsGuarantees(t *testing.T) {
	e := unreachableExecutor(t)
	valid := Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: time.Second, Audit: AuditStdout}

	for _, tt := range []struct {
		name string
		deps Deps
		want error
	}{
		{"no executor", Deps{Config: valid, Audit: NewAuditor(&bytes.Buffer{})}, ErrNoExecutor},
		{"no auditor", Deps{Config: valid, Executor: e}, ErrNoAuditor},
		{"an empty address", Deps{Config: Config{Path: "/mcp", ShutdownTimeout: time.Second, Audit: AuditStdout}, Executor: e, Audit: NewAuditor(&bytes.Buffer{})}, ErrInvalidVariable},
		{"an address with no host", Deps{Config: Config{Address: ":8080", Path: "/mcp", ShutdownTimeout: time.Second, Audit: AuditStdout}, Executor: e, Audit: NewAuditor(&bytes.Buffer{})}, ErrInvalidVariable},
		{"a relative path", Deps{Config: Config{Address: "127.0.0.1:0", Path: "mcp", ShutdownTimeout: time.Second, Audit: AuditStdout}, Executor: e, Audit: NewAuditor(&bytes.Buffer{})}, ErrInvalidVariable},
		// New is where this one has to be caught. Handler mounts the path on an
		// http.ServeMux, which reads it as a pattern: a space in it panics inside
		// mux.Handle, and Run reaches Handler only after the listener has bound
		// and logged that it is serving.
		{"a path that is a mux pattern", Deps{Config: Config{Address: "127.0.0.1:0", Path: "/mcp x", ShutdownTimeout: time.Second, Audit: AuditStdout}, Executor: e, Audit: NewAuditor(&bytes.Buffer{})}, ErrInvalidVariable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.deps)
			if !errors.Is(err, tt.want) {
				t.Errorf("New() = %v, want an error wrapping %v", err, tt.want)
			}
		})
	}
}
