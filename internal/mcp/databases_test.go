package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// discoveryAlias is the spec the tests below run list_databases against: a
// PostgreSQL alias whose port has nothing behind it, with every value that must
// never reach the agent set to something recognisable.
//
// The dead port is what makes these tests mean anything. The gate allows
// internal/db's discovery statement — its own suite proves that against the real
// baseline — so a call here gets as far as the socket and fails there, which is the
// closest a test with no database can come to the real path. A refusal arriving
// instead would say the statement never left the process.
func discoveryAlias(t *testing.T) db.AliasSpec {
	t.Helper()
	return db.AliasSpec{
		Alias: "warehouse", Engine: gate.PostgreSQL,
		Host: "db.internal.example", Port: deadPort(t),
		Database: "warehouse_prod", User: "reader", Password: db.Secret("hunter2"),
		TLS: db.TLSDisable,
	}
}

// assertNoConfiguredValues is the no-leak check over one agent-visible string, by
// value rather than by pattern so that a value nobody thought to look for is still
// caught. It is the loopback twin of engineHarness.assertNothingAboutTheConnection
// in mcp_integration_test.go, which does the same against a real engine's errors.
func assertNoConfiguredValues(t *testing.T, spec db.AliasSpec, text string) {
	t.Helper()
	for label, value := range map[string]string{
		"the host":          spec.Host,
		"the port":          strconv.Itoa(spec.Port),
		"the database name": spec.Database,
		"the username":      spec.User,
		"the password":      string(spec.Password),
	} {
		if value == "" {
			continue
		}
		if strings.Contains(text, value) {
			t.Errorf("the agent-visible text contains %s (%q): %q", label, value, text)
		}
	}
}

// TestListDatabasesIsAuditedWithItsCallerTheSubjectAndTheAlias is acceptance
// criterion 10's audit half.
//
// The call fails, and that is what makes it the useful case: the audit line for a
// call that reached nothing is the only record that it happened, and it has to carry
// the same identity, subject and alias a successful one would. The successful shape
// against a real engine is in mcp_integration_test.go.
func TestListDatabasesIsAuditedWithItsCallerTheSubjectAndTheAlias(t *testing.T) {
	spec := discoveryAlias(t)
	want := testIdentity()
	h := connect(t, unreachableExecutor(t, spec), admittingEveryRequestAs(want))

	res := h.call(t, ToolListDatabases, map[string]any{"alias": spec.Alias})
	if !res.IsError {
		t.Fatalf("list_databases against a dead port succeeded: %+v", res)
	}

	events := h.auditEventsFor(t, ToolListDatabases)
	if len(events) != 1 {
		t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
	}
	for field, wantValue := range map[string]any{
		"tool":     ToolListDatabases,
		"identity": want.Email,
		"subject":  want.Subject,
		"alias":    spec.Alias,
		"engine":   string(gate.PostgreSQL),
		"outcome":  string(OutcomeFailed),
		// The gate is not in this error, and internal/db's step order says why that
		// means it allowed the statement: the alias resolved, so the gate had already
		// answered before the connection was borrowed. Recording it is what lets the
		// stream answer "was this permitted" for a discovery call that failed.
		"verdict":    string(gate.Allow),
		"error_kind": string(db.KindUnavailable),
		// No statement: this tool's text is internal/db's constant rather than the
		// agent's, and the tool name is what identifies it.
		"statement": "",
	} {
		if got := events[0][field]; got != wantValue {
			t.Errorf("%s = %#v, want %#v", field, got, wantValue)
		}
	}

	// And the agent was told one of internal/db's fixed sentences, with none of the
	// alias's own values in it.
	text := resultText(t, res)
	if want := (&db.Error{Kind: db.KindUnavailable}).Agent(); text != want {
		t.Errorf("the client was told %q, want internal/db's fixed message %q", text, want)
	}
	assertNoConfiguredValues(t, spec, text)
	// The operator's side must not be empty, or the sanitisation was a discard.
	if !strings.Contains(h.appLog.String(), string(db.KindUnavailable)) {
		t.Errorf("the application log does not record the failure:\n%s", h.appLog.String())
	}
}

// TestListDatabasesOnAnAliasThatIsNotConfiguredIsRefusedAndAudited is the answer an
// agent gets when it does the one thing this tool's description exists to prevent:
// takes a name out of a list_databases result and passes it back as an alias.
//
// On PostgreSQL that is not a hypothetical — a cluster database that is not on its
// alias's configured list has no connection and no alias — so what the agent is told
// is worth pinning: internal/db's unknown-alias sentence, audited, with no verdict,
// because nothing was gated and nothing was opened.
func TestListDatabasesOnAnAliasThatIsNotConfiguredIsRefusedAndAudited(t *testing.T) {
	spec := discoveryAlias(t)
	h := connect(t, unreachableExecutor(t, spec), admittingEveryRequestAs(testIdentity()))

	res := h.call(t, ToolListDatabases, map[string]any{"alias": "some_database_the_list_returned"})
	if !res.IsError {
		t.Fatalf("list_databases on an unconfigured alias succeeded: %+v", res)
	}
	if got, want := resultText(t, res), (&db.Error{Kind: db.KindUnknownAlias}).Agent(); got != want {
		t.Errorf("the client was told %q, want internal/db's fixed message %q", got, want)
	}

	events := h.auditEventsFor(t, ToolListDatabases)
	if len(events) != 1 {
		t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
	}
	for field, wantValue := range map[string]any{
		"identity":   testIdentity().Email,
		"alias":      "some_database_the_list_returned",
		"outcome":    string(OutcomeFailed),
		"error_kind": string(db.KindUnknownAlias),
		// Empty rather than allowed: the alias never resolved, so the gate was never
		// asked, and claiming a verdict here would put an approval in the record for a
		// statement that was never validated.
		"verdict": "",
	} {
		if got := events[0][field]; got != wantValue {
			t.Errorf("%s = %#v, want %#v", field, got, wantValue)
		}
	}
}

// TestAListDatabasesCallThatFailsForLackOfPermissionIsAuditedAndSaysNothingElse is
// acceptance criterion 9 at this boundary.
//
// The criterion's own verification is a low-privilege role on the real PostgreSQL
// container, and that is internal/db's to run: permission-denied is a class only an
// engine can produce, and no engine reachable from this package's own suite will
// produce it for a metadata statement — pg_database is readable by everyone and
// MySQL's SHOW DATABASES filters silently instead of failing. What is left for this
// layer, and what is checked here, is the half that is this layer's regardless of
// which engine raised it: the reduction of that error to what the agent may read,
// and the audit line for it.
//
// So the error is a [db.Error] built with the exported fields internal/db fills, and
// nothing about it is faked twice over: the sentence the agent gets is read out of
// internal/db's own allowlist rather than transcribed here, and the code under test
// is the real handler path — [Server.refuseOrFail], which the ADR behind
// [agentError] requires every failing tool to go through.
func TestAListDatabasesCallThatFailsForLackOfPermissionIsAuditedAndSaysNothingElse(t *testing.T) {
	spec := discoveryAlias(t)
	h := &harness{audit: &bytes.Buffer{}, appLog: &bytes.Buffer{}}
	srv, err := New(Deps{
		Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: time.Second},
		Executor: unreachableExecutor(t, spec),
		Log:      NewLogger(h.appLog),
		Audit:    NewAuditor(h.audit),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Detail is the operator-facing side, and it is loaded with every value the agent
	// must not see — which is what a real engine puts there when it refuses a
	// metadata read: the object, the login it refused, and whatever the driver
	// appended about the connection it was on.
	denied := &db.Error{
		Op:     "list-databases",
		Alias:  spec.Alias,
		Engine: spec.Engine,
		Kind:   db.KindPermissionDenied,
		Detail: `ERROR: permission denied for table pg_database (SQLSTATE 42501) on ` +
			spec.Host + ":" + strconv.Itoa(spec.Port) + "/" + spec.Database +
			" as " + spec.User + ":" + string(spec.Password),
	}

	id := testIdentity()
	ctx := auth.WithIdentity(context.Background(), id)
	call := attempt{tool: ToolListDatabases, alias: spec.Alias}
	agentSide := srv.refuseOrFail(ctx, call, 3*time.Millisecond, denied).Error()

	if want := (&db.Error{Kind: db.KindPermissionDenied}).Agent(); agentSide != want {
		t.Errorf("the agent was told %q, want internal/db's fixed message %q", agentSide, want)
	}
	assertNoConfiguredValues(t, spec, agentSide)

	events := h.auditEventsFor(t, ToolListDatabases)
	if len(events) != 1 {
		t.Fatalf("got %d audit events for one failed call:\n%s", len(events), h.audit.String())
	}
	for field, wantValue := range map[string]any{
		"tool":       ToolListDatabases,
		"identity":   id.Email,
		"subject":    id.Subject,
		"alias":      spec.Alias,
		"engine":     string(gate.PostgreSQL),
		"outcome":    string(OutcomeFailed),
		"verdict":    string(gate.Allow),
		"error_kind": string(db.KindPermissionDenied),
	} {
		if got := events[0][field]; got != wantValue {
			t.Errorf("%s = %#v, want %#v", field, got, wantValue)
		}
	}
	// The audit stream is the one that may be shipped somewhere less trusted, so the
	// engine's words must not be in it either — only the class.
	if strings.Contains(h.audit.String(), "hunter2") || strings.Contains(h.audit.String(), spec.Host) {
		t.Errorf("the audit record carries the engine's own detail:\n%s", h.audit.String())
	}
	// And the operator, who is the person who has to grant the missing privilege,
	// gets all of it.
	if !strings.Contains(h.appLog.String(), "permission denied for table pg_database") {
		t.Errorf("the application log dropped the engine's detail instead of recording it:\n%s", h.appLog.String())
	}
}

// TestListDatabasesResultCarriesTheNamesAndTheTruncationFlag is the output type's
// own contract, asserted as the JSON a client receives.
//
// It is written against the type rather than through a call because the shape is
// what a client learns to read: an object with a databases array — the SDK rejects a
// bare list as an output schema — and a truncated flag beside it, so that an agent
// whose list was cut off by the row cap is not left reading a partial answer as the
// complete set of databases on that server.
func TestListDatabasesResultCarriesTheNamesAndTheTruncationFlag(t *testing.T) {
	got, err := json.Marshal(&ListDatabasesResult{
		Databases: []string{"crm", "ledger"},
		Truncated: true,
		RowCap:    2,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"databases":["crm","ledger"],"truncated":true,"row_cap":2}`
	if string(got) != want {
		t.Errorf("the result marshals to\n%s\nwant\n%s", got, want)
	}

	// No host, port, username or database topology beyond the names the agent asked
	// for: the field set is asserted whole, which is the only form of this check that
	// fails when a field is added.
	var fields []string
	for i := range reflect.TypeFor[ListDatabasesResult]().NumField() {
		fields = append(fields, reflect.TypeFor[ListDatabasesResult]().Field(i).Name)
	}
	if wantFields := []string{"Databases", "Truncated", "RowCap"}; !reflect.DeepEqual(fields, wantFields) {
		t.Errorf("ListDatabasesResult's fields are %v, want exactly %v", fields, wantFields)
	}
}
