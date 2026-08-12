//go:build integration

// This is the one path of acceptance criterion 5 that cannot be reached without a
// database: a successful execute_query. It follows mcp_integration_test.go's
// conventions — the same build tag, the same CERBERUS_TEST_REQUIRE_ENGINES, the
// same skip-or-fail — and reuses its helpers rather than standing up a second way
// to reach the same containers.
package mcp

import (
	"testing"
)

// TestASuccessfulQueryIsAuditedWithItsCallersEmailAndSubject completes criterion
// 5. The other two paths — a successful list_connections and a statement the gate
// refused — need no engine and are in identity_test.go.
//
// It runs against a real engine because the audit site being checked is the one
// that only exists when the query came back with rows: a failed or refused call
// takes refuseOrFail's path instead, and a test that could not make a query
// succeed would be asserting about a line this code never writes.
func TestASuccessfulQueryIsAuditedWithItsCallersEmailAndSubject(t *testing.T) {
	want := testIdentity()
	for _, engine := range testedEngines() {
		t.Run(string(engine), func(t *testing.T) {
			cfg, spec := liveConfig(t, engine)
			h := connect(t, executorFor(t, cfg, engine, spec.Alias), admittingEveryRequestAs(want))

			res := h.call(t, ToolExecuteQuery, map[string]any{"alias": spec.Alias, "statement": "SELECT 1 AS one"})
			if res.IsError {
				t.Fatalf("execute_query failed: %s", resultText(t, res))
			}

			events := h.auditEventsFor(t, ToolExecuteQuery)
			if len(events) != 1 {
				t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
			}
			event := events[0]
			if event["outcome"] != string(OutcomeAllowed) {
				t.Fatalf("outcome = %#v, want %q; this test is about the audit site a successful query takes", event["outcome"], OutcomeAllowed)
			}
			if event["identity"] != want.Email {
				t.Errorf("identity = %#v, want %q", event["identity"], want.Email)
			}
			if event["subject"] != want.Subject {
				t.Errorf("subject = %#v, want %q", event["subject"], want.Subject)
			}
		})
	}
}
