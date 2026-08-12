package mcp

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// admittingEveryRequestAs is a [Deps] adjustment that puts one known identity on
// every request, in the shape internal/auth's own middleware uses.
//
// It is not a stand-in for authentication and nothing here decides whether a
// caller is allowed: the token, the Tokeninfo call and the allowlist are
// internal/auth's and are tested there. What this stands in for is a middleware
// that already said yes — the only thing this package can observe about
// authentication is the identity that arrives, and it arrives through the real
// [auth.WithIdentity] on the real request context, through the real transport.
func admittingEveryRequestAs(id auth.Identity) func(*Deps) {
	return admittingEachRequestAs(func() auth.Identity { return id })
}

// admittingEachRequestAs is the same seam with a fresh identity per request, for
// the assertion that each call carries the identity of the request that made it
// rather than of some earlier one.
func admittingEachRequestAs(next func() auth.Identity) func(*Deps) {
	return func(d *Deps) {
		d.Middleware = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), next())))
			})
		}
	}
}

// testIdentity is one allowlisted caller. The subject is shaped like a real
// Google `sub` — 21 digits, opaque — so that a test which confused it with the
// email would be visibly wrong rather than plausibly wrong.
func testIdentity() auth.Identity {
	return auth.Identity{Subject: "104427392015467281503", Email: "analyst@example.com"}
}

// TestAnIdentitySetOnTheRequestContextSurvivesTheSDKsDispatchToTheToolHandler is
// acceptance criterion 10, and its name is the message: if this fails, the path
// by which an identity travels from net/http middleware into a tool handler has
// broken, and every audit record this server writes now names nobody.
//
// That path is a context value, and it is not a documented contract of the SDK.
// It works because Stateless: true makes an SDK session live exactly one HTTP
// request, so the session is rooted in that request's own context. The chain was
// traced by hand in the pinned go-sdk v1.7.0 and these are the lines to re-read
// when this test goes red:
//
//   - mcp/streamable.go:434 — connectStreamable(req.Context(), ...): each
//     stateless session is rooted in the context of the request that created it.
//   - mcp/transport.go:177-212 — connect passes that ctx to
//     jsonrpc2.NewConnection unmodified.
//   - internal/jsonrpc2/conn.go:231-234 — it is wrapped in notDone, whose Value
//     delegates to the wrapped context (:812-816), so values survive.
//   - internal/jsonrpc2/conn.go:564-567 and :654-685 — per-request contexts are
//     built with WithCancel and WithValue from that one, both value-preserving.
//   - mcp/server.go:1919, :955-963, :353-378 — the SDK adds its own values and
//     calls the registered tool handler with the result.
//
// A change to any of those, or a change here away from Stateless, breaks the
// channel without breaking a compile. The second subtest is the one that catches
// the Stateless case in particular: a stateful session would be rooted in the
// context of the initialize request and would keep serving that first identity
// for the rest of the session, which a test using a single fixed identity cannot
// see.
func TestAnIdentitySetOnTheRequestContextSurvivesTheSDKsDispatchToTheToolHandler(t *testing.T) {
	t.Run("the tool handler observes exactly the identity the middleware set", func(t *testing.T) {
		want := testIdentity()
		h := connect(t, unreachableExecutor(t), admittingEveryRequestAs(want))

		if res := h.call(t, ToolListConnections, nil); res.IsError {
			t.Fatalf("list_connections failed: %s", resultText(t, res))
		}

		events := h.auditEventsFor(t, ToolListConnections)
		if len(events) != 1 {
			t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
		}
		gotEmail, gotSubject := events[0]["identity"], events[0]["subject"]
		if gotEmail != want.Email || gotSubject != want.Subject {
			t.Errorf("the tool handler recorded identity=%#v subject=%#v, want %q and %q.\n"+
				"The identity the middleware put on the request context did not reach the tool handler: the SDK's context path is broken, not this assertion. "+
				"Re-read the chain listed in this test's comment against the pinned go-sdk, and check that StreamableHTTPOptions.Stateless is still true.",
				gotEmail, gotSubject, want.Email, want.Subject)
		}
	})

	t.Run("each call carries the identity of the request that made it", func(t *testing.T) {
		var mu sync.Mutex
		var assigned []auth.Identity
		h := connect(t, unreachableExecutor(t), admittingEachRequestAs(func() auth.Identity {
			mu.Lock()
			defer mu.Unlock()
			n := len(assigned) + 1
			id := auth.Identity{
				Subject: fmt.Sprintf("1044273920154672815%02d", n),
				Email:   fmt.Sprintf("analyst-%d@example.com", n),
			}
			assigned = append(assigned, id)
			return id
		}))

		// Two calls, two HTTP requests, two identities. The handshake consumed some
		// too, which is why the assertion below is that each recorded pair is one of
		// the assigned pairs and that the two differ, rather than which ones they are.
		for range 2 {
			if res := h.call(t, ToolListConnections, nil); res.IsError {
				t.Fatalf("list_connections failed: %s", resultText(t, res))
			}
		}

		events := h.auditEventsFor(t, ToolListConnections)
		if len(events) != 2 {
			t.Fatalf("got %d audit events for two calls:\n%s", len(events), h.audit.String())
		}

		mu.Lock()
		defer mu.Unlock()
		for i, event := range events {
			pairWasAssigned := false
			for _, id := range assigned {
				if event["identity"] == id.Email && event["subject"] == id.Subject {
					pairWasAssigned = true
				}
			}
			if !pairWasAssigned {
				t.Errorf("call %d recorded identity=%#v subject=%#v, which is not a pair any request was admitted as (%v): either the identity did not survive the transport or the two fields came from different requests",
					i, event["identity"], event["subject"], assigned)
			}
		}
		if events[0]["identity"] == events[1]["identity"] {
			t.Errorf("both calls recorded the caller %#v, so a later call is being served the identity of an earlier request. That is what a session outliving one HTTP request looks like: check that StreamableHTTPOptions.Stateless is still true",
				events[0]["identity"])
		}
	})
}

// TestEveryAuditEventOfAnAuthenticatedCallNamesItsCaller is acceptance criterion
// 5 for the two of its three paths that need no engine: a successful
// list_connections and a statement the gate refused. The third — a successful
// execute_query — needs a database that answers and is in
// identity_integration_test.go.
//
// The outcomes are asserted alongside the caller so that the test cannot be
// satisfied by two records of the wrong kind: what is being checked is that each
// of the three code paths in tools.go fills the pair, and a pair of allowed
// listings would say nothing about the refusal path.
func TestEveryAuditEventOfAnAuthenticatedCallNamesItsCaller(t *testing.T) {
	want := testIdentity()
	h := connect(t, unreachableExecutor(t), admittingEveryRequestAs(want))

	if res := h.call(t, ToolListConnections, nil); res.IsError {
		t.Fatalf("list_connections failed: %s", resultText(t, res))
	}
	// A write, so the gate refuses it before anything reaches a socket. The alias
	// points at a dead port, which is what makes "refused" the gate's answer rather
	// than an accident of reachability.
	refused := h.call(t, ToolExecuteQuery, map[string]any{"alias": "warehouse", "statement": "UPDATE invoices SET total = 0"})
	if !refused.IsError {
		t.Fatalf("the gate allowed a write: %+v", refused)
	}

	events := h.auditEvents(t)
	if len(events) != 2 {
		t.Fatalf("got %d audit events for two calls:\n%s", len(events), h.audit.String())
	}
	for _, tt := range []struct {
		tool    string
		outcome Outcome
		verdict gate.Verdict
	}{
		{ToolListConnections, OutcomeAllowed, ""},
		{ToolExecuteQuery, OutcomeRefused, gate.Deny},
	} {
		matched := false
		for _, event := range events {
			if event["tool"] != tt.tool || event["outcome"] != string(tt.outcome) || event["verdict"] != string(tt.verdict) {
				continue
			}
			matched = true
			if event["identity"] != want.Email {
				t.Errorf("the %s/%s event recorded identity=%#v, want %q", tt.tool, tt.outcome, event["identity"], want.Email)
			}
			if event["subject"] != want.Subject {
				t.Errorf("the %s/%s event recorded subject=%#v, want %q", tt.tool, tt.outcome, event["subject"], want.Subject)
			}
		}
		if !matched {
			t.Errorf("no audit event is a %s with outcome %s and verdict %q, so this test did not exercise that path:\n%s",
				tt.tool, tt.outcome, tt.verdict, h.audit.String())
		}
	}
}

// TestACallWithNoIdentityOnItsContextIsAuditedWithNoCallerAndWarnsTheOperator
// pins the decision at [Server.caller]: the two caller fields stay empty rather
// than carrying an invented value, and the operator is told on the application
// log instead.
//
// The state is reachable only with a nil Middleware — which every other test in
// this package uses and no deployment can, since the binary refuses to start
// without authentication configured — so this is what those tests are asserted to
// produce, and it is deliberately not something a reader of the audit stream can
// mistake for a caller.
func TestACallWithNoIdentityOnItsContextIsAuditedWithNoCallerAndWarnsTheOperator(t *testing.T) {
	h := connect(t, unreachableExecutor(t))

	if res := h.call(t, ToolListConnections, nil); res.IsError {
		t.Fatalf("list_connections failed: %s", resultText(t, res))
	}

	events := h.auditEventsFor(t, ToolListConnections)
	if len(events) != 1 {
		t.Fatalf("got %d audit events for one call:\n%s", len(events), h.audit.String())
	}
	for _, field := range []string{"identity", "subject"} {
		value, present := events[0][field]
		if !present {
			t.Errorf("the audit record has no %s field, so a consumer cannot tell an unidentified call from an older record: %v", field, events[0])
		}
		if value != "" {
			t.Errorf("%s = %#v on a call nobody was identified for; an invented value there satisfies every downstream check that only asks whether an identity was recorded", field, value)
		}
	}
	if !strings.Contains(h.appLog.String(), "no identity on its context") {
		t.Errorf("the application log does not report that a tool ran for nobody, which is the only place that defect is reported:\n%s", h.appLog.String())
	}
}
