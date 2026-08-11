package gate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestGate builds a gate on the embedded baseline only. Construction failing
// here means the embedded ruleset itself is broken, which no other test can
// work around.
func newTestGate(t *testing.T) *Gate {
	t.Helper()
	g, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") = %v", err)
	}
	return g
}

func sameDecision(a, b Decision) bool {
	return a.Verdict == b.Verdict && a.Reason == b.Reason && a.RuleID == b.RuleID &&
		a.Detail == b.Detail && slices.Equal(a.Pending, b.Pending) && slices.Equal(a.GrantsUsed, b.GrantsUsed)
}

func TestValidateVerdicts(t *testing.T) {
	g := newTestGate(t)
	for _, tt := range []struct {
		name      string
		engine    Engine
		statement string
		grants    []Grant
		want      Verdict
		reason    Reason
		ruleID    string
	}{
		{
			name: "plain select", engine: PostgreSQL, statement: "SELECT id, name FROM users WHERE id = 1",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "select with safe builtins", engine: SQLServer, statement: "SELECT UPPER(name), COUNT(*) FROM dbo.users GROUP BY UPPER(name)",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "cte then select", engine: PostgreSQL, statement: "WITH recent AS (SELECT id FROM orders) SELECT * FROM recent",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-with",
		},
		{
			name: "union", engine: MySQL, statement: "SELECT 1 UNION ALL SELECT 2",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "trailing semicolon", engine: MySQL, statement: "SELECT 1;",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "table hint", engine: SQLServer, statement: "SELECT * FROM dbo.orders WITH (NOLOCK)",
			want: Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "drop", engine: SQLServer, statement: "DROP TABLE dbo.orders",
			want: Deny, reason: ReasonForbiddenStatement, ruleID: "stmt-drop",
		},
		{
			name: "update hidden in a subquery", engine: MySQL, statement: "SELECT * FROM (UPDATE t SET a = 1) x",
			want: Deny, reason: ReasonForbiddenStatement, ruleID: "stmt-update",
		},
		{
			name: "execute with parentheses", engine: SQLServer, statement: "EXECUTE('DROP TABLE t')",
			want: Deny, reason: ReasonForbiddenStatement, ruleID: "stmt-execute",
		},
		{
			name: "bare extended procedure", engine: SQLServer, statement: "xp_cmdshell 'dir'",
			want: Deny, reason: ReasonForbiddenConstruct, ruleID: "fn-xp-cmdshell",
		},
		{
			name: "quoted forbidden function", engine: PostgreSQL, statement: "SELECT \"pg_read_file\"('/etc/passwd')",
			want: Deny, reason: ReasonForbiddenConstruct, ruleID: "fn-pg-read-file",
		},
		{
			name: "unknown function", engine: SQLServer, statement: "SELECT dbo.CalcularSaldo(1) FROM dbo.cuentas",
			want: NeedsApproval, reason: ReasonUnknownFunction, ruleID: "function:dbo.calcularsaldo",
		},
		{
			name: "unknown function granted", engine: SQLServer, statement: "SELECT dbo.CalcularSaldo(1) FROM dbo.cuentas",
			grants: []Grant{{RuleID: "function:dbo.calcularsaldo"}},
			want:   Allow, reason: ReasonReadStatement, ruleID: "read-select",
		},
		{
			name: "unknown leading keyword", engine: PostgreSQL, statement: "REINDEXX TABLE t",
			want: Deny, reason: ReasonUnknownStatement,
		},
		{
			name: "leading token is not a keyword", engine: PostgreSQL, statement: "(SELECT 1) UNION (SELECT 2)",
			want: Deny, reason: ReasonLeadingTokenNotWord,
		},
		{
			name: "unbalanced parenthesis", engine: MySQL, statement: "SELECT (1",
			want: Deny, reason: ReasonUnbalancedParens,
		},
		{
			name: "unterminated string", engine: MySQL, statement: "SELECT 'abc",
			want: Deny, reason: ReasonTokenizeError,
		},
		{
			name: "only a comment", engine: PostgreSQL, statement: "-- nothing here",
			want: Deny, reason: ReasonEmptyStatement,
		},
		{
			name: "unknown engine", engine: Engine("oracle"), statement: "SELECT 1",
			want: Deny, reason: ReasonInvalidEngine,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Validate(tt.engine, tt.statement, tt.grants)
			if got.Verdict != tt.want || got.Reason != tt.reason {
				t.Fatalf("Validate = %s/%s (%s), want %s/%s", got.Verdict, got.Reason, got.Detail, tt.want, tt.reason)
			}
			if tt.ruleID != "" && got.RuleID != tt.ruleID {
				t.Fatalf("RuleID = %q, want %q", got.RuleID, tt.ruleID)
			}
			if got.Verdict == NeedsApproval && len(got.Pending) == 0 {
				t.Fatalf("needs-approval decision carries no pending rule")
			}
		})
	}
}

// TestGrantIsRuleScoped covers the four halves of the grant contract: a grant
// for the only obstacle allows, the same statement without it escalates, a
// grant for a different rule changes nothing, and a grant naming a terminal
// deny changes nothing.
func TestGrantIsRuleScoped(t *testing.T) {
	g := newTestGate(t)
	const oneUnknown = "SELECT dbo.CalcularSaldo(1)"
	const twoUnknown = "SELECT dbo.CalcularSaldo(1), dbo.OtraFuncion(2)"
	const denied = "SELECT dbo.CalcularSaldo(1) FROM t; DROP TABLE t"

	for _, tt := range []struct {
		name      string
		statement string
		grants    []Grant
		want      Verdict
		ruleID    string
	}{
		{"no grant", oneUnknown, nil, NeedsApproval, "function:dbo.calcularsaldo"},
		{"matching grant", oneUnknown, []Grant{{RuleID: "function:dbo.calcularsaldo"}}, Allow, "read-select"},
		{"unrelated grant", oneUnknown, []Grant{{RuleID: "function:dbo.otrafuncion"}}, NeedsApproval, "function:dbo.calcularsaldo"},
		{"one of two granted", twoUnknown, []Grant{{RuleID: "function:dbo.calcularsaldo"}}, NeedsApproval, "function:dbo.otrafuncion"},
		{"both granted", twoUnknown, []Grant{{RuleID: "function:dbo.calcularsaldo"}, {RuleID: "function:dbo.otrafuncion"}}, Allow, "read-select"},
		{"grant on a terminal deny rule", denied, []Grant{{RuleID: "stmt-drop"}}, Deny, ""},
		{"grant on a terminal deny rule, escalatable obstacle present", denied, []Grant{{RuleID: "stmt-drop"}, {RuleID: "function:dbo.calcularsaldo"}}, Deny, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Validate(SQLServer, tt.statement, tt.grants)
			if got.Verdict != tt.want {
				t.Fatalf("Validate = %s/%s (%s), want %s", got.Verdict, got.Reason, got.Detail, tt.want)
			}
			if tt.ruleID != "" && got.RuleID != tt.ruleID {
				t.Fatalf("RuleID = %q, want %q", got.RuleID, tt.ruleID)
			}
		})
	}
}

// TestAllowRecordsTheGrantsItUsed keeps a grant-enabled allow auditable: the
// caller has to be able to tell an allow that needed nobody's approval from one
// that spent a grant, and which grant it spent.
func TestAllowRecordsTheGrantsItUsed(t *testing.T) {
	g := newTestGate(t)
	for _, tt := range []struct {
		name      string
		statement string
		grants    []Grant
		want      []string
	}{
		{"no grant needed", "SELECT UPPER(name) FROM t", []Grant{{RuleID: "function:dbo.calcularsaldo"}}, nil},
		{"one grant used", "SELECT dbo.CalcularSaldo(1)", []Grant{{RuleID: "function:dbo.calcularsaldo"}}, []string{"function:dbo.calcularsaldo"}},
		{
			"two grants used", "SELECT dbo.CalcularSaldo(1), dbo.OtraFuncion(2)",
			[]Grant{{RuleID: "function:dbo.calcularsaldo"}, {RuleID: "function:dbo.otrafuncion"}},
			[]string{"function:dbo.calcularsaldo", "function:dbo.otrafuncion"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Validate(SQLServer, tt.statement, tt.grants)
			if got.Verdict != Allow {
				t.Fatalf("Validate = %s/%s (%s), want allow", got.Verdict, got.Reason, got.Detail)
			}
			if got.RuleID != "read-select" {
				t.Fatalf("RuleID = %q, want the read rule that permitted the statement", got.RuleID)
			}
			if !slices.Equal(got.GrantsUsed, tt.want) {
				t.Fatalf("GrantsUsed = %v, want %v", got.GrantsUsed, tt.want)
			}
		})
	}
}

// wideRead is a statement of the shape the bound has to leave room for: a read
// naming several hundred aliased columns of a several-hundred-table schema.
func wideRead(columns int) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	for i := 0; i < columns; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "t.some_reasonably_long_column_name_%04d AS alias_for_column_%04d", i, i)
	}
	b.WriteString(" FROM dbo.some_reasonably_long_table_name AS t WHERE t.created_at > '2024-01-01'")
	return b.String()
}

func TestStatementLengthIsBounded(t *testing.T) {
	g := newTestGate(t)
	bound := g.Ruleset().MaxStatementBytes

	t.Run("a legitimate wide read passes", func(t *testing.T) {
		s := wideRead(300)
		if len(s) > bound {
			t.Fatalf("a 300-column read is %d bytes, over the %d-byte bound: the bound is too tight to be usable", len(s), bound)
		}
		if got := g.Validate(SQLServer, s, nil); got.Verdict != Allow {
			t.Fatalf("Validate = %s/%s (%s), want allow", got.Verdict, got.Reason, got.Detail)
		}
	})

	t.Run("over the bound is refused", func(t *testing.T) {
		s := "SELECT 1 -- " + strings.Repeat("x", bound)
		got := g.Validate(SQLServer, s, nil)
		if got.Verdict != Deny || got.Reason != ReasonStatementTooLong {
			t.Fatalf("Validate = %s/%s, want deny/%s", got.Verdict, got.Reason, ReasonStatementTooLong)
		}
	})

	t.Run("exactly at the bound is not refused for length", func(t *testing.T) {
		s := "SELECT 1 " + strings.Repeat("-", 0) + strings.Repeat(" ", bound-9)
		if len(s) != bound {
			t.Fatalf("test built a %d-byte statement, want %d", len(s), bound)
		}
		if got := g.Validate(SQLServer, s, nil); got.Reason == ReasonStatementTooLong {
			t.Fatalf("Validate at exactly the bound = %s, want the bound not to trigger", got.Reason)
		}
	})

	// The worst case for the name walk, at the largest size the bound admits.
	// Before the walk was capped this shape was quadratic: 8 seconds of CPU at
	// 40 KB and 83 at 120 KB, on the goroutine handling the request. The verdict
	// is not the point — SELECT a.a...a is a harmless read — the cost is, so the
	// budget is deliberately far above a correct implementation and far below a
	// quadratic one.
	t.Run("a pathological dotted name is bounded work", func(t *testing.T) {
		s := "SELECT " + strings.Repeat("a.", (bound-16)/2) + "a"
		start := time.Now()
		g.Validate(PostgreSQL, s, nil)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Validate on %d bytes of dotted name took %s: the name walk is no longer bounded", len(s), elapsed)
		}
	})

	t.Run("an overlay can raise the bound", func(t *testing.T) {
		raised, err := New(filepath.Join("testdata", "rulesets", "raised-statement-bound.json"))
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		s := "SELECT 1 -- " + strings.Repeat("x", bound)
		if got := raised.Validate(SQLServer, s, nil); got.Reason == ReasonStatementTooLong {
			t.Fatalf("Validate under the raised bound = %s, want the bound not to trigger", got.Reason)
		}
	})
}

func TestQualifiedNameWalkIsCapped(t *testing.T) {
	g := newTestGate(t)
	// A forbidden name is matched bare as well as qualified, so capping the walk
	// cannot hide one however deep the prefix is.
	if got := g.Validate(SQLServer, "SELECT a.b.c.d.e.f.xp_cmdshell(1)", nil); got.RuleID != "fn-xp-cmdshell" {
		t.Fatalf("Validate = %s/%s rule %q, want the xp_cmdshell rule", got.Verdict, got.Reason, got.RuleID)
	}
	got := g.Validate(SQLServer, "SELECT a.b.c.d.e.unknownfn(1)", nil)
	if got.Verdict != NeedsApproval {
		t.Fatalf("Validate = %s, want needs-approval", got.Verdict)
	}
	if strings.Count(got.RuleID, ".") != maxNameParts-1 {
		t.Fatalf("RuleID = %q, want a name of at most %d dotted parts", got.RuleID, maxNameParts)
	}
}

func TestValidateIsDeterministic(t *testing.T) {
	g := newTestGate(t)
	statements := []string{
		"SELECT dbo.A(1), dbo.B(2) FROM t",
		"SELECT dbo.C(1), dbo.A(2), dbo.B(3), dbo.A(4) FROM t",
		"WITH c AS (DELETE FROM x RETURNING *) SELECT * FROM c",
		"SELECT * FROM OPENROWSET('x', 'y', 'z')",
		"SELECT 1 SELECT 2",
		"SELECT UPPER(name) FROM users",
	}
	// Grants for some but not all of the unknown functions, so that Pending and
	// GrantsUsed are both non-empty and both have something to get wrong. Their
	// order is first appearance in the statement — no map is iterated to build
	// either — and this is what pins that.
	grants := []Grant{{RuleID: "function:dbo.a"}, {RuleID: "function:dbo.b"}}
	for _, engine := range Engines() {
		for _, s := range statements {
			first := g.Validate(engine, s, grants)
			for i := 0; i < 50; i++ {
				if got := g.Validate(engine, s, grants); !sameDecision(got, first) {
					t.Fatalf("%s %q: call %d = %+v, first = %+v", engine, s, i, got, first)
				}
			}
		}
	}

	// dbo.C first, dbo.A twice, dbo.B once. Ungranted, C is the only pending
	// obstacle; granted, all three are reported in the order they appear and
	// dbo.A appears once despite being called twice.
	if got := g.Validate(SQLServer, statements[1], grants); !slices.Equal(got.Pending, []string{"function:dbo.c"}) {
		t.Fatalf("Pending = %v, want the one ungranted obstacle", got.Pending)
	}
	all := append(slices.Clone(grants), Grant{RuleID: "function:dbo.c"})
	got := g.Validate(SQLServer, statements[1], all)
	if got.Verdict != Allow {
		t.Fatalf("Validate = %s/%s, want allow once every obstacle is granted", got.Verdict, got.Reason)
	}
	if want := []string{"function:dbo.c", "function:dbo.a", "function:dbo.b"}; !slices.Equal(got.GrantsUsed, want) {
		t.Fatalf("GrantsUsed = %v, want %v in first-appearance order with no repeat", got.GrantsUsed, want)
	}
}

func TestConstructionRejectsBrokenRulesets(t *testing.T) {
	for _, tt := range []struct {
		name string
		file string
	}{
		{"malformed json", "malformed.json"},
		{"unknown field", "unknown-field.json"},
		{"wrong version", "wrong-version.json"},
		{"duplicate rule id", "duplicate-id.json"},
		{"empty reason", "empty-reason.json"},
		{"removes a rule that does not exist", "remove-missing.json"},
		{"contradictory keyword", "contradiction.json"},
		{"safe and forbidden function", "safe-and-forbidden.json"},
		{"safe function disables a forbidden keyword", "safe-disables-keyword.json"},
		{"the keyword rule is deleted and reinstated with an undeclared exemption", "exploit-reinstate-execute.json"},
		{"the exemption is claimed with a blank reason", "safe-as-function-blank-reason.json"},
		{"the exemption is claimed on a read rule", "safe-as-function-on-a-read-rule.json"},
		{"statement bound below the floor", "tiny-statement-bound.json"},
		{"unknown engine", "unknown-engine.json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g, err := New(filepath.Join("testdata", "rulesets", tt.file))
			if err == nil {
				t.Fatalf("New(%s) = %+v, want an error", tt.file, g.Ruleset())
			}
			if g != nil {
				t.Fatalf("New(%s) returned a gate alongside %v", tt.file, err)
			}
			if !errors.Is(err, ErrInvalidRuleset) && !errors.Is(err, ErrUnknownEngine) {
				t.Fatalf("New(%s) = %v, want it to wrap ErrInvalidRuleset or ErrUnknownEngine", tt.file, err)
			}
		})
	}
}

func TestOverlayLoosensAndTightens(t *testing.T) {
	g, err := New(filepath.Join("testdata", "rulesets", "valid-overlay.json"))
	if err != nil {
		t.Fatalf("New(valid-overlay.json) = %v", err)
	}
	baseline := newTestGate(t)

	// The overlay grants dbo.CalcularSaldo permanently by adding it to the
	// safe-builtin allowlist, and tightens by removing the read rule for VALUES.
	if got := baseline.Validate(SQLServer, "SELECT dbo.CalcularSaldo(1)", nil); got.Verdict != NeedsApproval {
		t.Fatalf("baseline verdict = %s, want needs-approval", got.Verdict)
	}
	if got := g.Validate(SQLServer, "SELECT dbo.CalcularSaldo(1)", nil); got.Verdict != Allow {
		t.Fatalf("overlaid verdict = %s/%s (%s), want allow", got.Verdict, got.Reason, got.Detail)
	}
	if got := baseline.Validate(PostgreSQL, "VALUES (1)", nil); got.Verdict != Allow {
		t.Fatalf("baseline VALUES verdict = %s, want allow", got.Verdict)
	}
	if got := g.Validate(PostgreSQL, "VALUES (1)", nil); got.Verdict == Allow {
		t.Fatalf("overlaid VALUES verdict = allow, want a refusal")
	}
}

// TestTheSafeAsFunctionExemptionIsDeclaredNotDiscovered pins the whole of what
// the exemption is for. Deleting a keyword rule is already a loosening, but it
// leaves the statement one human approval away; claiming the exemption on top
// removes the human. So the exemption costs a written argument, and the three
// steps below are the measurement that says the argument is the only thing
// standing there.
func TestTheSafeAsFunctionExemptionIsDeclaredNotDiscovered(t *testing.T) {
	const stmt = "SELECT 1 EXECUTE('xp_cmdshell ''whoami''')"

	t.Run("the baseline refuses it terminally", func(t *testing.T) {
		if got := newTestGate(t).Validate(SQLServer, stmt, nil); got.Verdict != Deny || got.RuleID != "stmt-execute" {
			t.Fatalf("Validate = %s/%s rule %q, want deny on stmt-execute", got.Verdict, got.Reason, got.RuleID)
		}
	})

	t.Run("deleting the rule alone still needs a human", func(t *testing.T) {
		g, err := New(filepath.Join("testdata", "rulesets", "remove-execute-rules.json"))
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if got := g.Validate(SQLServer, stmt, nil); got.Verdict != NeedsApproval {
			t.Fatalf("Validate = %s/%s, want needs-approval: deleting the keyword rule must not by itself reach allow", got.Verdict, got.Reason)
		}
	})

	t.Run("an undeclared exemption is rejected", func(t *testing.T) {
		if _, err := New(filepath.Join("testdata", "rulesets", "exploit-reinstate-execute.json")); !errors.Is(err, ErrInvalidRuleset) {
			t.Fatalf("New = %v, want ErrInvalidRuleset", err)
		}
	})

	// The escape hatch does work when it is argued for, and what it buys is
	// severe. This asserts the cost honestly rather than pretending the
	// declaration is a safety mechanism: nothing checks the sentence.
	t.Run("a declared exemption is accepted and does loosen the gate", func(t *testing.T) {
		g, err := New(filepath.Join("testdata", "rulesets", "deliberate-execute-exemption.json"))
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if got := g.Validate(SQLServer, stmt, nil); got.Verdict != Allow {
			t.Fatalf("Validate = %s/%s, want allow: the declared exemption is meant to work, and this is what it costs", got.Verdict, got.Reason)
		}
		var declared string
		for _, r := range g.Ruleset().ForbiddenStatements {
			if r.Match == "execute" {
				declared = r.SafeAsFunction
			}
		}
		if strings.TrimSpace(declared) == "" {
			t.Fatalf("the accepted ruleset carries no written argument for the exemption")
		}
	})
}

// TestExemptionsAreReportable covers the counterpart control to
// safe_as_function being an unverified claim. The declarations have to be
// readable out of the loaded ruleset, because the edit that makes one dangerous
// — adding the colliding name to safe_functions — has a diff that does not
// contain the declaration it activates.
func TestExemptionsAreReportable(t *testing.T) {
	t.Run("the baseline reports its one exemption with the argument", func(t *testing.T) {
		g := newTestGate(t)
		got := g.Exemptions()
		if len(got) != 1 {
			t.Fatalf("Exemptions() = %+v, want exactly the stmt-replace declaration", got)
		}
		e := got[0]
		if e.RuleID != "stmt-replace" || e.Keyword != "replace" || e.SafeFunction != "replace" || e.Dangling {
			t.Fatalf("Exemptions()[0] = %+v, want the live stmt-replace exemption", e)
		}
		var declared string
		for _, r := range g.Ruleset().ForbiddenStatements {
			if r.ID == "stmt-replace" {
				declared = r.SafeAsFunction
			}
		}
		if e.Argument != declared || strings.TrimSpace(e.Argument) == "" {
			t.Fatalf("Argument = %q, want the rule's declaration verbatim (%q)", e.Argument, declared)
		}
	})

	// The dangling case is the point of the accessor, so it must survive being
	// currently harmless. This fixture is also the legitimate tightening that
	// rules out simply rejecting dangling declarations.
	t.Run("a dangling declaration is reported and marked", func(t *testing.T) {
		g, err := New(filepath.Join("testdata", "rulesets", "remove-replace-safe-function.json"))
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		got := g.Exemptions()
		if len(got) != 1 || !got[0].Dangling || got[0].SafeFunction != "" || strings.TrimSpace(got[0].Argument) == "" {
			t.Fatalf("Exemptions() = %+v, want one dangling declaration still carrying its argument", got)
		}
		// Inert today: the tightening this fixture performs is real.
		if d := g.Validate(MySQL, "SELECT REPLACE(a, 1, 2)", nil); d.Verdict != Deny || d.RuleID != "stmt-replace" {
			t.Fatalf("Validate = %s/%s rule %q, want deny on stmt-replace once REPLACE is no longer a safe builtin", d.Verdict, d.Reason, d.RuleID)
		}
	})

	t.Run("it tracks a reload rather than construction", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "overlay.json")
		copyFixture(t, "remove-replace-safe-function.json", path)
		g, err := New(path)
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if got := g.Exemptions(); len(got) != 1 || !got[0].Dangling {
			t.Fatalf("Exemptions() at construction = %+v, want one dangling declaration", got)
		}
		copyFixture(t, "no-op-overlay.json", path)
		if err := g.Reload(); err != nil {
			t.Fatalf("Reload = %v", err)
		}
		if got := g.Exemptions(); len(got) != 1 || got[0].Dangling || got[0].SafeFunction != "replace" {
			t.Fatalf("Exemptions() after reload = %+v, want the exemption live again", got)
		}
	})

	t.Run("the caller cannot mutate the gate through it", func(t *testing.T) {
		g := newTestGate(t)
		got := g.Exemptions()
		got[0].Argument = ""
		got[0].RuleID = "tampered"
		got[0].Dangling = true
		got[0].Engines = append(got[0].Engines, Engine("oracle"))
		got = got[:0]

		again := g.Exemptions()
		if len(again) != 1 || again[0].RuleID != "stmt-replace" || again[0].Dangling || strings.TrimSpace(again[0].Argument) == "" {
			t.Fatalf("Exemptions() after the caller mutated an earlier result = %+v", again)
		}
		if d := g.Validate(MySQL, "SELECT REPLACE(a, 1, 2)", nil); d.Verdict != Allow {
			t.Fatalf("Validate = %s, want the gate's own rules to be untouched", d.Verdict)
		}
	})
}

func copyFixture(t *testing.T, name, dest string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "rulesets", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
}

func TestMissingOverlayLeavesTheBaselineInForce(t *testing.T) {
	g, err := New(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("New(absent path) = %v", err)
	}
	if got := g.Validate(MySQL, "SELECT 1", nil); got.Verdict != Allow {
		t.Fatalf("Validate = %s, want allow under the baseline", got.Verdict)
	}
	if got := g.Validate(MySQL, "DROP TABLE t", nil); got.Verdict != Deny {
		t.Fatalf("Validate = %s, want deny under the baseline", got.Verdict)
	}
}

func TestFailedReloadLeavesThePreviousRulesetInForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	valid, err := os.ReadFile(filepath.Join("testdata", "rulesets", "valid-overlay.json"))
	if err != nil {
		t.Fatalf("read valid-overlay.json: %v", err)
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	g, err := New(path)
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	probes := []string{"SELECT dbo.CalcularSaldo(1)", "VALUES (1)", "SELECT 1", "DROP TABLE t"}
	before := make([]Decision, len(probes))
	for i, p := range probes {
		before[i] = g.Validate(SQLServer, p, nil)
	}

	broken, err := os.ReadFile(filepath.Join("testdata", "rulesets", "duplicate-id.json"))
	if err != nil {
		t.Fatalf("read duplicate-id.json: %v", err)
	}
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatalf("overwrite overlay: %v", err)
	}
	if err := g.Reload(); err == nil {
		t.Fatalf("Reload() = nil, want an error")
	}
	for i, p := range probes {
		if got := g.Validate(SQLServer, p, nil); !sameDecision(got, before[i]) {
			t.Fatalf("after a failed reload %q = %+v, want %+v", p, got, before[i])
		}
	}

	// A subsequent good reload does take effect, so the failure above was a
	// rejection and not a permanently wedged gate.
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("restore overlay: %v", err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload() = %v", err)
	}
}

func TestConcurrentReloadNeverExposesAPartialRuleset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	valid, err := os.ReadFile(filepath.Join("testdata", "rulesets", "valid-overlay.json"))
	if err != nil {
		t.Fatalf("read valid-overlay.json: %v", err)
	}
	broken, err := os.ReadFile(filepath.Join("testdata", "rulesets", "duplicate-id.json"))
	if err != nil {
		t.Fatalf("read duplicate-id.json: %v", err)
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	g, err := New(path)
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Under either ruleset these verdicts are fixed. A reader that
				// saw a half-applied ruleset would see something else.
				if got := g.Validate(SQLServer, "SELECT UPPER(name) FROM t", nil); got.Verdict != Allow {
					t.Errorf("read verdict during reload = %s/%s", got.Verdict, got.Reason)
					return
				}
				if got := g.Validate(SQLServer, "DROP TABLE t", nil); got.Verdict != Deny {
					t.Errorf("write verdict during reload = %s/%s", got.Verdict, got.Reason)
					return
				}
				// Exemptions reads the same pointer, so it is exercised under the
				// same load: the layer that logs it will be calling it exactly
				// when a reload has just happened.
				if got := g.Exemptions(); len(got) != 1 || got[0].RuleID != "stmt-replace" || strings.TrimSpace(got[0].Argument) == "" {
					t.Errorf("exemptions during reload = %+v", got)
					return
				}
			}
		}()
	}
	for i := 0; i < 60; i++ {
		body := valid
		if i%2 == 1 {
			body = broken
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Errorf("write overlay: %v", err)
			break
		}
		_ = g.Reload()
	}
	close(stop)
	wg.Wait()
}
