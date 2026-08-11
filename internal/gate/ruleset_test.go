package gate

import (
	"errors"
	"strings"
	"testing"
)

func baseForTest(t *testing.T) *Ruleset {
	t.Helper()
	rs, err := BaselineRuleset()
	if err != nil {
		t.Fatalf("BaselineRuleset() = %v", err)
	}
	return rs
}

func TestRulesetValidateRejects(t *testing.T) {
	valid := func() *Ruleset {
		return &Ruleset{
			Version:             rulesetVersion,
			MaxStatementBytes:   minStatementBytes,
			ReadStatements:      []Rule{{ID: "read-select", Match: "select", Reason: "SELECT is a read"}},
			ForbiddenStatements: []Rule{{ID: "stmt-drop", Match: "drop", Reason: "DROP removes schema objects"}},
		}
	}
	for _, tt := range []struct {
		name string
		bend func(rs *Ruleset)
		want error
	}{
		{"wrong version", func(rs *Ruleset) { rs.Version = 99 }, ErrInvalidRuleset},
		{"no read statements", func(rs *Ruleset) { rs.ReadStatements = nil }, ErrInvalidRuleset},
		{"no forbidden statements", func(rs *Ruleset) { rs.ForbiddenStatements = nil }, ErrInvalidRuleset},
		{"empty rule id", func(rs *Ruleset) { rs.ForbiddenStatements[0].ID = "" }, ErrInvalidRuleset},
		{"empty match", func(rs *Ruleset) { rs.ForbiddenStatements[0].Match = "" }, ErrInvalidRuleset},
		{"uppercase match", func(rs *Ruleset) { rs.ForbiddenStatements[0].Match = "DROP" }, ErrInvalidRuleset},
		{"padded match", func(rs *Ruleset) { rs.ForbiddenStatements[0].Match = "drop  table" }, ErrInvalidRuleset},
		{"empty reason", func(rs *Ruleset) { rs.ForbiddenStatements[0].Reason = "  " }, ErrInvalidRuleset},
		{"duplicate id", func(rs *Ruleset) {
			rs.ForbiddenStatements = append(rs.ForbiddenStatements, Rule{ID: "stmt-drop", Match: "insert", Reason: "INSERT writes"})
		}, ErrInvalidRuleset},
		{"multi-word read statement", func(rs *Ruleset) { rs.ReadStatements[0].Match = "select all" }, ErrInvalidRuleset},
		{"multi-word forbidden function", func(rs *Ruleset) {
			rs.ForbiddenFunctions = []Rule{{ID: "fn-x", Match: "a b", Reason: "two words"}}
		}, ErrInvalidRuleset},
		{"prefix on a forbidden rule", func(rs *Ruleset) { rs.ForbiddenStatements[0].Prefix = true }, ErrInvalidRuleset},
		{"safe_as_function on a read rule", func(rs *Ruleset) {
			rs.ReadStatements[0].SafeAsFunction = "a read rule has no keyword check to exempt"
		}, ErrInvalidRuleset},
		{"safe_as_function with a blank reason", func(rs *Ruleset) {
			rs.ForbiddenStatements[0].SafeAsFunction = " \t "
		}, ErrInvalidRuleset},
		{"safe function collides with a forbidden keyword", func(rs *Ruleset) {
			rs.SafeFunctions = []FunctionAllowance{{Names: []string{"drop"}}}
		}, ErrInvalidRuleset},
		{"the collision is declared but with no reason", func(rs *Ruleset) {
			rs.SafeFunctions = []FunctionAllowance{{Names: []string{"drop"}}}
			rs.ForbiddenStatements[0].SafeAsFunction = ""
		}, ErrInvalidRuleset},
		{"keyword both read and forbidden", func(rs *Ruleset) {
			rs.ForbiddenStatements = append(rs.ForbiddenStatements, Rule{ID: "stmt-select", Match: "select", Reason: "contradiction"})
		}, ErrInvalidRuleset},
		{"function both safe and forbidden", func(rs *Ruleset) {
			rs.ForbiddenFunctions = []Rule{{ID: "fn-x", Match: "xp_cmdshell", Reason: "runs a shell command"}}
			rs.SafeFunctions = []FunctionAllowance{{Names: []string{"xp_cmdshell"}}}
		}, ErrInvalidRuleset},
		{"uppercase safe function", func(rs *Ruleset) {
			rs.SafeFunctions = []FunctionAllowance{{Names: []string{"UPPER"}}}
		}, ErrInvalidRuleset},
		{"uppercase non-function keyword", func(rs *Ruleset) { rs.NonFunctionKeywords = []string{"IN"} }, ErrInvalidRuleset},
		{"unknown engine on a rule", func(rs *Ruleset) {
			rs.ForbiddenStatements[0].Engines = []Engine{"oracle"}
		}, ErrUnknownEngine},
		{"unknown engine on an allowance", func(rs *Ruleset) {
			rs.SafeFunctions = []FunctionAllowance{{Engines: []Engine{"oracle"}, Names: []string{"upper"}}}
		}, ErrUnknownEngine},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rs := valid()
			if err := rs.validate(); err != nil {
				t.Fatalf("the unbent ruleset is already invalid: %v", err)
			}
			tt.bend(rs)
			err := rs.validate()
			if err == nil {
				t.Fatalf("validate() = nil, want an error")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("validate() = %v, want it to wrap %v", err, tt.want)
			}
		})
	}
}

// TestSafeAsFunctionAcceptsOnlyAWrittenArgument covers the field's one job. It
// is not a check on the claim — nothing here can decide whether a keyword's
// statement form can precede a parenthesis — it is a check that a claim was
// made and can be attributed.
func TestSafeAsFunctionAcceptsOnlyAWrittenArgument(t *testing.T) {
	for _, tt := range []struct {
		name    string
		declare string
		wantErr bool
	}{
		{"absent", "", true},
		{"blank", "   ", true},
		{"tabs and newlines", "\t\n ", true},
		{"an argument", "the statement form always names a table first", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rs := baseForTest(t)
			rs.SafeFunctions = append(rs.SafeFunctions, FunctionAllowance{Names: []string{"drop"}, Reason: "for the test"})
			for i := range rs.ForbiddenStatements {
				if rs.ForbiddenStatements[i].ID == "stmt-drop" {
					rs.ForbiddenStatements[i].SafeAsFunction = tt.declare
				}
			}
			err := rs.validate()
			if tt.wantErr && !errors.Is(err, ErrInvalidRuleset) {
				t.Fatalf("validate() = %v, want ErrInvalidRuleset", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
		})
	}
}

func TestBaselineDeclaresItsOneExemption(t *testing.T) {
	rs := baseForTest(t)
	declared := map[string]string{}
	for _, r := range rs.ForbiddenStatements {
		if r.SafeAsFunction != "" {
			declared[r.ID] = r.SafeAsFunction
		}
	}
	if len(declared) != 1 || declared["stmt-replace"] == "" {
		t.Fatalf("the baseline declares %v, want exactly stmt-replace: every exemption is a loosening and each one has to be argued for on its own", declared)
	}
	// The argument has to name the statement forms it ruled out, or it is not an
	// argument. Guarding on length is crude; it is here so that replacing the
	// sentence with "reviewed" fails.
	if len(strings.Fields(declared["stmt-replace"])) < 20 {
		t.Fatalf("the stmt-replace exemption reads %q, which is too short to be an argument", declared["stmt-replace"])
	}
}

func TestMergeOverlay(t *testing.T) {
	t.Run("removes a rule", func(t *testing.T) {
		out, err := merge(baseForTest(t), &Overlay{Version: rulesetVersion, RemoveRules: []string{"stmt-waitfor"}})
		if err != nil {
			t.Fatalf("merge = %v", err)
		}
		for _, r := range out.ForbiddenStatements {
			if r.ID == "stmt-waitfor" {
				t.Fatalf("stmt-waitfor survived its removal")
			}
		}
	})

	t.Run("leaves the base untouched", func(t *testing.T) {
		base := baseForTest(t)
		before := len(base.ForbiddenStatements)
		if _, err := merge(base, &Overlay{Version: rulesetVersion, RemoveRules: []string{"stmt-waitfor"}}); err != nil {
			t.Fatalf("merge = %v", err)
		}
		if len(base.ForbiddenStatements) != before {
			t.Fatalf("merge mutated the ruleset it was given: %d rules, want %d", len(base.ForbiddenStatements), before)
		}
	})

	t.Run("removes a safe function", func(t *testing.T) {
		out, err := merge(baseForTest(t), &Overlay{Version: rulesetVersion, RemoveSafeFunctions: []string{"md5"}})
		if err != nil {
			t.Fatalf("merge = %v", err)
		}
		for _, a := range out.SafeFunctions {
			for _, n := range a.Names {
				if n == "md5" {
					t.Fatalf("md5 survived its removal")
				}
			}
		}
	})

	t.Run("rejects removing an absent rule", func(t *testing.T) {
		_, err := merge(baseForTest(t), &Overlay{Version: rulesetVersion, RemoveRules: []string{"stmt-nope"}})
		if !errors.Is(err, ErrInvalidRuleset) {
			t.Fatalf("merge = %v, want ErrInvalidRuleset", err)
		}
	})

	t.Run("rejects removing an absent safe function", func(t *testing.T) {
		_, err := merge(baseForTest(t), &Overlay{Version: rulesetVersion, RemoveSafeFunctions: []string{"not_a_builtin"}})
		if !errors.Is(err, ErrInvalidRuleset) {
			t.Fatalf("merge = %v, want ErrInvalidRuleset", err)
		}
	})

	t.Run("rejects a wrong version", func(t *testing.T) {
		_, err := merge(baseForTest(t), &Overlay{Version: rulesetVersion + 1})
		if !errors.Is(err, ErrInvalidRuleset) {
			t.Fatalf("merge = %v, want ErrInvalidRuleset", err)
		}
	})

	t.Run("validates the merged result", func(t *testing.T) {
		_, err := merge(baseForTest(t), &Overlay{
			Version:        rulesetVersion,
			ReadStatements: []Rule{{ID: "read-drop", Match: "drop", Reason: "a rule that contradicts the baseline"}},
		})
		if !errors.Is(err, ErrInvalidRuleset) {
			t.Fatalf("merge = %v, want ErrInvalidRuleset", err)
		}
	})
}

func TestDecodeRulesetRejectsUnknownFields(t *testing.T) {
	_, err := decodeRuleset([]byte(`{"version":1,"read_statementz":[]}`))
	if !errors.Is(err, ErrInvalidRuleset) {
		t.Fatalf("decodeRuleset = %v, want ErrInvalidRuleset", err)
	}
}

func TestRulesetIsACopy(t *testing.T) {
	g := newTestGate(t)
	rs := g.Ruleset()
	if len(rs.ForbiddenStatements) == 0 {
		t.Fatalf("the gate reports no forbidden statements")
	}
	rs.ForbiddenStatements = rs.ForbiddenStatements[:0]
	rs.SafeFunctions = nil
	if got := g.Validate(MySQL, "DROP TABLE t", nil); got.Verdict != Deny {
		t.Fatalf("mutating the reported ruleset changed the gate's verdict to %s", got.Verdict)
	}
}

func TestErrorsCarryThePackagePrefix(t *testing.T) {
	_, err := New("testdata/rulesets/duplicate-id.json")
	if err == nil {
		t.Fatalf("New = nil, want an error")
	}
	if !strings.HasPrefix(err.Error(), "gate: ") {
		t.Fatalf("error %q does not carry the package prefix", err)
	}
}
