package gate

import (
	"slices"
	"strings"
	"testing"
)

// fuzzGrants are held active throughout the fuzz run so that the grant path is
// exercised rather than skipped. The ruleset IDs among them are there to prove
// they do nothing: a grant naming a terminal-deny rule is not a way through.
var fuzzGrants = []Grant{
	{RuleID: "function:f"},
	{RuleID: "function:dbo.f"},
	{RuleID: "function:a"},
	{RuleID: "stmt-drop"},
	{RuleID: "fn-xp-cmdshell"},
	{RuleID: "read-select"},
}

// knownWrites are appended to inputs the gate accepts. Each begins with a
// newline so that an accepted statement ending inside a line comment cannot
// swallow the write: that is the one shape where a suffix would otherwise land
// somewhere the tokenizer never looks.
var knownWrites = []string{
	"\nDROP TABLE t",
	"\n; DELETE FROM t",
	"\nUPDATE t SET a = 1",
	"\nEXEC xp_cmdshell 'whoami'",
}

// FuzzGate drives the gate with corpus statements and whatever the fuzzer
// derives from them. Two properties are asserted on every input: the gate
// terminates without panicking and returns the same verdict twice, and no
// accepted statement stays accepted once a known write is appended to it.
func FuzzGate(f *testing.F) {
	g, err := New("")
	if err != nil {
		f.Fatalf("New(\"\") = %v", err)
	}
	for _, e := range loadCorpus(f).Entries {
		f.Add(e.Statement)
	}
	// Shapes the mutator could not reach from the corpus alone. The nested
	// comment followed by a line-comment introducer is the class that hid a
	// fail-open: a comment misjudged by one character puts the rest of the line
	// out of the tokenizer's sight while the server still executes it.
	for _, s := range []string{
		"", "$", "/*!", "--", "[", "'", "$tag$", "`", "\\",
		"SELECT 1 /* /* */ -- */ , f()",
		"SELECT 1 /* /* */ # */ , f()",
		"SELECT 1 /* /* /* */ */ -- */ , f()",
		"SELECT 1 /* /* */ -- */ ; DROP TABLE t",
		"SELECT 1 /*!50000 /* */ -- */ , f()",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, statement string) {
		for _, engine := range Engines() {
			got := g.Validate(engine, statement, fuzzGrants)
			switch got.Verdict {
			case Allow, Deny, NeedsApproval:
			default:
				t.Fatalf("Validate(%s, %q) returned verdict %q", engine, statement, got.Verdict)
			}
			// Every reported field, not just the verdict: Pending and GrantsUsed
			// are part of the audit record, and an order that came out of a map
			// would be stable right up until it was not.
			if again := g.Validate(engine, statement, fuzzGrants); again.Verdict != got.Verdict || again.Reason != got.Reason ||
				again.RuleID != got.RuleID || again.Detail != got.Detail ||
				!slices.Equal(again.Pending, got.Pending) || !slices.Equal(again.GrantsUsed, got.GrantsUsed) {
				t.Fatalf("Validate(%s, %q) is not deterministic: %+v then %+v", engine, statement, got, again)
			}
			if got.Verdict != Allow && len(got.GrantsUsed) != 0 {
				t.Fatalf("Validate(%s, %q) = %s but reports grants used: %v", engine, statement, got.Verdict, got.GrantsUsed)
			}
			if got.Verdict != Allow {
				continue
			}
			for _, w := range knownWrites {
				extended := g.Validate(engine, statement+w, fuzzGrants)
				if extended.Verdict == Allow {
					t.Fatalf("Validate(%s, %q) = allow, but %q with %q appended is still allow",
						engine, statement, statement, strings.TrimSpace(w))
				}
			}
		}
	})
}
