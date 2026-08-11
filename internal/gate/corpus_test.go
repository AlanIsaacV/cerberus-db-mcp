package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusEntry mirrors testdata/corpus.json. The corpus is the safety evidence
// for this package, so it is reviewed as data and every field is required: a
// statement with no stated reason or no stated provenance is not evidence.
type corpusEntry struct {
	Statement string `json:"statement"`
	Engine    string `json:"engine"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
}

type corpusFile struct {
	LicenseNotes []string      `json:"license_notes"`
	Entries      []corpusEntry `json:"entries"`
}

const corpusPath = "testdata/corpus.json"

func loadCorpus(t testing.TB) corpusFile {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(corpusPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpusFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(c.Entries) == 0 {
		t.Fatalf("corpus has no entries")
	}
	return c
}

// caseName keeps subtest names readable and unique without putting a whole
// payload into the test output.
func (e corpusEntry) caseName(i int) string {
	s := strings.Join(strings.Fields(e.Statement), " ")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return fmt.Sprintf("%03d/%s/%s", i, e.Engine, s)
}

func TestCorpusSchema(t *testing.T) {
	c := loadCorpus(t)
	if len(c.LicenseNotes) == 0 {
		t.Fatalf("corpus records no licence notes")
	}
	engines := map[string]int{}
	verdicts := map[Verdict]int{}
	seen := map[string]bool{}
	for i, e := range c.Entries {
		t.Run(e.caseName(i), func(t *testing.T) {
			for _, f := range []struct{ name, value string }{
				{"statement", e.Statement},
				{"engine", e.Engine},
				{"verdict", e.Verdict},
				{"reason", e.Reason},
				{"source", e.Source},
			} {
				if strings.TrimSpace(f.value) == "" {
					t.Fatalf("entry %d has a missing or empty %s", i, f.name)
				}
			}
			engine, err := ParseEngine(e.Engine)
			if err != nil {
				t.Fatalf("entry %d names engine %q: %v", i, e.Engine, err)
			}
			switch Verdict(e.Verdict) {
			case Allow, Deny, NeedsApproval:
			default:
				t.Fatalf("entry %d has verdict %q", i, e.Verdict)
			}
			key := e.Engine + "\x00" + e.Statement
			if seen[key] {
				t.Fatalf("entry %d duplicates an earlier statement for %s", i, engine)
			}
			seen[key] = true
			engines[e.Engine]++
			verdicts[Verdict(e.Verdict)]++
		})
	}
	for _, e := range Engines() {
		if engines[string(e)] == 0 {
			t.Fatalf("the corpus covers no %s statements", e)
		}
	}
	for _, v := range []Verdict{Allow, Deny, NeedsApproval} {
		if verdicts[v] == 0 {
			t.Fatalf("the corpus contains no %s entries", v)
		}
	}
}

func TestCorpusVerdicts(t *testing.T) {
	g := newTestGate(t)
	c := loadCorpus(t)
	for i, e := range c.Entries {
		t.Run(e.caseName(i), func(t *testing.T) {
			engine, err := ParseEngine(e.Engine)
			if err != nil {
				t.Fatalf("engine %q: %v", e.Engine, err)
			}
			got := g.Validate(engine, e.Statement, nil)
			if got.Verdict != Verdict(e.Verdict) {
				t.Fatalf("Validate(%s, %q) = %s/%s rule %q (%s), want %s\ncorpus reason: %s",
					engine, e.Statement, got.Verdict, got.Reason, got.RuleID, got.Detail, e.Verdict, e.Reason)
			}
		})
	}
}

// TestCorpusNeverAllowsWhatItDoesNotMarkAllow is the allowlist claim stated as a
// test: whatever else the gate does with a hostile statement, it must not pass
// it.
func TestCorpusNeverAllowsWhatItDoesNotMarkAllow(t *testing.T) {
	g := newTestGate(t)
	c := loadCorpus(t)
	for i, e := range c.Entries {
		if Verdict(e.Verdict) == Allow {
			continue
		}
		t.Run(e.caseName(i), func(t *testing.T) {
			engine, err := ParseEngine(e.Engine)
			if err != nil {
				t.Fatalf("engine %q: %v", e.Engine, err)
			}
			if got := g.Validate(engine, e.Statement, nil); got.Verdict == Allow {
				t.Fatalf("Validate(%s, %q) = allow, want a refusal", engine, e.Statement)
			}
		})
	}
}

// TestKnownDangerousNeverEscalates holds the line between the two kinds of
// refusal: what the gate knows to be dangerous is terminal on every engine and
// is never offered for human approval, because a DROP a human can approve makes
// the read-only guarantee a habit rather than a guarantee.
func TestKnownDangerousNeverEscalates(t *testing.T) {
	g := newTestGate(t)
	c := loadCorpus(t)
	for i, e := range c.Entries {
		if Verdict(e.Verdict) != Deny {
			continue
		}
		t.Run(e.caseName(i), func(t *testing.T) {
			for _, engine := range Engines() {
				if got := g.Validate(engine, e.Statement, nil); got.Verdict == NeedsApproval {
					t.Fatalf("Validate(%s, %q) = needs-approval on rule %q, want a terminal deny or a refusal that is not escalatable",
						engine, e.Statement, got.RuleID)
				}
			}
		})
	}
}

// TestGrantsCannotUnblockADenyReplays the whole corpus with a grant for every
// rule the baseline defines. No deny may become an allow.
func TestGrantsCannotUnblockADeny(t *testing.T) {
	g := newTestGate(t)
	rs := g.Ruleset()
	var grants []Grant
	for _, group := range [][]Rule{rs.ReadStatements, rs.ForbiddenStatements, rs.ForbiddenFunctions} {
		for _, r := range group {
			grants = append(grants, Grant{RuleID: r.ID})
		}
	}
	c := loadCorpus(t)
	for i, e := range c.Entries {
		if Verdict(e.Verdict) != Deny {
			continue
		}
		t.Run(e.caseName(i), func(t *testing.T) {
			engine, err := ParseEngine(e.Engine)
			if err != nil {
				t.Fatalf("engine %q: %v", e.Engine, err)
			}
			if got := g.Validate(engine, e.Statement, grants); got.Verdict != Deny {
				t.Fatalf("Validate(%s, %q) with every baseline rule granted = %s, want deny", engine, e.Statement, got.Verdict)
			}
		})
	}
}
