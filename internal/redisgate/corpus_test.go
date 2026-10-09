package redisgate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const corpusPath = "testdata/corpus.json"

func sourceReasons(t *testing.T) []Reason {
	t.Helper()
	fset := gotoken.NewFileSet()
	var reasons []Reason
	for _, name := range nonTestSources(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != gotoken.CONST {
				continue
			}
			var typ ast.Expr
			var values []ast.Expr
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if vs.Type != nil || len(vs.Values) > 0 {
					typ, values = vs.Type, vs.Values
				}
				for i, ident := range vs.Names {
					var value ast.Expr
					if i < len(values) {
						value = values[i]
					}
					if call, ok := value.(*ast.CallExpr); ok && typ == nil && isReasonIdent(call.Fun) && len(call.Args) == 1 {
						value = call.Args[0]
					} else if !isReasonIdent(typ) {
						continue
					}
					lit, ok := value.(*ast.BasicLit)
					if !ok || lit.Kind != gotoken.STRING {
						t.Fatalf("%s: Reason constant %s is not a string literal this test can read", fset.Position(ident.Pos()), ident.Name)
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: unquote %s: %v", fset.Position(lit.Pos()), lit.Value, err)
					}
					reasons = append(reasons, Reason(v))
				}
			}
		}
	}
	if !slices.Contains(reasons, ReasonBoundedRead) || !slices.Contains(reasons, ReasonWrongArity) {
		t.Fatalf("the source scan found %v, which misses reasons the package is known to define", reasons)
	}
	return reasons
}

func isReasonIdent(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && ident.Name == "Reason"
}

type corpusArg string

func (a *corpusArg) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = corpusArg(s)
		return nil
	}
	var raw struct {
		Base64 *string `json:"base64"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return errors.New("an argv element is a string or {\"base64\": ...}: " + err.Error())
	}
	if raw.Base64 == nil {
		return errors.New("an argv element object has no base64 field")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(*raw.Base64)
	if err != nil {
		return errors.New("an argv element has invalid base64: " + err.Error())
	}
	*a = corpusArg(b)
	return nil
}

type corpusEntry struct {
	Argv    *[]corpusArg `json:"argv"`
	Verdict string       `json:"verdict"`
	Reason  string       `json:"reason"`
	Source  string       `json:"source"`
}

func (e corpusEntry) argv() []string {
	if e.Argv == nil {
		return nil
	}
	out := make([]string, len(*e.Argv))
	for i, a := range *e.Argv {
		out[i] = string(a)
	}
	return out
}

func (e corpusEntry) caseName(i int) string {
	return strconv.Itoa(i) + "/" + strconv.QuoteToASCII(argvName(e.argv()))
}

type corpusLimits struct {
	MaxElements int `json:"max_elements"`
	MaxCount    int `json:"max_count"`
	MaxArgs     int `json:"max_args"`
	MaxBytes    int `json:"max_bytes"`
}

type corpusFile struct {
	Notes   []string      `json:"notes"`
	Limits  corpusLimits  `json:"limits"`
	Entries []corpusEntry `json:"entries"`
}

func loadCorpus(t testing.TB) corpusFile {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(corpusPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if !utf8.Valid(data) {
		t.Fatalf("the corpus file is not valid UTF-8; write raw bytes as {\"base64\": ...}")
	}
	var c corpusFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(c.Entries) == 0 {
		t.Fatalf("corpus has no entries")
	}
	return c
}

func corpusGate(t testing.TB, c corpusFile) *Gate {
	t.Helper()
	l := Limits{
		MaxElements: c.Limits.MaxElements,
		MaxCount:    c.Limits.MaxCount,
		MaxArgs:     c.Limits.MaxArgs,
		MaxBytes:    c.Limits.MaxBytes,
	}
	g, err := New(l)
	if err != nil {
		t.Fatalf("the corpus limits %+v do not build a gate: %v", c.Limits, err)
	}
	return g
}

func argvKey(argv []string) string {
	var b strings.Builder
	for _, a := range argv {
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteByte(':')
		b.WriteString(a)
	}
	return b.String()
}

func TestCorpusSchema(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Notes) == 0 {
		t.Fatalf("the corpus records no notes on its encoding")
	}
	allReasons := sourceReasons(t)
	known := map[Reason]bool{}
	for _, r := range allReasons {
		known[r] = true
	}
	reasons := map[Reason]int{}
	seen := map[string]int{}
	for i, e := range c.Entries {
		t.Run(e.caseName(i), func(t *testing.T) {
			if e.Argv == nil {
				t.Fatalf("entry %d has no argv", i)
			}
			for _, f := range []struct{ name, value string }{
				{"verdict", e.Verdict},
				{"reason", e.Reason},
				{"source", e.Source},
			} {
				if strings.TrimSpace(f.value) == "" {
					t.Fatalf("entry %d has a missing or empty %s", i, f.name)
				}
			}
			switch Verdict(e.Verdict) {
			case Allow, Deny:
			default:
				t.Fatalf("entry %d has verdict %q", i, e.Verdict)
			}
			if !known[Reason(e.Reason)] {
				t.Fatalf("entry %d has reason %q, which the gate does not define", i, e.Reason)
			}
			if (Verdict(e.Verdict) == Allow) != (Reason(e.Reason) == ReasonBoundedRead) {
				t.Fatalf("entry %d pairs verdict %s with reason %s", i, e.Verdict, e.Reason)
			}
			key := argvKey(e.argv())
			if first, dup := seen[key]; dup {
				t.Fatalf("entry %d duplicates entry %d", i, first)
			}
			seen[key] = i
			reasons[Reason(e.Reason)]++
		})
	}
	for _, r := range allReasons {
		if reasons[r] == 0 {
			t.Errorf("the corpus has no entry with reason %s", r)
		}
	}
}

func TestCorpusVerdicts(t *testing.T) {
	c := loadCorpus(t)
	g := corpusGate(t, c)
	for i, e := range c.Entries {
		t.Run(e.caseName(i), func(t *testing.T) {
			argv := e.argv()
			got := g.Validate(argv)
			if got.Verdict != Verdict(e.Verdict) || got.Reason != Reason(e.Reason) {
				t.Fatalf("Validate(%q) = %s/%s rule %q (%s), want %s/%s\nsource: %s",
					argv, got.Verdict, got.Reason, got.RuleID, got.Detail, e.Verdict, e.Reason, e.Source)
			}
		})
	}
}

func TestCorpusCoversEveryAllowlistedCommand(t *testing.T) {
	c := loadCorpus(t)
	g := corpusGate(t, c)
	allowed := map[string]int{}
	denied := map[string]int{}
	for _, e := range c.Entries {
		d := g.Validate(e.argv())
		if d.Verdict == Allow {
			allowed[d.RuleID]++
		} else {
			denied[d.RuleID]++
		}
	}
	for _, cmd := range Allowlist() {
		if allowed[cmd.RuleID] == 0 {
			t.Errorf("the corpus never allows %s", commandLabel(cmd))
		}
		if denied[cmd.RuleID] == 0 {
			t.Errorf("the corpus never denies a form of %s", commandLabel(cmd))
		}
	}
}
