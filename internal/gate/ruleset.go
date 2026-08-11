package gate

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

// rulesetVersion is the schema version this build understands. A ruleset file
// written for a different schema is rejected rather than partially applied.
const rulesetVersion = 1

// minStatementBytes is the floor an operator may not lower the statement bound
// below. It is set at a size no realistic read can fit under, so that a bound
// tightened into uselessness is a validation error rather than a gate that
// refuses everything.
const minStatementBytes = 4096

//go:embed baseline.json
var baselineJSON []byte

// ErrInvalidRuleset identifies a ruleset that is malformed or semantically
// inconsistent. It is never partially applied: a gate either holds a ruleset
// that passed validation whole, or it does not exist.
var ErrInvalidRuleset = errors.New("invalid ruleset")

// Rule is one named decision the gate can point at. The identity matters as
// much as the match: a [Grant] names a rule, a [Decision] reports one, and an
// overlay removes one by ID.
type Rule struct {
	// ID is stable across ruleset edits and is what a grant and a decision name.
	ID string `json:"id"`
	// Match is a lowercase keyword, a lowercase space-separated keyword phrase,
	// or a function name that may be schema-qualified with dots.
	Match string `json:"match"`
	// Engines restricts the rule to the listed engines; empty means every engine.
	Engines []Engine `json:"engines,omitempty"`
	// Reason is the machine-readable explanation surfaced to the caller.
	Reason string `json:"reason"`
	// Prefix marks a read statement that introduces another statement, as
	// EXPLAIN and DESCRIBE do, so that the one statement keyword following it is
	// a continuation rather than a second statement. It is meaningless, and
	// rejected, on any other kind of rule.
	Prefix bool `json:"prefix,omitempty"`
	// SafeAsFunction is the argument for why a safe builtin of this same name
	// does not disable this keyword rule: why no form of this statement can put
	// the keyword immediately before an opening parenthesis. It is a string
	// rather than a flag so that the exemption cannot be claimed without one —
	// an empty or whitespace-only value is not a declaration.
	//
	// Without a declaration, a name in SafeFunctions colliding with a forbidden
	// keyword is a validation error, because such a name silently disables the
	// keyword rule: EXECUTE('...') is valid T-SQL, so listing "execute" as a
	// safe function would let it through. Nothing here verifies the argument.
	// It exists so that the loosening appears in the ruleset's diff as a
	// sentence somebody had to write and can be held to.
	//
	// It is meaningless, and rejected, on any rule but a forbidden statement.
	SafeAsFunction string `json:"safe_as_function,omitempty"`
}

// declaresSafeAsFunction reports whether the rule carries a real argument, as
// opposed to none or a blank one.
func (r Rule) declaresSafeAsFunction() bool {
	return strings.TrimSpace(r.SafeAsFunction) != ""
}

// FunctionAllowance lists function names that are safe to call. It carries no
// rule ID because there is nothing to grant or to report: a safe function
// raises no obstacle.
type FunctionAllowance struct {
	Engines []Engine `json:"engines,omitempty"`
	Names   []string `json:"names"`
	// Reason documents the group for whoever reviews the ruleset. It is not
	// reported in any decision, because an allowance produces no obstacle.
	Reason string `json:"reason,omitempty"`
}

// Ruleset is the gate's rules as data. The baseline is embedded in the binary;
// an [Overlay] read from disk may add to it or take rules out of it.
type Ruleset struct {
	Version int `json:"version"`
	// Notes is for whoever reviews the ruleset. JSON has no comments and this
	// file is meant to be read by people, so the reasoning behind a number
	// lives next to the number.
	Notes []string `json:"notes,omitempty"`
	// MaxStatementBytes is the longest statement the gate will look at. Beyond
	// it the answer is a refusal, because the gate runs before anything else on
	// agent-supplied text and an unbounded input is an unbounded amount of work
	// on a request-handling goroutine.
	MaxStatementBytes int `json:"max_statement_bytes"`
	// ReadStatements is the allowlist of leading keywords. A statement whose
	// leading keyword is absent from it cannot be proven to be a read.
	ReadStatements []Rule `json:"read_statements"`
	// ForbiddenStatements are keywords and keyword phrases whose presence
	// anywhere in the statement is a terminal refusal, not merely in the leading
	// position: this is what catches a write hidden inside a CTE.
	ForbiddenStatements []Rule `json:"forbidden_statements"`
	// ForbiddenFunctions are named functions, rowset sources and procedures
	// whose presence anywhere is a terminal refusal.
	ForbiddenFunctions []Rule `json:"forbidden_functions"`
	// SafeFunctions is the allowlist that closes layer 3: any name called as a
	// function and absent from it is escalated rather than allowed.
	SafeFunctions []FunctionAllowance `json:"safe_functions"`
	// NonFunctionKeywords are reserved words that may be followed by an opening
	// parenthesis without that being a function call — IN (...), WITH (NOLOCK),
	// VARCHAR(10). Omitting one costs an unnecessary escalation; it cannot cost
	// an allow.
	NonFunctionKeywords []string `json:"non_function_keywords"`
}

// Overlay is the operator-controlled patch applied on top of the baseline. It
// can loosen the gate — that is its purpose and its danger — so it is validated
// in full, as part of the merged ruleset, before it takes effect.
type Overlay struct {
	Version int      `json:"version"`
	Notes   []string `json:"notes,omitempty"`
	// MaxStatementBytes replaces the baseline's bound when present. It is a
	// pointer so that an overlay that does not mention it leaves the bound
	// alone rather than setting it to zero.
	MaxStatementBytes   *int                `json:"max_statement_bytes,omitempty"`
	ReadStatements      []Rule              `json:"read_statements,omitempty"`
	ForbiddenStatements []Rule              `json:"forbidden_statements,omitempty"`
	ForbiddenFunctions  []Rule              `json:"forbidden_functions,omitempty"`
	SafeFunctions       []FunctionAllowance `json:"safe_functions,omitempty"`
	NonFunctionKeywords []string            `json:"non_function_keywords,omitempty"`
	// RemoveRules names baseline rule IDs to drop. An ID that is not present is
	// an error rather than a no-op, so a typo cannot silently leave a rule the
	// operator believed they had removed.
	RemoveRules []string `json:"remove_rules,omitempty"`
	// RemoveSafeFunctions tightens the safe-builtin allowlist.
	RemoveSafeFunctions []string `json:"remove_safe_functions,omitempty"`
}

// BaselineRuleset decodes a fresh copy of the ruleset embedded in the binary.
// The copy is independent: mutating it cannot affect any live gate.
func BaselineRuleset() (*Ruleset, error) {
	rs, err := decodeRuleset(baselineJSON)
	if err != nil {
		return nil, fmt.Errorf("gate: decode baseline ruleset: %w", err)
	}
	if err := rs.validate(); err != nil {
		return nil, fmt.Errorf("gate: validate baseline ruleset: %w", err)
	}
	return rs, nil
}

func decodeRuleset(data []byte) (*Ruleset, error) {
	var rs Ruleset
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidRuleset)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing content after the ruleset object: %w", ErrInvalidRuleset)
	}
	return &rs, nil
}

func loadOverlay(path string) (*Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gate: read ruleset overlay: %w", err)
	}
	var ov Overlay
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ov); err != nil {
		return nil, fmt.Errorf("gate: decode ruleset overlay: %w: %w", err, ErrInvalidRuleset)
	}
	if dec.More() {
		return nil, fmt.Errorf("gate: decode ruleset overlay: trailing content: %w", ErrInvalidRuleset)
	}
	return &ov, nil
}

// merge applies an overlay to a copy of base and returns the result. base is not
// modified, so a merge that fails validation leaves nothing behind.
func merge(base *Ruleset, ov *Overlay) (*Ruleset, error) {
	if ov.Version != rulesetVersion {
		return nil, fmt.Errorf("gate: merge ruleset overlay: version %d is not %d: %w", ov.Version, rulesetVersion, ErrInvalidRuleset)
	}
	out := &Ruleset{
		Version:             base.Version,
		Notes:               slices.Concat(base.Notes, ov.Notes),
		MaxStatementBytes:   base.MaxStatementBytes,
		ReadStatements:      slices.Clone(base.ReadStatements),
		ForbiddenStatements: slices.Clone(base.ForbiddenStatements),
		ForbiddenFunctions:  slices.Clone(base.ForbiddenFunctions),
		SafeFunctions:       slices.Clone(base.SafeFunctions),
		NonFunctionKeywords: slices.Clone(base.NonFunctionKeywords),
	}

	for _, id := range ov.RemoveRules {
		before := len(out.ReadStatements) + len(out.ForbiddenStatements) + len(out.ForbiddenFunctions)
		drop := func(r Rule) bool { return r.ID == id }
		out.ReadStatements = slices.DeleteFunc(out.ReadStatements, drop)
		out.ForbiddenStatements = slices.DeleteFunc(out.ForbiddenStatements, drop)
		out.ForbiddenFunctions = slices.DeleteFunc(out.ForbiddenFunctions, drop)
		after := len(out.ReadStatements) + len(out.ForbiddenStatements) + len(out.ForbiddenFunctions)
		if before == after {
			return nil, fmt.Errorf("gate: merge ruleset overlay: no rule %q to remove: %w", id, ErrInvalidRuleset)
		}
	}

	for _, name := range ov.RemoveSafeFunctions {
		removed := false
		for i := range out.SafeFunctions {
			names := slices.Clone(out.SafeFunctions[i].Names)
			trimmed := slices.DeleteFunc(names, func(n string) bool { return n == name })
			if len(trimmed) != len(names) {
				removed = true
			}
			out.SafeFunctions[i].Names = trimmed
		}
		if !removed {
			return nil, fmt.Errorf("gate: merge ruleset overlay: no safe function %q to remove: %w", name, ErrInvalidRuleset)
		}
	}

	if ov.MaxStatementBytes != nil {
		out.MaxStatementBytes = *ov.MaxStatementBytes
	}

	out.ReadStatements = append(out.ReadStatements, ov.ReadStatements...)
	out.ForbiddenStatements = append(out.ForbiddenStatements, ov.ForbiddenStatements...)
	out.ForbiddenFunctions = append(out.ForbiddenFunctions, ov.ForbiddenFunctions...)
	out.SafeFunctions = append(out.SafeFunctions, ov.SafeFunctions...)
	out.NonFunctionKeywords = append(out.NonFunctionKeywords, ov.NonFunctionKeywords...)

	if err := out.validate(); err != nil {
		return nil, fmt.Errorf("gate: validate merged ruleset: %w", err)
	}
	return out, nil
}

// validate checks the whole ruleset. It runs before any ruleset takes effect,
// including the merged result of an overlay, because a half-checked ruleset is
// indistinguishable from a loosened one.
func (rs *Ruleset) validate() error {
	if rs.Version != rulesetVersion {
		return fmt.Errorf("version %d is not %d: %w", rs.Version, rulesetVersion, ErrInvalidRuleset)
	}
	if rs.MaxStatementBytes < minStatementBytes {
		return fmt.Errorf("max_statement_bytes is %d, below the %d floor: %w", rs.MaxStatementBytes, minStatementBytes, ErrInvalidRuleset)
	}
	if len(rs.ReadStatements) == 0 {
		return fmt.Errorf("no read statements: %w", ErrInvalidRuleset)
	}
	if len(rs.ForbiddenStatements) == 0 {
		return fmt.Errorf("no forbidden statements: %w", ErrInvalidRuleset)
	}

	ids := make(map[string]bool)
	for _, group := range [][]Rule{rs.ReadStatements, rs.ForbiddenStatements, rs.ForbiddenFunctions} {
		for _, r := range group {
			if err := r.validate(); err != nil {
				return err
			}
			if ids[r.ID] {
				return fmt.Errorf("rule ID %q is used twice: %w", r.ID, ErrInvalidRuleset)
			}
			ids[r.ID] = true
		}
	}

	for _, r := range rs.ReadStatements {
		if strings.ContainsAny(r.Match, " .") {
			return fmt.Errorf("read statement %q must match a single keyword: %w", r.ID, ErrInvalidRuleset)
		}
	}
	for _, r := range rs.ForbiddenFunctions {
		if strings.Contains(r.Match, " ") {
			return fmt.Errorf("forbidden function %q must match a single name: %w", r.ID, ErrInvalidRuleset)
		}
	}
	for _, group := range [][]Rule{rs.ForbiddenStatements, rs.ForbiddenFunctions} {
		for _, r := range group {
			if r.Prefix {
				return fmt.Errorf("rule %q sets prefix, which only read statements may do: %w", r.ID, ErrInvalidRuleset)
			}
		}
	}
	for _, group := range [][]Rule{rs.ReadStatements, rs.ForbiddenFunctions} {
		for _, r := range group {
			if r.SafeAsFunction != "" {
				return fmt.Errorf("rule %q sets safe_as_function, which only forbidden statements may do: %w", r.ID, ErrInvalidRuleset)
			}
		}
	}
	for _, r := range rs.ForbiddenStatements {
		if r.SafeAsFunction != "" && !r.declaresSafeAsFunction() {
			return fmt.Errorf("rule %q sets safe_as_function to a blank reason, which declares nothing: %w", r.ID, ErrInvalidRuleset)
		}
	}

	// A keyword that is both a permitted leading keyword and a forbidden keyword
	// would make the verdict depend on evaluation order rather than on the rules.
	for _, read := range rs.ReadStatements {
		for _, forbidden := range rs.ForbiddenStatements {
			if read.Match == forbidden.Match && enginesOverlap(read.Engines, forbidden.Engines) {
				return fmt.Errorf("keyword %q is both read rule %q and forbidden rule %q: %w", read.Match, read.ID, forbidden.ID, ErrInvalidRuleset)
			}
		}
	}

	safe := make(map[string][]Engine)
	for _, a := range rs.SafeFunctions {
		for _, e := range a.Engines {
			if !e.Valid() {
				return fmt.Errorf("safe functions name engine %q: %w", e, ErrUnknownEngine)
			}
		}
		for _, n := range a.Names {
			if n == "" || n != strings.ToLower(n) || strings.ContainsAny(n, " \t") {
				return fmt.Errorf("safe function %q must be a lowercase name: %w", n, ErrInvalidRuleset)
			}
			if _, ok := safe[n]; ok && len(a.Engines) == 0 {
				safe[n] = nil
				continue
			}
			safe[n] = append(safe[n], a.Engines...)
		}
	}
	for _, r := range rs.ForbiddenFunctions {
		if _, ok := safe[r.Match]; ok {
			return fmt.Errorf("function %q is both safe and forbidden rule %q: %w", r.Match, r.ID, ErrInvalidRuleset)
		}
	}
	// A safe function whose name is also a forbidden keyword silently disables
	// that keyword rule, because a name on the safe list skips the phrase check.
	// That is a loosening, so it has to be argued for on the keyword rule rather
	// than arrived at by adding a name to an allowlist.
	for _, r := range rs.ForbiddenStatements {
		engines, ok := safe[r.Match]
		if !ok || r.declaresSafeAsFunction() {
			continue
		}
		if enginesOverlap(engines, r.Engines) {
			return fmt.Errorf("safe function %q disables forbidden rule %q, which states no safe_as_function reason: %w", r.Match, r.ID, ErrInvalidRuleset)
		}
	}

	for _, k := range rs.NonFunctionKeywords {
		if k == "" || k != strings.ToLower(k) || strings.ContainsAny(k, " \t") {
			return fmt.Errorf("non-function keyword %q must be a lowercase word: %w", k, ErrInvalidRuleset)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("a rule has an empty ID: %w", ErrInvalidRuleset)
	}
	if r.Match == "" || r.Match != strings.ToLower(r.Match) || r.Match != strings.Join(strings.Fields(r.Match), " ") {
		return fmt.Errorf("rule %q must match lowercase words separated by single spaces: %w", r.ID, ErrInvalidRuleset)
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("rule %q has an empty reason: %w", r.ID, ErrInvalidRuleset)
	}
	for _, e := range r.Engines {
		if !e.Valid() {
			return fmt.Errorf("rule %q names engine %q: %w", r.ID, e, ErrUnknownEngine)
		}
	}
	return nil
}

func enginesOverlap(a, b []Engine) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func ruleApplies(r Rule, e Engine) bool {
	return len(r.Engines) == 0 || slices.Contains(r.Engines, e)
}

// phrase is a forbidden keyword rule compiled into the token sequence it
// matches.
type phrase struct {
	words []string
	rule  Rule
}

// compiled is the immutable lookup form of a ruleset. A [Gate] swaps a pointer
// to one of these, so a reader either sees the whole previous ruleset or the
// whole new one.
type compiled struct {
	source     *Ruleset
	read       map[Engine]map[string]Rule
	forbidden  map[string][]phrase // keyed by the first word of the phrase
	forbidFunc map[Engine]map[string]Rule
	safeFunc   map[Engine]map[string]bool
	nonFunc    map[string]bool
}

func compile(rs *Ruleset) *compiled {
	c := &compiled{
		source:     rs,
		read:       map[Engine]map[string]Rule{},
		forbidden:  map[string][]phrase{},
		forbidFunc: map[Engine]map[string]Rule{},
		safeFunc:   map[Engine]map[string]bool{},
		nonFunc:    map[string]bool{},
	}
	for _, e := range Engines() {
		c.read[e] = map[string]Rule{}
		c.forbidFunc[e] = map[string]Rule{}
		c.safeFunc[e] = map[string]bool{}
	}
	for _, r := range rs.ReadStatements {
		for _, e := range Engines() {
			if ruleApplies(r, e) {
				c.read[e][r.Match] = r
			}
		}
	}
	for _, r := range rs.ForbiddenStatements {
		words := strings.Fields(r.Match)
		c.forbidden[words[0]] = append(c.forbidden[words[0]], phrase{words: words, rule: r})
	}
	// Longer phrases first so that "execute as" reports itself rather than the
	// bare "execute" rule that also matches.
	for k := range c.forbidden {
		slices.SortStableFunc(c.forbidden[k], func(a, b phrase) int { return len(b.words) - len(a.words) })
	}
	for _, r := range rs.ForbiddenFunctions {
		for _, e := range Engines() {
			if ruleApplies(r, e) {
				c.forbidFunc[e][r.Match] = r
			}
		}
	}
	for _, a := range rs.SafeFunctions {
		for _, e := range Engines() {
			if len(a.Engines) != 0 && !slices.Contains(a.Engines, e) {
				continue
			}
			for _, n := range a.Names {
				c.safeFunc[e][n] = true
			}
		}
	}
	for _, k := range rs.NonFunctionKeywords {
		c.nonFunc[k] = true
	}
	return c
}
