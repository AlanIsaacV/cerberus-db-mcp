package gate

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Verdict is the gate's answer for one statement. It is three-valued: the third
// value exists so that what the gate cannot classify can be escalated to a human
// instead of being refused forever, and it is reachable only from the
// unclassifiable. Everything known to be dangerous is a terminal [Deny] and is
// never offered for approval.
type Verdict string

const (
	Allow         Verdict = "allow"
	Deny          Verdict = "deny"
	NeedsApproval Verdict = "needs-approval"
)

// Reason is the machine-readable explanation of a verdict.
type Reason string

const (
	ReasonReadStatement       Reason = "read-statement"
	ReasonInvalidEngine       Reason = "invalid-engine"
	ReasonNoRuleset           Reason = "no-ruleset"
	ReasonTokenizeError       Reason = "tokenize-error"
	ReasonStatementTooLong    Reason = "statement-too-long"
	ReasonEmptyStatement      Reason = "empty-statement"
	ReasonLeadingTokenNotWord Reason = "leading-token-not-a-keyword"
	ReasonMultipleStatements  Reason = "multiple-statements"
	ReasonUnbalancedParens    Reason = "unbalanced-parentheses"
	ReasonForbiddenStatement  Reason = "forbidden-statement"
	ReasonForbiddenConstruct  Reason = "forbidden-construct"
	ReasonUnknownStatement    Reason = "unknown-statement"
	ReasonUnknownFunction     Reason = "unknown-function"
)

// Decision is what the gate returns. It carries no part of the statement's data
// and no configuration, only rule identities and keywords the caller itself
// submitted.
type Decision struct {
	Verdict Verdict `json:"verdict"`
	Reason  Reason  `json:"reason"`
	// RuleID identifies the rule that produced the verdict: the read rule that
	// permitted an [Allow], the rule that refused a [Deny], and for
	// [NeedsApproval] the rule a [Grant] must name to unblock the statement.
	RuleID string `json:"rule_id,omitempty"`
	// Pending lists every ungranted obstacle, first one first. A statement with
	// two unknown functions needs both granted, and reporting only the first
	// would make approval look like a single step when it is not.
	Pending []string `json:"pending,omitempty"`
	// GrantsUsed lists the grants an [Allow] actually depended on, empty when
	// the statement needed none. It is what makes a grant-enabled allow
	// auditable after the fact: RuleID stays the read rule that permitted the
	// statement's shape, which is one value and cannot also carry the two grants
	// a statement with two unknown functions consumed.
	GrantsUsed []string `json:"grants_used,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

// Gate evaluates statements against the ruleset currently in force. It is safe
// for concurrent use, and a [Gate.Reload] running under load never exposes a
// half-applied ruleset.
type Gate struct {
	overlayPath string
	rules       atomic.Pointer[compiled]
	reloadMu    sync.Mutex
}

// New builds a gate from the embedded baseline ruleset, overlaid by the file at
// overlayPath when that is not empty. It returns an error rather than a gate
// whose rules failed to load or validate: a gate with no rules must be
// impossible to construct.
//
// An overlayPath that does not exist is not an error — the baseline is then in
// force. Any other read failure is.
func New(overlayPath string) (*Gate, error) {
	g := &Gate{overlayPath: overlayPath}
	c, err := g.loadRules()
	if err != nil {
		return nil, err
	}
	g.rules.Store(c)
	return g, nil
}

// Reload re-reads the overlay and swaps the ruleset atomically. On any failure
// the previous ruleset stays entirely in force and the error describes what was
// rejected; there is no partial application.
func (g *Gate) Reload() error {
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	c, err := g.loadRules()
	if err != nil {
		return err
	}
	g.rules.Store(c)
	return nil
}

// Ruleset returns the ruleset in force, deeply copied, so that inspecting or
// mutating it cannot reach the rules the gate is deciding with.
func (g *Gate) Ruleset() *Ruleset {
	c := g.rules.Load()
	if c == nil {
		return nil
	}
	rs := *c.source
	rs.ReadStatements = cloneRules(rs.ReadStatements)
	rs.ForbiddenStatements = cloneRules(rs.ForbiddenStatements)
	rs.ForbiddenFunctions = cloneRules(rs.ForbiddenFunctions)
	rs.SafeFunctions = slices.Clone(rs.SafeFunctions)
	for i := range rs.SafeFunctions {
		rs.SafeFunctions[i].Engines = slices.Clone(rs.SafeFunctions[i].Engines)
		rs.SafeFunctions[i].Names = slices.Clone(rs.SafeFunctions[i].Names)
	}
	rs.NonFunctionKeywords = slices.Clone(rs.NonFunctionKeywords)
	return &rs
}

func cloneRules(in []Rule) []Rule {
	out := slices.Clone(in)
	for i := range out {
		out[i].Engines = slices.Clone(out[i].Engines)
	}
	return out
}

// Exemption is one active safe_as_function declaration: a forbidden keyword
// rule that has argued for why a safe builtin of its own name does not disable
// it.
type Exemption struct {
	// RuleID and Keyword identify the forbidden statement rule that carries the
	// declaration.
	RuleID  string `json:"rule_id"`
	Keyword string `json:"keyword"`
	// Engines is the rule's scope; empty means every engine.
	Engines []Engine `json:"engines,omitempty"`
	// SafeFunction is the colliding safe-builtin name when one is present in the
	// same ruleset, and empty when the declaration is Dangling.
	SafeFunction string `json:"safe_function,omitempty"`
	// Dangling marks a declaration with no colliding safe function in the
	// ruleset as it stands. Such a declaration changes no verdict today. It is
	// reported, and reported prominently, because it is the one that becomes
	// live the moment some later edit adds the name — see [Gate.Exemptions].
	Dangling bool `json:"dangling"`
	// Argument is the declared reason, verbatim. Nothing verifies it.
	Argument string `json:"argument"`
}

// Exemptions reports every safe_as_function declaration in the ruleset
// currently in force. It reads the same pointer the decision path reads, so it
// reflects whatever the last successful [Gate.Reload] installed rather than
// what was on disk at construction, and it is safe to call concurrently with
// [Gate.Validate] and [Gate.Reload]. The result is a copy.
//
// What it is for. A safe_as_function declaration is a claim this package does
// not check — it can tell that an argument was written, not that it is true —
// and it is the one thing in a ruleset that can turn a statement the gate would
// refuse into one it allows without a human in the loop. This accessor is the
// counterpart control: it lets the layer that loads rulesets state every active
// exemption on every load, so the claims are on the record even when no diff
// shows them.
//
// The case that motivates it. Adding a name to safe_functions in one edit,
// against a declaration written in an earlier edit, is a real loosening whose
// diff says only "added a name to an allowlist" — the sentence that makes it
// dangerous sits elsewhere in the file, unchanged, and so outside that diff. A
// reviewer of the second edit alone cannot see the argument they are accepting.
// Reading it out of the loaded ruleset is what makes it visible again, which is
// also why a Dangling declaration is reported rather than filtered out for
// being currently inert.
//
// This package cannot log — it has no clock and no I/O beyond reading the
// ruleset — so the accessor is the whole of its part. Doing something with it
// belongs to the objective that owns the server.
func (g *Gate) Exemptions() []Exemption {
	c := g.rules.Load()
	if c == nil {
		return nil
	}
	var out []Exemption
	for _, r := range c.source.ForbiddenStatements {
		if !r.declaresSafeAsFunction() {
			continue
		}
		e := Exemption{
			RuleID:   r.ID,
			Keyword:  r.Match,
			Engines:  slices.Clone(r.Engines),
			Argument: r.SafeAsFunction,
			Dangling: true,
		}
		for _, engine := range Engines() {
			if ruleApplies(r, engine) && c.safeFunc[engine][r.Match] {
				e.SafeFunction = r.Match
				e.Dangling = false
				break
			}
		}
		out = append(out, e)
	}
	return out
}

func (g *Gate) loadRules() (*compiled, error) {
	base, err := BaselineRuleset()
	if err != nil {
		return nil, err
	}
	if g.overlayPath == "" {
		return compile(base), nil
	}
	ov, err := loadOverlay(g.overlayPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return compile(base), nil
		}
		return nil, err
	}
	merged, err := merge(base, ov)
	if err != nil {
		return nil, err
	}
	return compile(merged), nil
}

// Validate decides whether statement is provably a single read under engine's
// rules, given the grants currently active. grants may be nil.
func (g *Gate) Validate(engine Engine, statement string, grants []Grant) Decision {
	c := g.rules.Load()
	if c == nil {
		return Decision{Verdict: Deny, Reason: ReasonNoRuleset, Detail: "no ruleset is in force"}
	}
	if !engine.Valid() {
		return Decision{Verdict: Deny, Reason: ReasonInvalidEngine, Detail: fmt.Sprintf("engine %q has no lexical rules", engine)}
	}
	// The bound is checked before tokenizing, not after: the work this refuses
	// is the tokenizing itself. The gate runs before anything else on
	// agent-supplied text, on the goroutine handling the request.
	if len(statement) > c.source.MaxStatementBytes {
		return Decision{
			Verdict: Deny,
			Reason:  ReasonStatementTooLong,
			Detail:  fmt.Sprintf("the statement is %d bytes, over the %d-byte bound", len(statement), c.source.MaxStatementBytes),
		}
	}
	toks, err := tokenize(engine, statement)
	if err != nil {
		return Decision{Verdict: Deny, Reason: ReasonTokenizeError, Detail: err.Error()}
	}
	if len(toks) == 0 {
		return Decision{Verdict: Deny, Reason: ReasonEmptyStatement, Detail: "the statement contains no tokens"}
	}
	return c.analyse(engine, toks, grants)
}

// obstacle is one reason a statement cannot be allowed. Terminal obstacles deny;
// escalatable ones are the unclassifiable, and a grant naming their rule ID
// clears them.
type obstacle struct {
	reason Reason
	ruleID string
	detail string
}

func (c *compiled) analyse(engine Engine, toks []token, grants []Grant) Decision {
	if toks[0].kind != tokenWord {
		return Decision{
			Verdict: Deny,
			Reason:  ReasonLeadingTokenNotWord,
			Detail:  "the statement does not begin with a keyword",
		}
	}

	var terminal []obstacle
	var escalatable []obstacle
	seen := map[string]bool{}
	deny := func(reason Reason, ruleID, detail string) {
		terminal = append(terminal, obstacle{reason: reason, ruleID: ruleID, detail: detail})
	}
	escalate := func(reason Reason, ruleID, detail string) {
		if seen[ruleID] {
			return
		}
		seen[ruleID] = true
		escalatable = append(escalatable, obstacle{reason: reason, ruleID: ruleID, detail: detail})
	}

	depth := 0
	// withBodyPending marks the one place a statement-leading keyword may
	// legitimately appear at depth 0 after a closing parenthesis: the body of a
	// WITH statement, after its last CTE definition. It is cleared once used, so
	// a further "... ) SELECT" is a second statement.
	withBodyPending := false
	// prefixPending does the same for the single statement that EXPLAIN or
	// DESCRIBE introduces.
	prefixPending := false
	var allowedBy Rule

	for i := 0; i < len(toks); i++ {
		t := toks[i]

		if t.kind == tokenPunct {
			switch t.text {
			case "(":
				depth++
			case ")":
				depth--
				if depth < 0 {
					deny(ReasonUnbalancedParens, "", "the statement closes a parenthesis it never opened")
				}
			case ";":
				if i != len(toks)-1 {
					deny(ReasonMultipleStatements, "", "a semicolon separates two statements")
				}
			}
			continue
		}
		if t.kind != tokenWord && t.kind != tokenQuotedIdent {
			continue
		}

		name := t.lower
		qualified := qualifiedName(toks, i)
		isCall := i+1 < len(toks) && toks[i+1].kind == tokenPunct && toks[i+1].text == "("

		// A forbidden name is refused wherever it appears and however it is
		// written: called, quoted, schema-qualified, or bare as T-SQL's
		// implicit EXEC of a procedure at the start of a batch.
		if r, ok := c.forbidFunc[engine][name]; ok {
			deny(ReasonForbiddenConstruct, r.ID, r.Reason)
			continue
		}
		if r, ok := c.forbidFunc[engine][qualified]; ok && qualified != name {
			deny(ReasonForbiddenConstruct, r.ID, r.Reason)
			continue
		}
		if t.kind == tokenQuotedIdent {
			// A delimited identifier is never a keyword, so only the function
			// checks apply to it.
			if isCall && !c.safe(engine, name, qualified) {
				escalate(ReasonUnknownFunction, unknownFunctionPrefix+qualified, "the statement calls a function that is not on the safe-builtin allowlist")
			}
			continue
		}

		// A word followed by "(" is a function call only when the ruleset says
		// the name is a safe builtin. Without that condition EXECUTE('...') and
		// TRUNCATE(x) would read as calls and skip the keyword rules that must
		// refuse them.
		safe := isCall && c.safe(engine, name, qualified)
		if !safe {
			if r, ok := c.matchPhrase(engine, toks, i); ok {
				deny(ReasonForbiddenStatement, r.ID, r.Reason)
				continue
			}
		}

		read, isRead := c.read[engine][name]
		switch {
		case i == 0:
			if isRead {
				allowedBy = read
				withBodyPending = name == "with"
				prefixPending = read.Prefix
			} else {
				// Terminal, and not escalatable. When a function is unknown the
				// rest of the statement was still checked in full; when the
				// leading keyword is unknown the gate did not understand the
				// statement's shape at all, so approving it would permit a class
				// nobody inspected — COMMENT ON, SAVEPOINT, BINLOG, CHANGE
				// MASTER TO and STOP SLAVE all arrive here.
				deny(ReasonUnknownStatement, "", "the statement does not begin with a keyword known to be a read")
				continue
			}
		case isRead && depth == 0 && !(name == "with" && isCall):
			// T-SQL makes semicolons optional, so a second statement can begin
			// with no punctuation at all. A statement-leading keyword at depth 0
			// is that boundary unless a set operator or a WITH body explains it.
			// "WITH (" is excluded because it is a T-SQL table hint, never a CTE.
			if !boundaryExplained(toks, i, &withBodyPending, &prefixPending) {
				deny(ReasonMultipleStatements, "", "a second statement begins here")
				continue
			}
		}

		if isCall && !safe && !isRead && !c.nonFunc[name] && !cteName(toks, i, depth, withBodyPending) {
			escalate(ReasonUnknownFunction, unknownFunctionPrefix+qualified, "the statement calls a function that is not on the safe-builtin allowlist")
		}
	}

	if depth != 0 && len(terminal) == 0 {
		deny(ReasonUnbalancedParens, "", "the statement leaves a parenthesis open")
	}
	if len(terminal) > 0 {
		o := terminal[0]
		return Decision{Verdict: Deny, Reason: o.reason, RuleID: o.ruleID, Detail: o.detail}
	}

	var pending, used []string
	first := -1
	for i, o := range escalatable {
		if granted(grants, o.ruleID) {
			used = append(used, o.ruleID)
			continue
		}
		if first < 0 {
			first = i
		}
		pending = append(pending, o.ruleID)
	}
	if first < 0 {
		return Decision{Verdict: Allow, Reason: ReasonReadStatement, RuleID: allowedBy.ID, GrantsUsed: used, Detail: allowedBy.Reason}
	}
	o := escalatable[first]
	return Decision{Verdict: NeedsApproval, Reason: o.reason, RuleID: o.ruleID, Pending: pending, Detail: o.detail}
}

func (c *compiled) safe(engine Engine, name, qualified string) bool {
	return c.safeFunc[engine][name] || c.safeFunc[engine][qualified]
}

// matchPhrase reports the longest forbidden keyword rule whose word sequence
// starts at toks[i].
func (c *compiled) matchPhrase(engine Engine, toks []token, i int) (Rule, bool) {
	for _, p := range c.forbidden[toks[i].lower] {
		if !ruleApplies(p.rule, engine) {
			continue
		}
		if i+len(p.words) > len(toks) {
			continue
		}
		ok := true
		for k, w := range p.words {
			if toks[i+k].kind != tokenWord || toks[i+k].lower != w {
				ok = false
				break
			}
		}
		if ok {
			return p.rule, true
		}
	}
	return Rule{}, false
}

// setOperators are the only words after which a statement-leading keyword may
// legitimately appear at depth 0 within one statement.
var setOperators = map[string]bool{
	"union":     true,
	"all":       true,
	"intersect": true,
	"except":    true,
	"minus":     true,
}

func boundaryExplained(toks []token, i int, withBodyPending, prefixPending *bool) bool {
	prev := toks[i-1]
	if prev.kind == tokenWord && setOperators[prev.lower] {
		return true
	}
	if prev.kind == tokenPunct && prev.text == ")" && *withBodyPending {
		*withBodyPending = false
		return true
	}
	if *prefixPending {
		*prefixPending = false
		return true
	}
	return false
}

// cteName reports whether toks[i] is the name being defined in a WITH clause,
// as in WITH r(n) AS (...). Such a name is followed by a parenthesised column
// list, which is otherwise indistinguishable from a call. A name in this
// position is never invoked, and a forbidden name has already been refused
// before this is consulted.
func cteName(toks []token, i, depth int, withBodyPending bool) bool {
	if !withBodyPending || depth != 0 || i == 0 {
		return false
	}
	prev := toks[i-1]
	if prev.kind == tokenPunct && prev.text == "," {
		return true
	}
	return prev.kind == tokenWord && (prev.lower == "with" || prev.lower == "recursive")
}

// maxNameParts bounds the backward walk in qualifiedName at the deepest real
// name, server.database.schema.object. Without the bound the walk is quadratic
// in the statement length — a measured 83 seconds of CPU on 120 KB of
// "SELECT a.a.a...a" — which is a denial of service on the goroutine handling
// the request. The bound costs nothing in safety: a forbidden name is matched
// bare as well as qualified, so a deeper prefix cannot hide one.
const maxNameParts = 4

// qualifiedName joins the dotted name ending at toks[i], lowercased, so that
// sys.xp_cmdshell and dbo.CalcularSaldo are matched and reported whole.
func qualifiedName(toks []token, i int) string {
	parts := []string{toks[i].lower}
	j := i
	for len(parts) < maxNameParts && j-2 >= 0 && toks[j-1].kind == tokenPunct && toks[j-1].text == "." &&
		(toks[j-2].kind == tokenWord || toks[j-2].kind == tokenQuotedIdent) {
		parts = append(parts, toks[j-2].lower)
		j -= 2
	}
	slices.Reverse(parts)
	return strings.Join(parts, ".")
}
