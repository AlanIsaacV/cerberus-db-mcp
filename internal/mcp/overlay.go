package mcp

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

const (
	gateLoadStartup = "startup"
	gateLoadReload  = "reload"

	ruleKindRead              = "read_statement"
	ruleKindForbiddenStmt     = "forbidden_statement"
	ruleKindForbiddenFunction = "forbidden_function"
)

type RuleDefinition struct {
	Kind           string        `json:"kind"`
	Match          string        `json:"match"`
	Engines        []gate.Engine `json:"engines"`
	Prefix         bool          `json:"prefix"`
	SafeAsFunction string        `json:"safe_as_function"`
	Reason         string        `json:"reason"`
}

type RuleChange struct {
	ID string `json:"id"`
	RuleDefinition
}

type RuleReplacement struct {
	ID       string         `json:"id"`
	Baseline RuleDefinition `json:"baseline"`
	InForce  RuleDefinition `json:"in_force"`
}

type MaxStatementBytesChange struct {
	Baseline int `json:"baseline"`
	InForce  int `json:"in_force"`
}

type RulesetDiff struct {
	RulesAdded               []RuleChange             `json:"rules_added"`
	RulesRemoved             []RuleChange             `json:"rules_removed"`
	RulesReplaced            []RuleReplacement        `json:"rules_replaced"`
	SafeFunctionsAdded       map[gate.Engine][]string `json:"safe_functions_added"`
	SafeFunctionsRemoved     map[gate.Engine][]string `json:"safe_functions_removed"`
	NonFunctionKeywordsAdded []string                 `json:"non_function_keywords_added"`
	MaxStatementBytes        *MaxStatementBytesChange `json:"max_statement_bytes_changed"`
}

func (d RulesetDiff) Empty() bool {
	return len(d.RulesAdded) == 0 && len(d.RulesRemoved) == 0 && len(d.RulesReplaced) == 0 &&
		len(d.SafeFunctionsAdded) == 0 && len(d.SafeFunctionsRemoved) == 0 &&
		len(d.NonFunctionKeywordsAdded) == 0 && d.MaxStatementBytes == nil
}

func DiffAgainstBaseline(inForce *gate.Ruleset) (RulesetDiff, error) {
	if inForce == nil {
		return RulesetDiff{}, fmt.Errorf("mcp: diff gate ruleset: %w", gate.ErrInvalidRuleset)
	}
	base, err := gate.BaselineRuleset()
	if err != nil {
		return RulesetDiff{}, err
	}
	d := RulesetDiff{
		RulesAdded:               []RuleChange{},
		RulesRemoved:             []RuleChange{},
		RulesReplaced:            []RuleReplacement{},
		SafeFunctionsAdded:       map[gate.Engine][]string{},
		SafeFunctionsRemoved:     map[gate.Engine][]string{},
		NonFunctionKeywordsAdded: []string{},
	}

	baseRules := rulesByID(base)
	forceRules := rulesByID(inForce)
	for _, id := range sortedKeys(forceRules) {
		now := forceRules[id]
		was, ok := baseRules[id]
		switch {
		case !ok:
			d.RulesAdded = append(d.RulesAdded, now.change())
		case !reflect.DeepEqual(was, now):
			d.RulesReplaced = append(d.RulesReplaced, RuleReplacement{ID: id, Baseline: was.definition(), InForce: now.definition()})
		}
	}
	for _, id := range sortedKeys(baseRules) {
		if _, ok := forceRules[id]; !ok {
			d.RulesRemoved = append(d.RulesRemoved, baseRules[id].change())
		}
	}

	baseSafe := safeFunctionsByEngine(base)
	forceSafe := safeFunctionsByEngine(inForce)
	for _, engine := range gate.Engines() {
		if added := missingFrom(baseSafe[engine], forceSafe[engine]); len(added) > 0 {
			d.SafeFunctionsAdded[engine] = added
		}
		if removed := missingFrom(forceSafe[engine], baseSafe[engine]); len(removed) > 0 {
			d.SafeFunctionsRemoved[engine] = removed
		}
	}

	baseKeywords := make(map[string]bool, len(base.NonFunctionKeywords))
	for _, k := range base.NonFunctionKeywords {
		baseKeywords[k] = true
	}
	for _, k := range inForce.NonFunctionKeywords {
		if !baseKeywords[k] {
			baseKeywords[k] = true
			d.NonFunctionKeywordsAdded = append(d.NonFunctionKeywordsAdded, k)
		}
	}
	sort.Strings(d.NonFunctionKeywordsAdded)

	if base.MaxStatementBytes != inForce.MaxStatementBytes {
		d.MaxStatementBytes = &MaxStatementBytesChange{Baseline: base.MaxStatementBytes, InForce: inForce.MaxStatementBytes}
	}
	return d, nil
}

type kindedRule struct {
	kind string
	rule gate.Rule
}

func (r kindedRule) change() RuleChange {
	return RuleChange{ID: r.rule.ID, RuleDefinition: r.definition()}
}

func (r kindedRule) definition() RuleDefinition {
	engines := append([]gate.Engine(nil), r.rule.Engines...)
	if len(engines) == 0 {
		engines = gate.Engines()
	}
	sort.Slice(engines, func(i, j int) bool { return engines[i] < engines[j] })
	return RuleDefinition{
		Kind:           r.kind,
		Match:          r.rule.Match,
		Engines:        engines,
		Prefix:         r.rule.Prefix,
		SafeAsFunction: r.rule.SafeAsFunction,
		Reason:         r.rule.Reason,
	}
}

func rulesByID(rs *gate.Ruleset) map[string]kindedRule {
	out := make(map[string]kindedRule)
	for _, group := range []struct {
		kind  string
		rules []gate.Rule
	}{
		{ruleKindRead, rs.ReadStatements},
		{ruleKindForbiddenStmt, rs.ForbiddenStatements},
		{ruleKindForbiddenFunction, rs.ForbiddenFunctions},
	} {
		for _, r := range group.rules {
			out[r.ID] = kindedRule{kind: group.kind, rule: r}
		}
	}
	return out
}

func safeFunctionsByEngine(rs *gate.Ruleset) map[gate.Engine]map[string]bool {
	out := make(map[gate.Engine]map[string]bool)
	for _, engine := range gate.Engines() {
		out[engine] = make(map[string]bool)
	}
	for _, a := range rs.SafeFunctions {
		for _, engine := range gate.Engines() {
			if !allowanceApplies(a, engine) {
				continue
			}
			for _, n := range a.Names {
				out[engine][n] = true
			}
		}
	}
	return out
}

func allowanceApplies(a gate.FunctionAllowance, engine gate.Engine) bool {
	if len(a.Engines) == 0 {
		return true
	}
	for _, e := range a.Engines {
		if e == engine {
			return true
		}
	}
	return false
}

func missingFrom(reference, candidate map[string]bool) []string {
	var out []string
	for n := range candidate {
		if !reference[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func LogGateLoad(log zerolog.Logger, overlayPath string, g *gate.Gate) error {
	return logGateLoad(log, gateLoadStartup, overlayPath, g)
}

func logGateLoad(log zerolog.Logger, trigger, overlayPath string, g *gate.Gate) error {
	diff, err := DiffAgainstBaseline(g.Ruleset())
	if err != nil {
		return err
	}
	exemptions := g.Exemptions()
	if exemptions == nil {
		exemptions = []gate.Exemption{}
	}
	event := log.Log()
	if zerolog.LevelFieldName != "" {
		event = event.Str(zerolog.LevelFieldName, zerolog.LevelFieldMarshalFunc(zerolog.InfoLevel))
	}
	event = event.
		Str("trigger", trigger).
		Bool("overlay_configured", overlayPath != "").
		Str("overlay_path", overlayPath).
		Interface("diff", diff).
		Interface("exemptions", exemptions)
	if overlayPath == "" {
		event.Msg("gate ruleset loaded: no overlay is configured, so the baseline is in force")
		return nil
	}
	event.Msg("gate ruleset loaded: the overlay was applied on top of the baseline")
	return nil
}

func (s *Server) reloadGate() {
	if s.cfg.GateOverlay == "" || s.gate == nil {
		s.log.Warn().
			Str("trigger", gateLoadReload).
			Bool("overlay_configured", false).
			Msg("SIGHUP received but no gate overlay is configured; nothing was reloaded and the ruleset in force is unchanged")
		return
	}
	if err := s.gate.Reload(); err != nil {
		s.log.Error().
			Str("trigger", gateLoadReload).
			Bool("overlay_configured", true).
			Str("overlay_path", s.cfg.GateOverlay).
			Err(err).
			Bool("previous_ruleset_in_force", true).
			Msg("gate overlay rejected on reload; the previous ruleset remains in force")
		return
	}
	if err := logGateLoad(s.log, gateLoadReload, s.cfg.GateOverlay, s.gate); err != nil {
		s.log.Error().
			Str("trigger", gateLoadReload).
			Str("overlay_path", s.cfg.GateOverlay).
			Err(err).
			Msg("the gate overlay was reloaded but its diff against the baseline could not be computed")
	}
}
