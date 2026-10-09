package redisgate

import (
	"errors"
	"strconv"
)

type Verdict string

const (
	Allow Verdict = "allow"
	Deny  Verdict = "deny"
)

type Reason string

const (
	ReasonBoundedRead       Reason = "bounded-read"
	ReasonEmptyCommand      Reason = "empty-command"
	ReasonTooManyArguments  Reason = "too-many-arguments"
	ReasonCommandTooLarge   Reason = "command-too-large"
	ReasonForbiddenCommand  Reason = "forbidden-command"
	ReasonUnboundedCommand  Reason = "unbounded-command"
	ReasonUnknownCommand    Reason = "unknown-command"
	ReasonMissingSubcommand Reason = "missing-subcommand"
	ReasonUnknownSubcommand Reason = "unknown-subcommand"
	ReasonWrongArity        Reason = "wrong-arity"
	ReasonUnknownArgument   Reason = "unknown-argument"
	ReasonInvalidArgument   Reason = "invalid-argument"
	ReasonDuplicateArgument Reason = "duplicate-argument"
	ReasonMissingCount      Reason = "missing-count"
	ReasonMissingLimit      Reason = "missing-limit"
	ReasonMissingMaxlen     Reason = "missing-maxlen"
	ReasonCountTooLarge     Reason = "count-too-large"
	ReasonTooManyElements   Reason = "too-many-elements"
	ReasonUnboundedWindow   Reason = "unbounded-window"
	ReasonWindowTooLarge    Reason = "window-too-large"
	ReasonTraversalTooDeep  Reason = "traversal-too-deep"
)

const (
	RuleArgvEmpty  = "argv-empty"
	RuleArgvLength = "argv-length"
	RuleArgvBytes  = "argv-bytes"
	RuleAllowlist  = "allowlist"
)

type Decision struct {
	Verdict Verdict `json:"verdict"`
	Reason  Reason  `json:"reason"`
	RuleID  string  `json:"rule_id"`
	Detail  string  `json:"detail,omitempty"`
}

type Limits struct {
	MaxElements int
	MaxCount    int
	MaxArgs     int
	MaxBytes    int
}

var ErrInvalidLimits = errors.New("redisgate: every limit must be positive")

type limitError struct {
	field string
	value int
}

func (e *limitError) Error() string {
	return "redisgate: " + e.field + " must be positive, got " + strconv.Itoa(e.value)
}

func (e *limitError) Unwrap() error {
	return ErrInvalidLimits
}

type Gate struct {
	limits Limits
}

func New(limits Limits) (*Gate, error) {
	for _, f := range []struct {
		name  string
		value int
	}{
		{"MaxElements", limits.MaxElements},
		{"MaxCount", limits.MaxCount},
		{"MaxArgs", limits.MaxArgs},
		{"MaxBytes", limits.MaxBytes},
	} {
		if f.value <= 0 {
			return nil, &limitError{field: f.name, value: f.value}
		}
	}
	return &Gate{limits: limits}, nil
}

func (g *Gate) Validate(argv []string) Decision {
	if len(argv) == 0 {
		return deny(ReasonEmptyCommand, RuleArgvEmpty, "the command has no name")
	}
	if len(argv) > g.limits.MaxArgs {
		return deny(ReasonTooManyArguments, RuleArgvLength,
			"the command has "+strconv.Itoa(len(argv))+" elements; at most "+strconv.Itoa(g.limits.MaxArgs)+" are accepted")
	}
	total := 0
	for _, a := range argv {
		total += len(a)
		if total > g.limits.MaxBytes {
			return deny(ReasonCommandTooLarge, RuleArgvBytes,
				"the command exceeds "+strconv.Itoa(g.limits.MaxBytes)+" bytes in total")
		}
	}

	name := asciiLower(argv[0])
	if subs, ok := containers[name]; ok {
		if len(argv) < 2 {
			return deny(ReasonMissingSubcommand, RuleAllowlist,
				asciiUpper(name)+" needs one of the subcommands "+subcommandList(name))
		}
		r, ok := subs[asciiLower(argv[1])]
		if !ok {
			return deny(ReasonUnknownSubcommand, RuleAllowlist,
				"the subcommand is not on the allowlist; "+asciiUpper(name)+" accepts "+subcommandList(name))
		}
		return g.apply(r, argv, 2)
	}
	if r, ok := commands[name]; ok {
		return g.apply(r, argv, 1)
	}
	if alternative, ok := unboundedCommands[name]; ok {
		return deny(ReasonUnboundedCommand, "unbounded-"+name,
			"the command returns the whole value with no bound; use "+alternative)
	}
	if forbiddenCommands[name] {
		return deny(ReasonForbiddenCommand, "forbidden-"+name, "the command is refused by this server")
	}
	return deny(ReasonUnknownCommand, RuleAllowlist, "the command is not on the allowlist")
}

func (g *Gate) apply(r *rule, argv []string, offset int) Decision {
	if ref := r.check(g, argv[offset:]); ref != nil {
		detail := ref.detail
		if ref.arg > 0 {
			detail = "argv[" + strconv.Itoa(ref.arg-1+offset) + "] is not an option this command accepts there"
		}
		return deny(ref.reason, r.RuleID, detail)
	}
	return Decision{Verdict: Allow, Reason: ReasonBoundedRead, RuleID: r.RuleID}
}

func deny(reason Reason, ruleID, detail string) Decision {
	return Decision{Verdict: Deny, Reason: reason, RuleID: ruleID, Detail: detail}
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func asciiEqualFold(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
