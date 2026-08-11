package gate

// Grant is a human's answer to one [NeedsApproval] decision. It is scoped to a
// rule, not to a statement: granting function:dbo.calcularsaldo lets every
// statement whose only obstacle is that function through, for as long as the
// caller keeps passing the grant in.
//
// The gate has no opinion on where a grant came from, who approved it or how
// long it lives. It receives the active set on every call and consults it only
// for obstacles that are escalatable in the first place.
type Grant struct {
	// RuleID is the identity reported in [Decision.RuleID] of the decision this
	// grant answers.
	RuleID string `json:"rule_id"`
}

// unknownFunctionPrefix namespaces the one escalatable obstacle the gate has,
// keeping it distinct from ruleset rule IDs, which are never grantable: a rule
// in the ruleset describes something known, and everything known-dangerous is a
// terminal deny.
//
// An unrecognised function is the only thing a human can usefully be asked
// about, because the statement around it was checked in full and the question
// reduces to "is this one name a read?". An unrecognised leading keyword is not:
// there the gate understood nothing of the statement's shape, so it is a
// terminal deny.
const unknownFunctionPrefix = "function:"

func granted(grants []Grant, ruleID string) bool {
	for _, g := range grants {
		if g.RuleID == ruleID {
			return true
		}
	}
	return false
}
