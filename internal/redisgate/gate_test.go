package redisgate

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var testLimits = Limits{MaxElements: 10, MaxCount: 20, MaxArgs: 40, MaxBytes: 1024}

func newTestGate(t testing.TB) *Gate {
	t.Helper()
	g, err := New(testLimits)
	if err != nil {
		t.Fatalf("New(%+v) = %v", testLimits, err)
	}
	return g
}

func caseVariants(argv []string) map[string][]string {
	upper := make([]string, len(argv))
	lower := make([]string, len(argv))
	mixed := make([]string, len(argv))
	for i, a := range argv {
		upper[i] = strings.ToUpper(a)
		lower[i] = strings.ToLower(a)
		var b strings.Builder
		for j, r := range strings.ToLower(a) {
			if j%2 == 0 {
				b.WriteString(strings.ToUpper(string(r)))
			} else {
				b.WriteRune(r)
			}
		}
		mixed[i] = b.String()
	}
	return map[string][]string{"upper": upper, "lower": lower, "mixed": mixed}
}

func argvName(argv []string) string {
	s := strings.Join(argv, " ")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	if s == "" {
		s = "<empty>"
	}
	return s
}

func repeatArgs(prefix []string, n int, stem string) []string {
	out := slices.Clone(prefix)
	for i := range n {
		out = append(out, stem+strconv.Itoa(i))
	}
	return out
}

func TestNewRefusesNonPositiveLimits(t *testing.T) {
	fields := map[string]func(*Limits, int){
		"MaxElements": func(l *Limits, v int) { l.MaxElements = v },
		"MaxCount":    func(l *Limits, v int) { l.MaxCount = v },
		"MaxArgs":     func(l *Limits, v int) { l.MaxArgs = v },
		"MaxBytes":    func(l *Limits, v int) { l.MaxBytes = v },
	}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		for _, v := range []int{0, -1} {
			t.Run(field+"="+strconv.Itoa(v), func(t *testing.T) {
				l := testLimits
				fields[field](&l, v)
				g, err := New(l)
				if err == nil {
					t.Fatalf("New(%+v) = %v, nil; want an error", l, g)
				}
				if !errors.Is(err, ErrInvalidLimits) {
					t.Fatalf("New(%+v) error = %v, want it to wrap ErrInvalidLimits", l, err)
				}
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("New(%+v) error = %q, want it to name %s", l, err, field)
				}
			})
		}
	}
	if _, err := New(testLimits); err != nil {
		t.Fatalf("New(%+v) = %v, want a gate", testLimits, err)
	}
}

func TestDecisionJSONShape(t *testing.T) {
	g := newTestGate(t)
	for _, tc := range []struct {
		argv []string
		keys []string
	}{
		{[]string{"GET", "k"}, []string{"reason", "rule_id", "verdict"}},
		{[]string{"SMEMBERS", "k"}, []string{"detail", "reason", "rule_id", "verdict"}},
	} {
		t.Run(argvName(tc.argv), func(t *testing.T) {
			data, err := json.Marshal(g.Validate(tc.argv))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatalf("unmarshal %s: %v", data, err)
			}
			if got := slices.Sorted(maps.Keys(fields)); !slices.Equal(got, tc.keys) {
				t.Fatalf("decision JSON %s has fields %v, want %v", data, got, tc.keys)
			}
			switch Verdict(fields["verdict"].(string)) {
			case Allow, Deny:
			default:
				t.Fatalf("decision JSON %s has verdict %v", data, fields["verdict"])
			}
		})
	}
}

func TestReasonsAreKebabCase(t *testing.T) {
	for _, r := range sourceReasons(t) {
		t.Run(string(r), func(t *testing.T) {
			s := string(r)
			if s == "" || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
				t.Fatalf("reason %q is not kebab-case", s)
			}
			for _, c := range s {
				if (c < 'a' || c > 'z') && c != '-' {
					t.Fatalf("reason %q is not kebab-case", s)
				}
			}
		})
	}
}

func TestAllowlistAccessorIsACopy(t *testing.T) {
	first := Allowlist()
	if len(first) == 0 {
		t.Fatal("Allowlist() is empty")
	}
	first[0].Name = "FLUSHALL"
	first[0].RuleID = "read-flushall"
	if got := Allowlist()[0]; got.Name == "FLUSHALL" || got.RuleID == "read-flushall" {
		t.Fatalf("mutating Allowlist()'s result reached the gate: %+v", got)
	}
	g := newTestGate(t)
	if d := g.Validate([]string{"FLUSHALL"}); d.Verdict != Deny {
		t.Fatalf("Validate(FLUSHALL) after mutating the accessor = %+v", d)
	}
}

var forbiddenCatalogue = [][]string{
	{"SET", "k", "v"},
	{"DEL", "k"},
	{"UNLINK", "k"},
	{"FLUSHALL"},
	{"FLUSHDB"},
	{"CONFIG", "SET", "maxmemory", "1"},
	{"CONFIG", "GET", "*"},
	{"EVAL", "return 1", "0"},
	{"EVAL_RO", "return 1", "0"},
	{"EVALSHA_RO", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db", "0"},
	{"FCALL_RO", "f", "0"},
	{"SCRIPT", "FLUSH"},
	{"FUNCTION", "LIST"},
	{"MULTI"},
	{"EXEC"},
	{"SELECT", "1"},
	{"SWAPDB", "0", "1"},
	{"SUBSCRIBE", "c"},
	{"PSUBSCRIBE", "c*"},
	{"MONITOR"},
	{"DEBUG", "SLEEP", "10"},
	{"BLPOP", "k", "0"},
	{"BLMOVE", "a", "b", "LEFT", "RIGHT", "0"},
	{"XREAD", "COUNT", "1", "STREAMS", "s", "0"},
	{"XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"},
	{"KEYS", "*"},
	{"SORT", "k"},
	{"SORT_RO", "k"},
	{"GEORADIUS", "k", "0", "0", "1", "km"},
	{"INFO"},
	{"CLIENT", "LIST"},
	{"SHUTDOWN"},
	{"MIGRATE", "h", "6379", "k", "0", "1000"},
	{"RESTORE", "k", "0", "payload"},
	{"DUMP", "k"},
	{"TOUCH", "k"},
	{"LCS", "a", "b"},
	{"GETEX", "k"},
	{"GETDEL", "k"},
	{"AUTH", "password"},
	{"HELLO", "3"},
	{"ACL", "WHOAMI"},
	{"MODULE", "LIST"},
	{"WAIT", "1", "0"},
}

func TestForbiddenCatalogueIsDenied(t *testing.T) {
	g := newTestGate(t)
	for _, argv := range forbiddenCatalogue {
		for _, variant := range []string{"lower", "mixed", "upper"} {
			v := caseVariants(argv)[variant]
			t.Run(variant+"/"+argvName(argv), func(t *testing.T) {
				d := g.Validate(v)
				if d.Verdict != Deny || d.Reason != ReasonForbiddenCommand {
					t.Fatalf("Validate(%q) = %+v, want deny/%s", v, d, ReasonForbiddenCommand)
				}
				if want := "forbidden-" + strings.ToLower(argv[0]); d.RuleID != want {
					t.Fatalf("Validate(%q) rule = %q, want %q", v, d.RuleID, want)
				}
			})
		}
	}
}

func TestWholeValueReadsNameTheirBoundedAlternative(t *testing.T) {
	g := newTestGate(t)
	for _, tc := range []struct {
		argv        []string
		alternative string
		bound       string
	}{
		{[]string{"SMEMBERS", "k"}, "SSCAN", "COUNT"},
		{[]string{"HGETALL", "k"}, "HSCAN", "COUNT"},
		{[]string{"HKEYS", "k"}, "HSCAN", "COUNT"},
		{[]string{"HVALS", "k"}, "HSCAN", "COUNT"},
	} {
		t.Run(argvName(tc.argv), func(t *testing.T) {
			d := g.Validate(tc.argv)
			if d.Verdict != Deny || d.Reason != ReasonUnboundedCommand {
				t.Fatalf("Validate(%q) = %+v, want deny/%s", tc.argv, d, ReasonUnboundedCommand)
			}
			if want := tc.alternative + " with " + tc.bound; !strings.Contains(d.Detail, want) {
				t.Fatalf("Validate(%q) detail %q does not name %q", tc.argv, d.Detail, want)
			}
			if _, ok := commands[strings.ToLower(tc.alternative)]; !ok {
				t.Fatalf("the alternative %s named for %s is not on the allowlist", tc.alternative, tc.argv[0])
			}
		})
	}
}

func TestUnboundedReadsNameTheirBound(t *testing.T) {
	g := newTestGate(t)
	over := testLimits.MaxElements + 1
	for _, tc := range []struct {
		argv   []string
		reason Reason
		bound  string
	}{
		{[]string{"SCAN", "0"}, ReasonMissingCount, "COUNT"},
		{[]string{"SCAN", "0", "MATCH", "user:*", "TYPE", "hash"}, ReasonMissingCount, "COUNT"},
		{[]string{"HSCAN", "k", "0"}, ReasonMissingCount, "COUNT"},
		{[]string{"SSCAN", "k", "0", "MATCH", "*"}, ReasonMissingCount, "COUNT"},
		{[]string{"ZSCAN", "k", "0"}, ReasonMissingCount, "COUNT"},
		{[]string{"LRANGE", "k", "0", "-1"}, ReasonUnboundedWindow, "stop"},
		{[]string{"LRANGE", "k", "-5", "-1"}, ReasonUnboundedWindow, "start"},
		{[]string{"LRANGE", "k", "0", strconv.Itoa(over)}, ReasonWindowTooLarge, "stop"},
		{[]string{"ZRANGE", "k", "0", "-1"}, ReasonUnboundedWindow, "stop"},
		{[]string{"ZRANGE", "k", "0", strconv.Itoa(over), "REV"}, ReasonWindowTooLarge, "stop"},
		{[]string{"ZRANGE", "k", "-inf", "+inf", "BYSCORE"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZRANGE", "k", "-", "+", "BYLEX"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZRANGE", "k", "-inf", "+inf", "BYSCORE", "LIMIT", "0", "-1"}, ReasonTooManyElements, "LIMIT"},
		{[]string{"ZRANGEBYSCORE", "k", "-inf", "+inf"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZREVRANGEBYSCORE", "k", "+inf", "-inf", "WITHSCORES"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZRANGEBYLEX", "k", "-", "+"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZREVRANGEBYLEX", "k", "+", "-"}, ReasonMissingLimit, "LIMIT"},
		{[]string{"ZREVRANGE", "k", "0", "-1"}, ReasonUnboundedWindow, "stop"},
		{[]string{"XRANGE", "s", "-", "+"}, ReasonMissingCount, "COUNT"},
		{[]string{"XREVRANGE", "s", "+", "-"}, ReasonMissingCount, "COUNT"},
		{[]string{"LPOS", "k", "e"}, ReasonMissingMaxlen, "MAXLEN"},
		{[]string{"LPOS", "k", "e", "COUNT", "0"}, ReasonMissingMaxlen, "MAXLEN"},
		{[]string{"LPOS", "k", "e", "MAXLEN", "0"}, ReasonTooManyElements, "MAXLEN"},
		{[]string{"SRANDMEMBER", "k", strconv.Itoa(over)}, ReasonTooManyElements, "count"},
		{[]string{"SRANDMEMBER", "k", strconv.Itoa(-over)}, ReasonTooManyElements, "count"},
		{[]string{"HRANDFIELD", "k", strconv.Itoa(over)}, ReasonTooManyElements, "count"},
		{[]string{"HRANDFIELD", "k", strconv.Itoa(-over), "WITHVALUES"}, ReasonTooManyElements, "count"},
		{[]string{"ZRANDMEMBER", "k", strconv.Itoa(over)}, ReasonTooManyElements, "count"},
		{[]string{"ZRANDMEMBER", "k", strconv.Itoa(-over), "WITHSCORES"}, ReasonTooManyElements, "count"},
		{repeatArgs([]string{"MGET"}, over, "k"), ReasonTooManyElements, "keys"},
		{repeatArgs([]string{"HMGET", "h"}, over, "f"), ReasonTooManyElements, "fields"},
		{repeatArgs([]string{"EXISTS"}, over, "k"), ReasonTooManyElements, "keys"},
		{repeatArgs([]string{"SMISMEMBER", "s"}, over, "m"), ReasonTooManyElements, "members"},
		{repeatArgs([]string{"ZMSCORE", "z"}, over, "m"), ReasonTooManyElements, "members"},
		{[]string{"GEOSEARCH", "g", "FROMMEMBER", "m", "BYRADIUS", "10", "km"}, ReasonMissingCount, "COUNT"},
		{[]string{"GEOSEARCH", "g", "FROMLONLAT", "0", "0", "BYBOX", "10", "10", "km", "ASC"}, ReasonMissingCount, "COUNT"},
		{[]string{"XPENDING", "s", "g", "-", "+"}, ReasonMissingCount, "count"},
		{[]string{"XINFO", "STREAM", "s", "FULL"}, ReasonMissingCount, "COUNT"},
	} {
		t.Run(argvName(tc.argv), func(t *testing.T) {
			d := g.Validate(tc.argv)
			if d.Verdict != Deny || d.Reason != tc.reason {
				t.Fatalf("Validate(%q) = %+v, want deny/%s", tc.argv, d, tc.reason)
			}
			if !strings.Contains(strings.ToLower(d.Detail), strings.ToLower(tc.bound)) {
				t.Fatalf("Validate(%q) detail %q does not name %s", tc.argv, d.Detail, tc.bound)
			}
		})
	}
}

type boundedForm struct {
	name   string
	limit  int
	reason Reason
	build  func(n int) []string
}

func boundedForms(l Limits) []boundedForm {
	n := strconv.Itoa
	elem := l.MaxElements
	count := l.MaxCount
	return []boundedForm{
		{"LRANGE window", elem, ReasonWindowTooLarge, func(k int) []string { return []string{"LRANGE", "k", "0", n(k - 1)} }},
		{"ZRANGE window", elem, ReasonWindowTooLarge, func(k int) []string { return []string{"ZRANGE", "k", "0", n(k - 1), "WITHSCORES"} }},
		{"ZRANGE REV window", elem, ReasonWindowTooLarge, func(k int) []string { return []string{"ZRANGE", "k", "0", n(k - 1), "REV"} }},
		{"ZREVRANGE window", elem, ReasonWindowTooLarge, func(k int) []string { return []string{"ZREVRANGE", "k", "0", n(k - 1)} }},
		{"ZRANGE BYSCORE LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZRANGE", "k", "-inf", "+inf", "BYSCORE", "LIMIT", "0", n(k)}
		}},
		{"ZRANGE BYLEX LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZRANGE", "k", "-", "+", "BYLEX", "REV", "LIMIT", "0", n(k)}
		}},
		{"ZRANGEBYSCORE LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZRANGEBYSCORE", "k", "-inf", "+inf", "WITHSCORES", "LIMIT", "0", n(k)}
		}},
		{"ZREVRANGEBYSCORE LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZREVRANGEBYSCORE", "k", "+inf", "-inf", "LIMIT", "0", n(k)}
		}},
		{"ZRANGEBYLEX LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZRANGEBYLEX", "k", "-", "+", "LIMIT", "0", n(k)}
		}},
		{"ZREVRANGEBYLEX LIMIT", elem, ReasonTooManyElements, func(k int) []string {
			return []string{"ZREVRANGEBYLEX", "k", "+", "-", "LIMIT", "0", n(k)}
		}},
		{"SRANDMEMBER count", elem, ReasonTooManyElements, func(k int) []string { return []string{"SRANDMEMBER", "k", n(k)} }},
		{"SRANDMEMBER negative count", elem, ReasonTooManyElements, func(k int) []string { return []string{"SRANDMEMBER", "k", n(-k)} }},
		{"HRANDFIELD count", elem, ReasonTooManyElements, func(k int) []string { return []string{"HRANDFIELD", "k", n(k), "WITHVALUES"} }},
		{"HRANDFIELD negative count", elem, ReasonTooManyElements, func(k int) []string { return []string{"HRANDFIELD", "k", n(-k)} }},
		{"ZRANDMEMBER count", elem, ReasonTooManyElements, func(k int) []string { return []string{"ZRANDMEMBER", "k", n(k), "WITHSCORES"} }},
		{"ZRANDMEMBER negative count", elem, ReasonTooManyElements, func(k int) []string { return []string{"ZRANDMEMBER", "k", n(-k)} }},
		{"MGET keys", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"MGET"}, k, "k") }},
		{"HMGET fields", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"HMGET", "h"}, k, "f") }},
		{"EXISTS keys", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"EXISTS"}, k, "k") }},
		{"SMISMEMBER members", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"SMISMEMBER", "s"}, k, "m") }},
		{"ZMSCORE members", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"ZMSCORE", "z"}, k, "m") }},
		{"GEOPOS members", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"GEOPOS", "g"}, k, "m") }},
		{"GEOHASH members", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"GEOHASH", "g"}, k, "m") }},
		{"PFCOUNT keys", elem, ReasonTooManyElements, func(k int) []string { return repeatArgs([]string{"PFCOUNT"}, k, "h") }},
		{"LPOS MAXLEN", elem, ReasonTooManyElements, func(k int) []string { return []string{"LPOS", "k", "e", "COUNT", "0", "MAXLEN", n(k)} }},
		{"MEMORY USAGE SAMPLES", elem, ReasonTooManyElements, func(k int) []string { return []string{"MEMORY", "USAGE", "k", "SAMPLES", n(k)} }},
		{"SCAN COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"SCAN", "0", "MATCH", "*", "COUNT", n(k), "TYPE", "zset"} }},
		{"HSCAN COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"HSCAN", "h", "0", "COUNT", n(k), "NOVALUES"} }},
		{"SSCAN COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"SSCAN", "s", "0", "COUNT", n(k)} }},
		{"ZSCAN COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"ZSCAN", "z", "0", "COUNT", n(k), "MATCH", "a*"} }},
		{"XRANGE COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"XRANGE", "s", "-", "+", "COUNT", n(k)} }},
		{"XREVRANGE COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"XREVRANGE", "s", "+", "-", "COUNT", n(k)} }},
		{"GEOSEARCH COUNT", count, ReasonCountTooLarge, func(k int) []string {
			return []string{"GEOSEARCH", "g", "FROMMEMBER", "m", "BYRADIUS", "10", "km", "COUNT", n(k), "ANY", "WITHDIST"}
		}},
		{"XPENDING count", count, ReasonCountTooLarge, func(k int) []string { return []string{"XPENDING", "s", "g", "-", "+", n(k)} }},
		{"XINFO STREAM FULL COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"XINFO", "STREAM", "s", "FULL", "COUNT", n(k)} }},
		{"LPOS COUNT", count, ReasonCountTooLarge, func(k int) []string { return []string{"LPOS", "k", "e", "COUNT", n(k), "MAXLEN", "1"} }},
	}
}

func TestBoundedFormsAtAndPastTheirCap(t *testing.T) {
	for _, l := range []Limits{testLimits, {MaxElements: 3, MaxCount: 7, MaxArgs: 40, MaxBytes: 1024}} {
		g, err := New(l)
		if err != nil {
			t.Fatalf("New(%+v) = %v", l, err)
		}
		for _, f := range boundedForms(l) {
			t.Run(strconv.Itoa(l.MaxElements)+"-"+strconv.Itoa(l.MaxCount)+"/"+f.name, func(t *testing.T) {
				at := f.build(f.limit)
				if d := g.Validate(at); d.Verdict != Allow {
					t.Fatalf("at the cap: Validate(%q) = %+v, want allow", at, d)
				}
				past := f.build(f.limit + 1)
				if d := g.Validate(past); d.Verdict != Deny || d.Reason != f.reason {
					t.Fatalf("past the cap: Validate(%q) = %+v, want deny/%s", past, d, f.reason)
				}
			})
		}
	}
}

func traversalForms(l Limits) []boundedForm {
	n := strconv.Itoa
	return []boundedForm{
		{"ZRANGE BYSCORE LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZRANGE", "k", "-inf", "+inf", "BYSCORE", "LIMIT", n(k - 1), "1"}
		}},
		{"ZRANGE BYLEX REV LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZRANGE", "k", "+", "-", "BYLEX", "REV", "LIMIT", n(k - 1), "1"}
		}},
		{"ZRANGEBYSCORE LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZRANGEBYSCORE", "k", "-inf", "+inf", "WITHSCORES", "LIMIT", n(k - 1), "1"}
		}},
		{"ZREVRANGEBYSCORE LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZREVRANGEBYSCORE", "k", "+inf", "-inf", "LIMIT", n(k - 1), "1"}
		}},
		{"ZRANGEBYLEX LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZRANGEBYLEX", "k", "-", "+", "LIMIT", n(k - 1), "1"}
		}},
		{"ZREVRANGEBYLEX LIMIT offset", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZREVRANGEBYLEX", "k", "+", "-", "LIMIT", n(k - 1), "1"}
		}},
		{"ZRANGEBYSCORE LIMIT offset with the whole count", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"ZRANGEBYSCORE", "k", "-inf", "+inf", "LIMIT", n(k - l.MaxElements), n(l.MaxElements)}
		}},
		{"LRANGE stop", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"LRANGE", "k", n(k - 1), n(k - 1)}
		}},
		{"LRANGE stop with the whole window", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"LRANGE", "k", n(k - l.MaxElements), n(k - 1)}
		}},
		{"LINDEX from the head", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"LINDEX", "k", n(k - 1)}
		}},
		{"LINDEX from the tail", l.MaxElements, ReasonTraversalTooDeep, func(k int) []string {
			return []string{"LINDEX", "k", n(-k)}
		}},
	}
}

func traversalArgument(argv []string) string {
	switch strings.ToUpper(argv[0]) {
	case "LRANGE":
		return "stop"
	case "LINDEX":
		return "index"
	case "XPENDING":
		return "IDLE"
	default:
		return "offset"
	}
}

func TestTraversalIsBoundedByTheArguments(t *testing.T) {
	for _, l := range []Limits{testLimits, {MaxElements: 3, MaxCount: 7, MaxArgs: 40, MaxBytes: 1024}} {
		g, err := New(l)
		if err != nil {
			t.Fatalf("New(%+v) = %v", l, err)
		}
		for _, f := range traversalForms(l) {
			t.Run(strconv.Itoa(l.MaxElements)+"/"+f.name, func(t *testing.T) {
				at := f.build(f.limit)
				if d := g.Validate(at); d.Verdict != Allow {
					t.Fatalf("at the bound: Validate(%q) = %+v, want allow", at, d)
				}
				past := f.build(f.limit + 1)
				d := g.Validate(past)
				if d.Verdict != Deny || d.Reason != f.reason {
					t.Fatalf("past the bound: Validate(%q) = %+v, want deny/%s", past, d, f.reason)
				}
				if arg := traversalArgument(past); !strings.Contains(d.Detail, arg) {
					t.Fatalf("past the bound: Validate(%q) detail %q does not name %s", past, d.Detail, arg)
				}
			})
		}
	}
	g := newTestGate(t)
	for _, argv := range [][]string{
		{"ZRANGEBYSCORE", "k", "-inf", "+inf", "LIMIT", "999999999", "1"},
		{"ZRANGEBYSCORE", "k", "-inf", "+inf", "LIMIT", "9223372036854775807", "1"},
		{"ZRANGE", "k", "-inf", "+inf", "BYSCORE", "LIMIT", "9223372036854775807", strconv.Itoa(testLimits.MaxElements)},
		{"LRANGE", "k", "1000000", "1000005"},
		{"LINDEX", "k", "9223372036854775807"},
		{"LINDEX", "k", "-9223372036854775808"},
		{"XPENDING", "s", "g", "IDLE", "9223372036854775807", "-", "+", "1"},
		{"XPENDING", "s", "g", "IDLE", "9223372036854775807", "-", "+", "1", "consumer"},
		{"XPENDING", "s", "g", "idle", "0", "-", "+", strconv.Itoa(testLimits.MaxCount)},
		{"XPENDING", "s", "g", "IDLE", "1000", "-", "+"},
	} {
		t.Run(argvName(argv), func(t *testing.T) {
			d := g.Validate(argv)
			if d.Verdict != Deny || d.Reason != ReasonTraversalTooDeep {
				t.Fatalf("Validate(%q) = %+v, want deny/%s", argv, d, ReasonTraversalTooDeep)
			}
			if arg := traversalArgument(argv); !strings.Contains(d.Detail, arg) {
				t.Fatalf("Validate(%q) detail %q does not name %s", argv, d.Detail, arg)
			}
		})
	}
}

func TestEnvelopeIsCheckedBeforeAnyCommandRule(t *testing.T) {
	l := Limits{MaxElements: 100, MaxCount: 100, MaxArgs: 8, MaxBytes: 32}
	g, err := New(l)
	if err != nil {
		t.Fatalf("New(%+v) = %v", l, err)
	}
	key := func(n int) string { return strings.Repeat("k", n) }
	for _, tc := range []struct {
		name   string
		argv   []string
		reason Reason
	}{
		{"length at cap", repeatArgs([]string{"MGET"}, l.MaxArgs-1, "k"), ReasonBoundedRead},
		{"length past cap", repeatArgs([]string{"MGET"}, l.MaxArgs, "k"), ReasonTooManyArguments},
		{"length past cap on a forbidden command", repeatArgs([]string{"DEL"}, l.MaxArgs, "k"), ReasonTooManyArguments},
		{"length past cap on an unknown command", repeatArgs([]string{"NOSUCH"}, l.MaxArgs, "k"), ReasonTooManyArguments},
		{"length past cap on an otherwise wrong arity", repeatArgs([]string{"GET"}, l.MaxArgs, "k"), ReasonTooManyArguments},
		{"bytes at cap", []string{"GET", key(l.MaxBytes - 3)}, ReasonBoundedRead},
		{"bytes past cap", []string{"GET", key(l.MaxBytes - 2)}, ReasonCommandTooLarge},
		{"bytes past cap on a forbidden command", []string{"SET", key(l.MaxBytes)}, ReasonCommandTooLarge},
		{"bytes past cap on an unknown command", []string{key(l.MaxBytes + 1)}, ReasonCommandTooLarge},
		{"bytes past cap on an unbounded read", []string{"SCAN", "0", "MATCH", key(l.MaxBytes)}, ReasonCommandTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := g.Validate(tc.argv)
			if d.Reason != tc.reason {
				t.Fatalf("Validate(%s) = %+v, want reason %s", argvName(tc.argv), d, tc.reason)
			}
			if (d.Verdict == Allow) != (tc.reason == ReasonBoundedRead) {
				t.Fatalf("Validate(%s) = %+v, wrong verdict", argvName(tc.argv), d)
			}
		})
	}
}

func TestUnknownCommandsAndArguments(t *testing.T) {
	g := newTestGate(t)
	for _, tc := range []struct {
		argv   []string
		reason Reason
	}{
		{[]string{"NOSUCHCOMMAND"}, ReasonUnknownCommand},
		{[]string{"GETX", "k"}, ReasonUnknownCommand},
		{[]string{"JSON.GET", "k", "$"}, ReasonUnknownCommand},
		{[]string{"FT.SEARCH", "idx", "*"}, ReasonUnknownCommand},
		{[]string{"BF.EXISTS", "b", "x"}, ReasonUnknownCommand},
		{[]string{"", "k"}, ReasonUnknownCommand},
		{[]string{"GET\x00", "k"}, ReasonUnknownCommand},
		{[]string{" GET", "k"}, ReasonUnknownCommand},
		{[]string{"ſcan", "0", "COUNT", "1"}, ReasonUnknownCommand},
		{[]string{"Keys", "*"}, ReasonUnknownCommand},
		{[]string{"ZRANGE", "k", "0", "5", "STORE", "dst"}, ReasonUnknownArgument},
		{[]string{"ZRANGE", "k", "-inf", "+inf", "BYSCORE", "LIMIT", "0", "5", "STORE"}, ReasonUnknownArgument},
		{[]string{"SCAN", "0", "COUNT", "10", "FOO"}, ReasonUnknownArgument},
		{[]string{"SCAN", "0", "COUNT", "10", "NOVALUES"}, ReasonUnknownArgument},
		{[]string{"SSCAN", "s", "0", "COUNT", "10", "NOVALUES"}, ReasonUnknownArgument},
		{[]string{"ZSCAN", "z", "0", "COUNT", "10", "TYPE", "zset"}, ReasonUnknownArgument},
		{[]string{"XRANGE", "s", "-", "+", "COUNT", "1", "BLOCK", "0"}, ReasonUnknownArgument},
		{[]string{"LPOS", "k", "e", "MAXLEN", "5", "FROM", "1"}, ReasonUnknownArgument},
		{[]string{"ZRANGEBYLEX", "k", "-", "+", "LIMIT", "0", "1", "WITHSCORES"}, ReasonUnknownArgument},
		{[]string{"HRANDFIELD", "h", "1", "WITHSCORES"}, ReasonUnknownArgument},
		{[]string{"ZRANK", "z", "m", "WITHSCORES"}, ReasonUnknownArgument},
		{[]string{"GEOSEARCH", "g", "FROMMEMBER", "m", "BYRADIUS", "1", "km", "COUNT", "1", "STORE", "dst"}, ReasonUnknownArgument},
		{[]string{"GEOSEARCH", "g", "FROMMEMBER", "m", "BYRADIUS", "1", "parsec", "COUNT", "1"}, ReasonUnknownArgument},
		{[]string{"BITCOUNT", "k", "0", "1", "WORD"}, ReasonUnknownArgument},
		{[]string{"XINFO", "STREAM", "s", "BRIEF"}, ReasonUnknownArgument},
		{[]string{"MEMORY", "USAGE", "k", "DEEP", "1"}, ReasonUnknownArgument},
	} {
		for _, variant := range []string{"lower", "mixed", "upper"} {
			v := caseVariants(tc.argv)[variant]
			if strings.ContainsFunc(tc.argv[0], func(r rune) bool { return r > 0x7f }) {
				v = tc.argv
			}
			t.Run(variant+"/"+argvName(tc.argv), func(t *testing.T) {
				if d := g.Validate(v); d.Verdict != Deny || d.Reason != tc.reason {
					t.Fatalf("Validate(%q) = %+v, want deny/%s", v, d, tc.reason)
				}
			})
		}
	}
}

func TestEmptyAndSubcommandShapes(t *testing.T) {
	g := newTestGate(t)
	for _, tc := range []struct {
		argv   []string
		reason Reason
	}{
		{nil, ReasonEmptyCommand},
		{[]string{}, ReasonEmptyCommand},
		{[]string{"OBJECT"}, ReasonMissingSubcommand},
		{[]string{"MEMORY"}, ReasonMissingSubcommand},
		{[]string{"XINFO"}, ReasonMissingSubcommand},
		{[]string{"OBJECT", "HELP"}, ReasonUnknownSubcommand},
		{[]string{"OBJECT", "ENCODINGS", "k"}, ReasonUnknownSubcommand},
		{[]string{"OBJECT", "", "k"}, ReasonUnknownSubcommand},
		{[]string{"MEMORY", "STATS"}, ReasonUnknownSubcommand},
		{[]string{"MEMORY", "PURGE"}, ReasonUnknownSubcommand},
		{[]string{"MEMORY", "DOCTOR"}, ReasonUnknownSubcommand},
		{[]string{"XINFO", "HELP"}, ReasonUnknownSubcommand},
		{[]string{"XINFO", "k"}, ReasonUnknownSubcommand},
		{[]string{"OBJECT", "ENCODING"}, ReasonWrongArity},
		{[]string{"XINFO", "CONSUMERS", "s"}, ReasonWrongArity},
	} {
		for _, variant := range []string{"lower", "mixed", "upper"} {
			v := caseVariants(tc.argv)[variant]
			t.Run(variant+"/"+argvName(tc.argv), func(t *testing.T) {
				if d := g.Validate(v); d.Verdict != Deny || d.Reason != tc.reason {
					t.Fatalf("Validate(%q) = %+v, want deny/%s", v, d, tc.reason)
				}
			})
		}
	}
	for _, argv := range [][]string{
		{"object", "encoding", "k"},
		{"Object", "Freq", "k"},
		{"MEMORY", "usage", "k"},
		{"xInFo", "sTrEaM", "s"},
	} {
		t.Run("allowed/"+argvName(argv), func(t *testing.T) {
			if d := g.Validate(argv); d.Verdict != Allow {
				t.Fatalf("Validate(%q) = %+v, want allow", argv, d)
			}
		})
	}
}
