package redisgate

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func decodeArgvKey(s string) ([]string, bool) {
	var argv []string
	for s != "" {
		i := strings.IndexByte(s, ':')
		if i < 1 {
			return nil, false
		}
		for _, c := range []byte(s[:i]) {
			if c < '0' || c > '9' {
				return nil, false
			}
		}
		n, err := strconv.Atoi(s[:i])
		if err != nil || n > len(s)-i-1 {
			return nil, false
		}
		argv = append(argv, s[i+1:i+1+n])
		s = s[i+1+n:]
	}
	return argv, true
}

func FuzzRedisGate(f *testing.F) {
	c := loadCorpus(f)
	g := corpusGate(f, c)
	for _, e := range c.Entries {
		f.Add(argvKey(e.argv()))
	}
	for _, argv := range [][]string{
		nil,
		{"", ""},
		{"GET"},
		{"GET", "k\x00"},
		{"SCAN", "0", "COUNT"},
		{"SCAN", "0", "COUNT", "99999999999999999999"},
		{"LRANGE", "k", "0", "9223372036854775807"},
		{"LRANGE", "k", "9223372036854775806", "9223372036854775807"},
		{"SRANDMEMBER", "k", "-9223372036854775808"},
		{"ZRANGE", "k", "0", "1", "LIMIT", "0", "1"},
		{"XPENDING", "s", "g", "IDLE", ""},
		{"XPENDING", "s", "g", "IDLE", "9223372036854775807", "-", "+", "1"},
		{"XPENDING", "s", "g", "IDLE", "9223372036854775807", "-", "+", "1", "consumer"},
		{"OBJECT", "", "k"},
		{"ſCAN", "0", "COUNT", "1"},
	} {
		f.Add(argvKey(argv))
	}

	byRule := map[string]Command{}
	for _, cmd := range Allowlist() {
		byRule[cmd.RuleID] = cmd
	}
	var forbidden []string
	for name := range forbiddenCommands {
		forbidden = append(forbidden, name)
	}
	slices.Sort(forbidden)

	f.Fuzz(func(t *testing.T, encoded string) {
		argv, ok := decodeArgvKey(encoded)
		if !ok {
			return
		}
		original := slices.Clone(argv)

		got := g.Validate(argv)
		switch got.Verdict {
		case Allow, Deny:
		default:
			t.Fatalf("Validate(%q) returned verdict %q", argv, got.Verdict)
		}
		if !slices.Equal(argv, original) {
			t.Fatalf("Validate mutated its argv: %q became %q", original, argv)
		}
		if again := g.Validate(argv); again != got {
			t.Fatalf("Validate(%q) is not deterministic: %+v then %+v", argv, got, again)
		}

		if got.Verdict == Allow {
			cmd, ok := byRule[got.RuleID]
			if !ok {
				t.Fatalf("Validate(%q) = allow under rule %q, which is not an allowlist rule", argv, got.RuleID)
			}
			if cmd.Name != asciiUpper(argv[0]) {
				t.Fatalf("Validate(%q) = allow under rule %q, which belongs to %s, not to argv[0]", argv, got.RuleID, cmd.Name)
			}
			if cmd.Subcommand != "" && (len(argv) < 2 || cmd.Subcommand != asciiUpper(argv[1])) {
				t.Fatalf("Validate(%q) = allow under rule %q, which belongs to %s %s", argv, got.RuleID, cmd.Name, cmd.Subcommand)
			}
			return
		}

		if got.Reason == ReasonWrongArity {
			return
		}
		for i, name := range forbidden {
			if i%2 == 1 {
				name = asciiUpper(name)
			}
			extended := append(slices.Clone(argv), name)
			if d := g.Validate(extended); d.Verdict == Allow {
				t.Fatalf("Validate(%q) = deny/%s, but appending %q makes it allow under %q", argv, got.Reason, name, d.RuleID)
			}
		}
	})
}
