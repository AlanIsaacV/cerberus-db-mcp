package redisgate

import "strings"

type Command struct {
	Name       string `json:"name"`
	Subcommand string `json:"subcommand,omitempty"`
	RuleID     string `json:"rule_id"`
}

type rule struct {
	Command
	check func(g *Gate, args []string) *refusal
}

func entry(name string, check func(g *Gate, args []string) *refusal) *rule {
	return &rule{Command: Command{Name: name, RuleID: "read-" + asciiLower(name)}, check: check}
}

func subentry(name, sub string, check func(g *Gate, args []string) *refusal) *rule {
	return &rule{
		Command: Command{Name: name, Subcommand: sub, RuleID: "read-" + asciiLower(name) + "-" + asciiLower(sub)},
		check:   check,
	}
}

var allowlist = []*rule{
	entry("SCAN", checkScan),
	entry("TYPE", fixed(1)),
	entry("EXISTS", variadic(0, 1, "keys")),
	entry("TTL", fixed(1)),
	entry("PTTL", fixed(1)),
	entry("EXPIRETIME", fixed(1)),
	entry("PEXPIRETIME", fixed(1)),
	subentry("OBJECT", "ENCODING", fixed(1)),
	subentry("OBJECT", "FREQ", fixed(1)),
	subentry("OBJECT", "IDLETIME", fixed(1)),
	subentry("OBJECT", "REFCOUNT", fixed(1)),
	subentry("MEMORY", "USAGE", checkMemoryUsage),
	entry("DBSIZE", fixed(0)),
	entry("RANDOMKEY", fixed(0)),

	entry("GET", fixed(1)),
	entry("MGET", variadic(0, 1, "keys")),
	entry("STRLEN", fixed(1)),
	entry("GETRANGE", checkGetRange),
	entry("SUBSTR", checkGetRange),
	entry("GETBIT", checkGetBit),
	entry("BITCOUNT", checkBitCount),
	entry("BITPOS", checkBitPos),

	entry("HGET", fixed(2)),
	entry("HMGET", variadic(1, 1, "fields")),
	entry("HLEN", fixed(1)),
	entry("HSTRLEN", fixed(2)),
	entry("HEXISTS", fixed(2)),
	entry("HSCAN", checkKeyScan("novalues")),
	entry("HRANDFIELD", checkRandom("withvalues")),

	entry("LLEN", fixed(1)),
	entry("LINDEX", checkLIndex),
	entry("LRANGE", checkLRange),
	entry("LPOS", checkLPos),

	entry("SCARD", fixed(1)),
	entry("SISMEMBER", fixed(2)),
	entry("SMISMEMBER", variadic(1, 1, "members")),
	entry("SSCAN", checkKeyScan("")),
	entry("SRANDMEMBER", checkRandom("")),

	entry("ZCARD", fixed(1)),
	entry("ZSCORE", fixed(2)),
	entry("ZMSCORE", variadic(1, 1, "members")),
	entry("ZRANK", checkZRank),
	entry("ZREVRANK", checkZRank),
	entry("ZCOUNT", fixed(3)),
	entry("ZLEXCOUNT", fixed(3)),
	entry("ZRANGE", checkZRange),
	entry("ZRANGEBYSCORE", checkZRangeBy(true)),
	entry("ZREVRANGEBYSCORE", checkZRangeBy(true)),
	entry("ZRANGEBYLEX", checkZRangeBy(false)),
	entry("ZREVRANGEBYLEX", checkZRangeBy(false)),
	entry("ZREVRANGE", checkZRevRange),
	entry("ZSCAN", checkKeyScan("")),
	entry("ZRANDMEMBER", checkRandom("withscores")),

	entry("XLEN", fixed(1)),
	entry("XRANGE", checkXRange),
	entry("XREVRANGE", checkXRange),
	subentry("XINFO", "STREAM", checkXInfoStream),
	subentry("XINFO", "GROUPS", fixed(1)),
	subentry("XINFO", "CONSUMERS", fixed(2)),
	entry("XPENDING", checkXPending),

	entry("GEOPOS", variadic(1, 0, "members")),
	entry("GEODIST", checkGeoDist),
	entry("GEOHASH", variadic(1, 0, "members")),
	entry("GEOSEARCH", checkGeoSearch),

	entry("PFCOUNT", variadic(0, 1, "keys")),
}

var commands, containers = indexAllowlist(allowlist)

func indexAllowlist(rules []*rule) (map[string]*rule, map[string]map[string]*rule) {
	cmds := map[string]*rule{}
	subs := map[string]map[string]*rule{}
	for _, r := range rules {
		name := asciiLower(r.Name)
		if r.Subcommand == "" {
			cmds[name] = r
			continue
		}
		if subs[name] == nil {
			subs[name] = map[string]*rule{}
		}
		subs[name][asciiLower(r.Subcommand)] = r
	}
	return cmds, subs
}

func subcommandList(container string) string {
	var names []string
	for _, r := range allowlist {
		if r.Subcommand != "" && asciiLower(r.Name) == container {
			names = append(names, r.Subcommand)
		}
	}
	return strings.Join(names, ", ")
}

func Allowlist() []Command {
	out := make([]Command, len(allowlist))
	for i, r := range allowlist {
		out[i] = r.Command
	}
	return out
}
