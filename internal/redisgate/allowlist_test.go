package redisgate

import "testing"

var transcribedAllowlist = []string{
	"SCAN", "TYPE", "EXISTS", "TTL", "PTTL", "EXPIRETIME", "PEXPIRETIME",
	"OBJECT ENCODING", "OBJECT FREQ", "OBJECT IDLETIME", "OBJECT REFCOUNT",
	"MEMORY USAGE", "DBSIZE", "RANDOMKEY",

	"GET", "MGET", "STRLEN", "GETRANGE", "SUBSTR", "GETBIT", "BITCOUNT", "BITPOS",

	"HGET", "HMGET", "HLEN", "HSTRLEN", "HEXISTS", "HSCAN", "HRANDFIELD",

	"LLEN", "LINDEX", "LRANGE", "LPOS",

	"SCARD", "SISMEMBER", "SMISMEMBER", "SSCAN", "SRANDMEMBER",

	"ZCARD", "ZSCORE", "ZMSCORE", "ZRANK", "ZREVRANK", "ZCOUNT", "ZLEXCOUNT",
	"ZRANGE", "ZRANGEBYSCORE", "ZREVRANGEBYSCORE", "ZRANGEBYLEX", "ZREVRANGEBYLEX",
	"ZREVRANGE", "ZSCAN", "ZRANDMEMBER",

	"XLEN", "XRANGE", "XREVRANGE", "XINFO STREAM", "XINFO GROUPS", "XINFO CONSUMERS", "XPENDING",

	"GEOPOS", "GEODIST", "GEOHASH", "GEOSEARCH",

	"PFCOUNT",
}

func commandLabel(c Command) string {
	if c.Subcommand == "" {
		return c.Name
	}
	return c.Name + " " + c.Subcommand
}

func TestAllowlistMatchesTheTranscribedList(t *testing.T) {
	if len(transcribedAllowlist) != 65 {
		t.Fatalf("the transcribed list has %d entries, want 65", len(transcribedAllowlist))
	}
	want := map[string]bool{}
	for _, name := range transcribedAllowlist {
		if want[name] {
			t.Fatalf("the transcribed list names %s twice", name)
		}
		want[name] = true
	}
	got := map[string]bool{}
	for _, c := range Allowlist() {
		label := commandLabel(c)
		if got[label] {
			t.Errorf("Allowlist() names %s twice", label)
		}
		got[label] = true
		if !want[label] {
			t.Errorf("Allowlist() has %s, which the transcribed list does not", label)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("the transcribed list has %s, which Allowlist() does not", name)
		}
	}
}
