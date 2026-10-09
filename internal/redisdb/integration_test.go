//go:build integration

package redisdb

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

const (
	redisAddrVar     = "CERBERUS_TEST_REDIS_ADDR"
	redisUserVar     = "CERBERUS_TEST_REDIS_USER"
	redisPasswordVar = "CERBERUS_TEST_REDIS_PASSWORD"
)

type fixture struct {
	host     string
	port     string
	user     string
	password string
	prefix   string
	admins   map[int]*redis.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	addr := os.Getenv(redisAddrVar)
	if addr == "" {
		t.Skipf("%s is not set; set it to the host:port of a redis:7.4.2-alpine started with the ro user of deploy/compose.test.yaml", redisAddrVar)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("%s is not a host:port: %v", redisAddrVar, err)
	}
	f := &fixture{
		host:     host,
		port:     port,
		user:     os.Getenv(redisUserVar),
		password: os.Getenv(redisPasswordVar),
		prefix:   "cerberus-redisdb-it:" + strconv.FormatInt(time.Now().UnixNano(), 36) + ":",
		admins:   map[int]*redis.Client{},
	}
	if f.user == "" || f.password == "" {
		t.Fatalf("%s is set, so %s and %s must name the read-only ACL user the reads go through", redisAddrVar, redisUserVar, redisPasswordVar)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.admin(t, 0).Ping(ctx).Err(); err != nil {
		t.Fatalf("%s=%s is set but not reachable: %v", redisAddrVar, addr, err)
	}
	return f
}

func (f *fixture) admin(t *testing.T, db int) *redis.Client {
	t.Helper()
	if c, ok := f.admins[db]; ok {
		return c
	}
	c := redis.NewClient(&redis.Options{
		Addr:            net.JoinHostPort(f.host, f.port),
		DB:              db,
		Protocol:        2,
		DisableIdentity: true,
		MaxRetries:      -1,
	})
	f.admins[db] = c
	t.Cleanup(func() { c.Close() })
	return c
}

func (f *fixture) key(name string) string { return f.prefix + name }

func (f *fixture) write(t *testing.T, db int, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := f.admin(t, db)
	if err := c.Do(ctx, args...).Err(); err != nil {
		t.Fatalf("setup %v in database %d: %v", args, db, err)
	}
	key, _ := args[1].(string)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Del(ctx, key)
	})
}

func (f *fixture) serverMillis(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now, err := f.admin(t, 0).Time(ctx).Result()
	if err != nil {
		t.Fatalf("TIME: %v", err)
	}
	return now.UnixMilli()
}

func (f *fixture) aclDenialsSince(t *testing.T, since int64) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := f.admin(t, 0).Do(ctx, "ACL", "LOG").Result()
	if err != nil {
		t.Fatalf("ACL LOG: %v", err)
	}
	entries, ok := raw.([]any)
	if !ok {
		t.Fatalf("ACL LOG replied %T", raw)
	}
	var out []map[string]any
	for _, e := range entries {
		fields, ok := e.([]any)
		if !ok {
			t.Fatalf("ACL LOG entry is %T", e)
		}
		entry := map[string]any{}
		for i := 0; i+1 < len(fields); i += 2 {
			name, _ := fields[i].(string)
			entry[name] = fields[i+1]
		}
		updated, _ := entry["timestamp-last-updated"].(int64)
		if entry["username"] == f.user && updated >= since {
			out = append(out, entry)
		}
	}
	return out
}

func (f *fixture) executor(t *testing.T, databases string, overrides map[string]string) *Executor {
	t.Helper()
	isolateEnvironment(t)
	environ := map[string]string{
		"CERBERUS_REDIS_ALIASES":         "it",
		"CERBERUS_REDIS_IT_HOST":         f.host,
		"CERBERUS_REDIS_IT_PORT":         f.port,
		"CERBERUS_REDIS_IT_USER":         f.user,
		"CERBERUS_REDIS_IT_PASSWORD":     f.password,
		"CERBERUS_REDIS_IT_DATABASES":    databases,
		"CERBERUS_REDIS_COMMAND_TIMEOUT": "10s",
	}
	for k, v := range overrides {
		environ[k] = v
	}
	cfg, err := LoadConfigFrom(environ)
	if err != nil {
		t.Fatalf("LoadConfigFrom() = %v", err)
	}
	g, err := redisgate.New(cfg.Settings.GateLimits())
	if err != nil {
		t.Fatalf("redisgate.New() = %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func run(t *testing.T, e *Executor, alias string, argv ...string) *Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := e.Execute(ctx, alias, argv)
	if err != nil {
		t.Fatalf("Execute(%s, %v) = %v", alias, argv, err)
	}
	return result
}

func bulk(s string) Value { return Value{Type: TypeString, Bytes: []byte(s)} }

func array(vs ...Value) Value {
	if vs == nil {
		vs = []Value{}
	}
	return Value{Type: TypeArray, Array: vs}
}

func bulks(ss ...string) Value {
	out := make([]Value, len(ss))
	for i, s := range ss {
		out[i] = bulk(s)
	}
	return array(out...)
}

func expect(t *testing.T, label string, result *Result, want Value, wantCut Truncation) {
	t.Helper()
	if result.Truncation != wantCut {
		t.Errorf("%s: truncation = %s, want %s", label, result.Truncation, wantCut)
	}
	if !reflect.DeepEqual(result.Reply, want) {
		t.Errorf("%s: reply\n got %s\nwant %s", label, render(result.Reply), render(want))
	}
}

func render(v Value) string {
	switch v.Type {
	case TypeString:
		return strconv.Quote(string(v.Bytes))
	case TypeInteger:
		return strconv.FormatInt(v.Integer, 10)
	case TypeArray:
		parts := make([]string, len(v.Array))
		for i, item := range v.Array {
			parts[i] = render(item)
		}
		return "[" + strings.Join(parts, " ") + "]"
	case TypeError:
		return "error(" + v.Message + ")"
	default:
		return string(v.Type)
	}
}

func scanMembers(t *testing.T, label string, result *Result) []string {
	t.Helper()
	reply := result.Reply
	if reply.Type != TypeArray || len(reply.Array) != 2 || reply.Array[1].Type != TypeArray {
		t.Fatalf("%s: reply is not [cursor, [members]]: %s", label, render(reply))
	}
	if reply.Array[0].Type != TypeString || string(reply.Array[0].Bytes) != "0" {
		t.Fatalf("%s: the scan did not finish in one call: cursor %s", label, render(reply.Array[0]))
	}
	var out []string
	for _, m := range reply.Array[1].Array {
		if m.Type != TypeString {
			t.Fatalf("%s: a member is %s", label, render(m))
		}
		out = append(out, string(m.Bytes))
	}
	return out
}

func TestReadsEveryCoreTypeFromItsOwnDatabaseAsTheReadOnlyUser(t *testing.T) {
	f := newFixture(t)
	since := f.serverMillis(t)

	f.write(t, 3, "SET", f.key("string"), "alpha-in-three")
	f.write(t, 3, "SET", f.key("only-three"), "three-only")
	f.write(t, 3, "HSET", f.key("hash"), "f1", "v1", "f2", "v2")
	f.write(t, 3, "RPUSH", f.key("list"), "a", "b", "c")
	f.write(t, 3, "SADD", f.key("set"), "m1", "m2", "m3")
	f.write(t, 3, "ZADD", f.key("zset"), "1", "one", "2", "two")
	f.write(t, 3, "XADD", f.key("stream"), "1-1", "field", "value1")
	f.write(t, 3, "XADD", f.key("stream"), "2-1", "field", "value2")
	f.write(t, 5, "SET", f.key("string"), "alpha-in-five")

	e := f.executor(t, "3,5", nil)

	expect(t, "GET in database 3", run(t, e, "it.3", "GET", f.key("string")), bulk("alpha-in-three"), TruncationNone)
	expect(t, "GET in database 5", run(t, e, "it.5", "GET", f.key("string")), bulk("alpha-in-five"), TruncationNone)
	expect(t, "GET of a key only database 3 holds, through it.5", run(t, e, "it.5", "GET", f.key("only-three")), Value{Type: TypeNil}, TruncationNone)
	expect(t, "GET of a missing key", run(t, e, "it.3", "GET", f.key("missing")), Value{Type: TypeNil}, TruncationNone)
	expect(t, "LLEN", run(t, e, "it.3", "LLEN", f.key("list")), Value{Type: TypeInteger, Integer: 3}, TruncationNone)
	expect(t, "LRANGE", run(t, e, "it.3", "LRANGE", f.key("list"), "0", "2"), bulks("a", "b", "c"), TruncationNone)
	expect(t, "ZRANGE WITHSCORES", run(t, e, "it.3", "ZRANGE", f.key("zset"), "0", "1", "WITHSCORES"), bulks("one", "1", "two", "2"), TruncationNone)
	expect(t, "XRANGE", run(t, e, "it.3", "XRANGE", f.key("stream"), "-", "+", "COUNT", "10"),
		array(
			array(bulk("1-1"), bulks("field", "value1")),
			array(bulk("2-1"), bulks("field", "value2")),
		), TruncationNone)

	hash := run(t, e, "it.3", "HSCAN", f.key("hash"), "0", "COUNT", "100")
	if hash.Truncation != TruncationNone {
		t.Errorf("HSCAN: truncation = %s", hash.Truncation)
	}
	pairs := scanMembers(t, "HSCAN", hash)
	got := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		got[pairs[i]] = pairs[i+1]
	}
	if want := map[string]string{"f1": "v1", "f2": "v2"}; len(pairs) != 4 || !reflect.DeepEqual(got, want) {
		t.Errorf("HSCAN: fields %v, want %v", pairs, want)
	}

	set := run(t, e, "it.3", "SSCAN", f.key("set"), "0", "COUNT", "100")
	if set.Truncation != TruncationNone {
		t.Errorf("SSCAN: truncation = %s", set.Truncation)
	}
	members := scanMembers(t, "SSCAN", set)
	slices.Sort(members)
	if want := []string{"m1", "m2", "m3"}; !slices.Equal(members, want) {
		t.Errorf("SSCAN: members %v, want %v", members, want)
	}

	_, err := e.Execute(context.Background(), "it.3", []string{"GET", f.key("hash")})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != KindRedisError || !errors.Is(err, ErrRedisError) {
		t.Fatalf("GET on a hash = %v, want kind redis_error", err)
	}
	if !strings.HasPrefix(failure.Detail, "WRONGTYPE") {
		t.Errorf("GET on a hash: detail %q, want Redis's WRONGTYPE message", failure.Detail)
	}

	if denials := f.aclDenialsSince(t, since); len(denials) > 0 {
		t.Fatalf("ACL LOG holds %d entries for %s from this run: %v", len(denials), f.user, denials)
	}
}

func TestRepliesAreCutAtTheElementCapAndTheByteBudget(t *testing.T) {
	const budget, elementCap = 16, 4
	f := newFixture(t)

	under := strings.Repeat("u", budget-1)
	at := strings.Repeat("a", budget)
	over := "o" + strings.Repeat("v", budget)
	f.write(t, 3, "SET", f.key("under"), under)
	f.write(t, 3, "SET", f.key("at"), at)
	f.write(t, 3, "SET", f.key("over"), over)
	f.write(t, 3, "SET", f.key("m1"), "aaaaaa")
	f.write(t, 3, "SET", f.key("m2"), "bbbbbb")
	f.write(t, 3, "SET", f.key("m3"), "cccccc")
	f.write(t, 3, "SADD", f.key("cap"), "1", "2", "3", "4")
	f.write(t, 3, "SADD", f.key("over-cap"), "1", "2", "3", "4", "5")

	e := f.executor(t, "3", map[string]string{
		"CERBERUS_REDIS_REPLY_BYTE_BUDGET": strconv.Itoa(budget),
		"CERBERUS_REDIS_MAX_ELEMENTS":      strconv.Itoa(elementCap),
	})

	expect(t, "GET budget-1", run(t, e, "it.3", "GET", f.key("under")), bulk(under), TruncationNone)
	expect(t, "GET budget", run(t, e, "it.3", "GET", f.key("at")), bulk(at), TruncationNone)
	expect(t, "GET budget+1", run(t, e, "it.3", "GET", f.key("over")), bulk(over[:budget]), TruncationByteBudget)
	expect(t, "MGET across the budget", run(t, e, "it.3", "MGET", f.key("m1"), f.key("m2"), f.key("m3")),
		bulks("aaaaaa", "bbbbbb", "cccc"), TruncationByteBudget)

	atCap := run(t, e, "it.3", "SSCAN", f.key("cap"), "0", "COUNT", "100")
	if atCap.Truncation != TruncationNone {
		t.Errorf("SSCAN of %d members: truncation = %s, want none", elementCap, atCap.Truncation)
	}
	if members := scanMembers(t, "SSCAN at the cap", atCap); len(members) != elementCap {
		t.Errorf("SSCAN of %d members returned %v", elementCap, members)
	}

	overCap := run(t, e, "it.3", "SSCAN", f.key("over-cap"), "0", "COUNT", "100")
	if overCap.Truncation != TruncationElementCap {
		t.Errorf("SSCAN of %d members: truncation = %s, want element_cap", elementCap+1, overCap.Truncation)
	}
	members := scanMembers(t, "SSCAN over the cap", overCap)
	if len(members) != elementCap {
		t.Errorf("SSCAN of %d members returned %d: %v", elementCap+1, len(members), members)
	}
	for _, m := range members {
		if !slices.Contains([]string{"1", "2", "3", "4", "5"}, m) {
			t.Errorf("SSCAN returned a member that was never written: %q", m)
		}
	}
}
