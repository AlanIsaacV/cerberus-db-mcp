//go:build integration

package redismcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

const (
	redisAddrVar      = "CERBERUS_TEST_REDIS_ADDR"
	redisUserVar      = "CERBERUS_TEST_REDIS_USER"
	redisPasswordVar  = "CERBERUS_TEST_REDIS_PASSWORD"
	requireEnginesVar = "CERBERUS_TEST_REQUIRE_ENGINES"
)

func redisIsRequired() bool {
	for _, name := range strings.Split(os.Getenv(requireEnginesVar), ",") {
		if strings.EqualFold(strings.TrimSpace(name), "redis") {
			return true
		}
	}
	return false
}

type fixture struct {
	host     string
	port     string
	user     string
	password string
	prefix   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	addr := os.Getenv(redisAddrVar)
	if addr == "" {
		if redisIsRequired() {
			t.Fatalf("%s names redis and %s is not set; set it to the host:port of the redis service in deploy/compose.test.yaml", requireEnginesVar, redisAddrVar)
		}
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
		prefix:   "cerberus-redismcp-it:" + strconv.FormatInt(time.Now().UnixNano(), 36) + ":",
	}
	if f.user == "" || f.password == "" {
		t.Fatalf("%s is set, so %s and %s must name the read-only ACL user the tools run as", redisAddrVar, redisUserVar, redisPasswordVar)
	}
	return f
}

func (f *fixture) name(suffix string) string { return f.prefix + suffix }

func (f *fixture) config(t *testing.T) *redisdb.Config {
	t.Helper()
	cfg, err := redisdb.LoadConfigFrom(map[string]string{
		"CERBERUS_REDIS_ALIASES":         "it",
		"CERBERUS_REDIS_IT_HOST":         f.host,
		"CERBERUS_REDIS_IT_PORT":         f.port,
		"CERBERUS_REDIS_IT_USER":         f.user,
		"CERBERUS_REDIS_IT_PASSWORD":     f.password,
		"CERBERUS_REDIS_IT_DATABASES":    "0,1",
		"CERBERUS_REDIS_COMMAND_TIMEOUT": "10s",
	})
	if err != nil {
		t.Fatalf("redisdb.LoadConfigFrom: %v", err)
	}
	return cfg
}

type adminConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (f *fixture) admin(t *testing.T, database int) *adminConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(f.host, f.port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the test Redis as the default user: %v", err)
	}
	a := &adminConn{conn: conn, reader: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	a.do(t, "SELECT", strconv.Itoa(database))
	return a
}

func (a *adminConn) do(t *testing.T, args ...string) any {
	t.Helper()
	if err := a.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	if _, err := io.WriteString(a.conn, b.String()); err != nil {
		t.Fatalf("write %v: %v", args, err)
	}
	reply, err := readReply(a.reader)
	if err != nil {
		t.Fatalf("setup %v: %v", args, err)
	}
	return reply
}

func (a *adminConn) seed(t *testing.T, args ...string) {
	t.Helper()
	a.do(t, args...)
	name := args[1]
	t.Cleanup(func() { a.do(t, "DEL", name) })
}

func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("empty reply line")
	}
	body := line[1:]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, fmt.Errorf("redis: %s", body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n < 0 {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n < 0 {
			return nil, err
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = readReply(r); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected reply line %q", line)
	}
}

func TestListToolsAgainstRedisNameAliasesCommandsAndLimitsOnly(t *testing.T) {
	f := newFixture(t)
	cfg := f.config(t)
	h := connect(t, cfg)

	res := h.call(t, "list_connections", map[string]any{})
	if res.IsError {
		t.Fatalf("list_connections failed: %s", resultText(t, res))
	}
	wantConnections := map[string]any{"connections": []any{
		map[string]any{"alias": "it.0", "database": float64(0)},
		map[string]any{"alias": "it.1", "database": float64(1)},
	}}
	if got := structured(t, res); !reflect.DeepEqual(got, wantConnections) {
		t.Errorf("list_connections = %v, want %v", got, wantConnections)
	}
	raw, _ := json.Marshal(res)
	for _, leaked := range []string{f.host, f.port, strconv.Quote(f.user), f.password} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("list_connections result contains %q: %s", leaked, raw)
		}
	}

	res = h.call(t, "list_commands", map[string]any{})
	if res.IsError {
		t.Fatalf("list_commands failed: %s", resultText(t, res))
	}
	got := structured(t, res)
	wantLimits := map[string]any{
		"max_elements":      float64(cfg.Settings.MaxElements),
		"max_count":         float64(cfg.Settings.MaxCount),
		"max_args":          float64(cfg.Settings.MaxArgs),
		"max_argv_bytes":    float64(cfg.Settings.MaxArgvBytes),
		"reply_byte_budget": float64(cfg.Settings.ReplyByteBudget),
	}
	if !reflect.DeepEqual(got["limits"], wantLimits) {
		t.Errorf("limits = %v, want %v", got["limits"], wantLimits)
	}
	commands, _ := got["commands"].([]any)
	allowlist := redisgate.Allowlist()
	if len(commands) != len(allowlist) {
		t.Fatalf("commands = %d entries, want %d", len(commands), len(allowlist))
	}
	for i, entry := range allowlist {
		want := map[string]any{"name": entry.Name, "rule_id": entry.RuleID}
		if entry.Subcommand != "" {
			want["subcommand"] = entry.Subcommand
		}
		if !reflect.DeepEqual(commands[i], want) {
			t.Errorf("commands[%d] = %v, want %v", i, commands[i], want)
		}
	}
}

func TestExecuteCommandReturnsEncodedRepliesAsTheReadOnlyUser(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(t, 0)
	text, binary, hash, list, stream := f.name("text"), f.name("binary"), f.name("hash"), f.name("list"), f.name("stream")
	admin.seed(t, "SET", text, "hello ☃")
	admin.seed(t, "SET", binary, "\xff\xfe")
	admin.seed(t, "HSET", hash, "f1", "v1", "f2", "v2")
	admin.seed(t, "RPUSH", list, "a", "b", "c", "d")
	admin.seed(t, "XADD", stream, "1-1", "field", "value")

	h := connect(t, f.config(t))
	for _, tt := range []struct {
		argv []string
		rule string
		want any
	}{
		{[]string{"GET", text}, "read-get", "hello ☃"},
		{[]string{"GET", binary}, "read-get", map[string]any{"$base64": "//4="}},
		{[]string{"HSCAN", hash, "0", "COUNT", "100"}, "read-hscan", []any{"0", []any{"f1", "v1", "f2", "v2"}}},
		{[]string{"LRANGE", list, "0", "2"}, "read-lrange", []any{"a", "b", "c"}},
		{[]string{"XRANGE", stream, "-", "+", "COUNT", "10"}, "read-xrange", []any{[]any{"1-1", []any{"field", "value"}}}},
	} {
		h.audit.Reset()
		res := h.call(t, "execute_command", map[string]any{"alias": "it.0", "argv": tt.argv})
		if res.IsError {
			t.Errorf("execute_command %v failed: %s", tt.argv, resultText(t, res))
			continue
		}
		got := structured(t, res)
		want := map[string]any{"reply": tt.want, "truncated": false, "truncation": "none"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("execute_command %v = %v, want %v", tt.argv, got, want)
		}
		events := h.auditEvents(t)
		if len(events) != 1 {
			t.Errorf("execute_command %v left %d audit lines, want 1", tt.argv, len(events))
			continue
		}
		assertAuditLine(t, events[0], map[string]any{
			"tool":       "execute_command",
			"alias":      "it.0",
			"argv":       argvField(tt.argv...),
			"outcome":    "allowed",
			"verdict":    "allow",
			"reason":     "bounded-read",
			"rule_id":    tt.rule,
			"error_kind": "",
			"truncated":  false,
		})
	}

	if clients, _ := admin.do(t, "CLIENT", "LIST").(string); !strings.Contains(clients, " user="+f.user+" ") {
		t.Errorf("no client connection to the test Redis runs as %s: %s", f.user, clients)
	}

	h.audit.Reset()
	res := h.call(t, "execute_command", map[string]any{"alias": "it.0", "argv": []string{"GET", hash}})
	if !res.IsError {
		t.Fatalf("GET on a hash succeeded: %v", structured(t, res))
	}
	if got := resultText(t, res); !strings.HasPrefix(got, "Redis replied with an error: WRONGTYPE") {
		t.Errorf("GET on a hash = %q, want Redis's WRONGTYPE message", got)
	}
	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("GET on a hash left %d audit lines, want 1", len(events))
	}
	assertAuditLine(t, events[0], map[string]any{
		"argv":       argvField("GET", hash),
		"outcome":    "failed",
		"verdict":    "allow",
		"error_kind": "redis_error",
	})
}

func TestScanKeysPagesThroughTheSeededKeyspace(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(t, 1)
	var strs, hashes []string
	for i := range 20 {
		name := f.name("scan:s:" + strconv.Itoa(i))
		admin.seed(t, "SET", name, "v")
		strs = append(strs, name)
	}
	for i := range 10 {
		name := f.name("scan:h:" + strconv.Itoa(i))
		admin.seed(t, "HSET", name, "f", "v")
		hashes = append(hashes, name)
	}
	for i := range 5 {
		admin.seed(t, "SET", f.name("other:"+strconv.Itoa(i)), "v")
	}

	h := connect(t, f.config(t))
	const count = 5
	scan := func(t *testing.T, kind string) ([]string, int) {
		t.Helper()
		var collected []string
		pages := 0
		cursor := "0"
		for {
			args := map[string]any{"alias": "it.1", "cursor": cursor, "match": f.name("scan:*"), "count": count}
			if kind != "" {
				args["type"] = kind
			}
			h.audit.Reset()
			res := h.call(t, "scan_keys", args)
			if res.IsError {
				t.Fatalf("scan_keys failed: %s", resultText(t, res))
			}
			got := structured(t, res)
			if got["truncation"] != "none" {
				t.Fatalf("scan_keys page was truncated: %v", got)
			}
			page, _ := got["keys"].([]any)
			for _, name := range page {
				collected = append(collected, name.(string))
			}
			wantArgv := []string{"SCAN", cursor, "COUNT", strconv.Itoa(count), "MATCH", f.name("scan:*")}
			if kind != "" {
				wantArgv = append(wantArgv, "TYPE", kind)
			}
			events := h.auditEvents(t)
			if len(events) != 1 {
				t.Fatalf("scan_keys left %d audit lines, want 1", len(events))
			}
			assertAuditLine(t, events[0], map[string]any{
				"tool":    "scan_keys",
				"alias":   "it.1",
				"argv":    argvField(wantArgv...),
				"outcome": "allowed",
				"rule_id": "read-scan",
			})
			pages++
			cursor, _ = got["cursor"].(string)
			if cursor == "0" {
				return collected, pages
			}
			if pages > 1000 {
				t.Fatal("scan_keys never returned cursor 0")
			}
		}
	}

	t.Run("match", func(t *testing.T) {
		collected, pages := scan(t, "")
		slices.Sort(collected)
		want := slices.Sorted(slices.Values(append(slices.Clone(strs), hashes...)))
		if !slices.Equal(slices.Compact(collected), want) {
			t.Errorf("scan_keys collected %v, want %v", collected, want)
		}
		if pages < 2 {
			t.Errorf("scan_keys returned %d pages for %d keys at count %d, want it to page", pages, len(want), count)
		}
	})
	t.Run("match and type", func(t *testing.T) {
		collected, _ := scan(t, "hash")
		slices.Sort(collected)
		if !slices.Equal(slices.Compact(collected), slices.Sorted(slices.Values(hashes))) {
			t.Errorf("scan_keys collected %v, want %v", collected, hashes)
		}
	})
}

func TestInspectKeyDescribesEachCoreTypeAndAMissingKey(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(t, 0)
	keys := map[string]string{
		"string": f.name("inspect:string"),
		"hash":   f.name("inspect:hash"),
		"list":   f.name("inspect:list"),
		"set":    f.name("inspect:set"),
		"zset":   f.name("inspect:zset"),
		"stream": f.name("inspect:stream"),
	}
	admin.seed(t, "SET", keys["string"], "hello")
	admin.do(t, "PEXPIRE", keys["string"], "600000")
	admin.seed(t, "HSET", keys["hash"], "a", "1", "b", "2", "c", "3")
	admin.seed(t, "RPUSH", keys["list"], "a", "b")
	admin.seed(t, "SADD", keys["set"], "x", "y", "z", "w")
	admin.seed(t, "ZADD", keys["zset"], "1", "m")
	admin.seed(t, "XADD", keys["stream"], "1-1", "f", "v")
	admin.do(t, "XADD", keys["stream"], "1-2", "f", "v")
	wantLength := map[string]float64{"string": 5, "hash": 3, "list": 2, "set": 4, "zset": 1, "stream": 2}
	lengthCommand := map[string]string{"string": "STRLEN", "hash": "HLEN", "list": "LLEN", "set": "SCARD", "zset": "ZCARD", "stream": "XLEN"}

	h := connect(t, f.config(t))
	for kind, name := range keys {
		t.Run(kind, func(t *testing.T) {
			h.audit.Reset()
			res := h.call(t, "inspect_key", map[string]any{"alias": "it.0", "key": name})
			if res.IsError {
				t.Fatalf("inspect_key failed: %s", resultText(t, res))
			}
			got := structured(t, res)
			if got["exists"] != true || got["type"] != kind || got["length"] != wantLength[kind] {
				t.Errorf("inspect_key = %v, want exists, type %s and length %v", got, kind, wantLength[kind])
			}
			if encoding := admin.do(t, "OBJECT", "ENCODING", name); got["encoding"] != encoding {
				t.Errorf("encoding = %v, want %v", got["encoding"], encoding)
			}
			if memory, _ := got["memory_bytes"].(float64); memory <= 0 {
				t.Errorf("memory_bytes = %v, want a positive number", got["memory_bytes"])
			}
			ttl, _ := got["ttl_ms"].(float64)
			if kind == "string" && (ttl <= 0 || ttl > 600000) {
				t.Errorf("ttl_ms = %v, want the remaining expiry", got["ttl_ms"])
			}
			if kind != "string" && ttl != -1 {
				t.Errorf("ttl_ms = %v, want -1 for a key without expiry", got["ttl_ms"])
			}

			events := h.auditEvents(t)
			wantArgvs := [][]string{
				{"TYPE", name},
				{"PTTL", name},
				{"OBJECT", "ENCODING", name},
				{"MEMORY", "USAGE", name, "SAMPLES", "1"},
				{lengthCommand[kind], name},
			}
			if len(events) != len(wantArgvs) {
				t.Fatalf("inspect_key left %d audit lines, want %d", len(events), len(wantArgvs))
			}
			for i, argv := range wantArgvs {
				assertAuditLine(t, events[i], map[string]any{
					"tool":       "inspect_key",
					"alias":      "it.0",
					"argv":       argvField(argv...),
					"outcome":    "allowed",
					"verdict":    "allow",
					"error_kind": "",
				})
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		h.audit.Reset()
		missing := f.name("inspect:missing")
		res := h.call(t, "inspect_key", map[string]any{"alias": "it.0", "key": missing})
		if res.IsError {
			t.Fatalf("inspect_key failed: %s", resultText(t, res))
		}
		if got := structured(t, res); !reflect.DeepEqual(got, map[string]any{"exists": false}) {
			t.Errorf("inspect_key on a missing key = %v, want only exists false", got)
		}
		events := h.auditEvents(t)
		if len(events) != 1 {
			t.Fatalf("inspect_key on a missing key left %d audit lines, want 1", len(events))
		}
		assertAuditLine(t, events[0], map[string]any{"argv": argvField("TYPE", missing), "outcome": "allowed"})
	})
}
