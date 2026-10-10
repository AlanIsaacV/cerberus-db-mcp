package redismcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

func isolateRedisEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "CERBERUS_REDIS_") && value != "" {
			t.Setenv(name, "")
		}
	}
}

func deadPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", l.Addr(), err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return port
}

type countingListener struct {
	listener net.Listener
	accepted atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
}

func silentListener(t *testing.T) *countingListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &countingListener{listener: l}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			c.accepted.Add(1)
			c.mu.Lock()
			c.conns = append(c.conns, conn)
			c.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, conn := range c.conns {
			_ = conn.Close()
		}
	})
	return c
}

func (c *countingListener) port(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(c.listener.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", c.listener.Addr(), err)
	}
	return port
}

func redisConfig(t *testing.T, port string, overrides map[string]string) *redisdb.Config {
	t.Helper()
	environ := map[string]string{
		"CERBERUS_REDIS_ALIASES":         "cache",
		"CERBERUS_REDIS_CACHE_HOST":      "127.0.0.1",
		"CERBERUS_REDIS_CACHE_PORT":      port,
		"CERBERUS_REDIS_CACHE_USER":      "reader",
		"CERBERUS_REDIS_CACHE_PASSWORD":  "hunter2",
		"CERBERUS_REDIS_CACHE_DATABASES": "0,3",
		"CERBERUS_REDIS_CONNECT_TIMEOUT": "2s",
	}
	for k, v := range overrides {
		environ[k] = v
	}
	cfg, err := redisdb.LoadConfigFrom(environ)
	if err != nil {
		t.Fatalf("redisdb.LoadConfigFrom: %v", err)
	}
	return cfg
}

func executorFor(t *testing.T, cfg *redisdb.Config) *redisdb.Executor {
	t.Helper()
	isolateRedisEnvironment(t)
	g, err := redisgate.New(cfg.Settings.GateLimits())
	if err != nil {
		t.Fatalf("redisgate.New: %v", err)
	}
	e, err := redisdb.New(g, cfg)
	if err != nil {
		t.Fatalf("redisdb.New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

type harness struct {
	session *sdk.ClientSession
	audit   *lockedBuffer
	appLog  *lockedBuffer
}

func connect(t *testing.T, cfg *redisdb.Config) *harness {
	t.Helper()
	h := &harness{audit: &lockedBuffer{}, appLog: &lockedBuffer{}}
	srv, err := New(Deps{
		Config:   mcpserve.Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: 5 * time.Second},
		Executor: executorFor(t, cfg),
		Redis:    cfg,
		Log:      mcpserve.NewLogger(h.appLog),
		Audit:    mcpserve.NewAuditor(h.audit),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "cerberus-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             httpServer.URL + "/mcp",
		HTTPClient:           http.DefaultClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	h.session = session
	return h
}

func (h *harness) call(t *testing.T, name string, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := h.session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s, %v) returned a protocol error: %v", name, args, err)
	}
	return res
}

func resultText(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("the tool result carries no content: %+v", res)
	}
	tc, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func structured(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured content %s: %v", raw, err)
	}
	return out
}

func (h *harness) auditEvents(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("the audit stream is not one JSON object per line: %v\n%s", err, line)
		}
		out = append(out, event)
	}
	return out
}

var auditFieldSet = []string{
	"alias", "argv", "elapsed_ms", "error_kind", "identity", "message", "outcome", "reason",
	"rule_id", "stream", "subject", "time", "tool", "truncated", "verdict",
}

func assertAuditLine(t *testing.T, event map[string]any, want map[string]any) {
	t.Helper()
	fields := make([]string, 0, len(event))
	for name := range event {
		fields = append(fields, name)
	}
	slices.Sort(fields)
	if !slices.Equal(fields, auditFieldSet) {
		t.Errorf("audit line fields = %v, want %v", fields, auditFieldSet)
	}
	if event["stream"] != "audit" || event["message"] != "tool call" {
		t.Errorf("audit line stream = %v, message = %v, want audit and tool call", event["stream"], event["message"])
	}
	if _, ok := event["elapsed_ms"].(float64); !ok {
		t.Errorf("audit line elapsed_ms = %v, want a number", event["elapsed_ms"])
	}
	for name, value := range want {
		if !reflect.DeepEqual(event[name], value) {
			t.Errorf("audit line %s = %#v, want %#v", name, event[name], value)
		}
	}
}

func argvField(argv ...string) []any {
	out := make([]any, len(argv))
	for i, a := range argv {
		out[i] = a
	}
	return out
}

func TestToolsListIsExactlyTheFiveReadOnlyToolsWithDerivedSchemas(t *testing.T) {
	h := connect(t, redisConfig(t, deadPort(t), nil))

	if got := h.session.InitializeResult().ServerInfo.Name; got != "cerberus-cache-mcp" {
		t.Errorf("server name = %q, want cerberus-cache-mcp", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := h.session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := make(map[string]*sdk.Tool, len(list.Tools))
	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		got[tool.Name] = tool
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	wantNames := []string{"execute_command", "inspect_key", "list_commands", "list_connections", "scan_keys"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("tools/list = %v, want exactly %v", names, wantNames)
	}

	for name, wantJSON := range map[string]string{
		"list_connections": `{"additionalProperties":false,"type":"object"}`,
		"list_commands":    `{"additionalProperties":false,"type":"object"}`,
		"execute_command": `{"additionalProperties":false,"type":"object",` +
			`"properties":{` +
			`"alias":{"type":"string","description":"which configured database to run against, as named by list_connections"},` +
			`"argv":{"type":["null","array"],"items":{"type":"string"},"description":"the command and its arguments, one element each, such as [\"HSCAN\", \"user:1\", \"0\", \"COUNT\", \"100\"]; only the read-only, bounded commands list_commands names are sent"}},` +
			`"required":["alias","argv"]}`,
		"scan_keys": `{"additionalProperties":false,"type":"object",` +
			`"properties":{` +
			`"alias":{"type":"string","description":"which configured database to scan, as named by list_connections"},` +
			`"cursor":{"type":"string","description":"the cursor a previous call returned; omit it or pass 0 to start"},` +
			`"match":{"type":"string","description":"an optional glob the key names must match, such as user:*"},` +
			`"type":{"type":"string","description":"an optional Redis type the keys must have: string, hash, list, set, zset or stream"},` +
			`"count":{"type":"integer","description":"how much of the keyspace one call examines, at most max_count from list_commands; omitted, it is max_count"}},` +
			`"required":["alias"]}`,
		"inspect_key": `{"additionalProperties":false,"type":"object",` +
			`"properties":{` +
			`"alias":{"type":"string","description":"which configured database to read, as named by list_connections"},` +
			`"key":{"type":"string","description":"the exact key name"}},` +
			`"required":["alias","key"]}`,
	} {
		var want any
		if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
			t.Fatalf("the expectation for %q is not valid JSON: %v", name, err)
		}
		if !reflect.DeepEqual(got[name].InputSchema, want) {
			actual, _ := json.Marshal(got[name].InputSchema)
			t.Errorf("%q input schema =\n%s\nwant\n%s", name, actual, wantJSON)
		}
	}

	for _, name := range wantNames {
		tool := got[name]
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%q does not carry ReadOnlyHint: %+v", name, tool.Annotations)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%q has no output schema, so its result carries no structured content", name)
		}
	}
}

func TestRefusedArgvsOpenNoConnectionAndAreAuditedAsRefused(t *testing.T) {
	listener := silentListener(t)
	h := connect(t, redisConfig(t, listener.port(t), nil))

	cases := []struct {
		argv   []string
		reason string
		rule   string
	}{
		{[]string{"SET", "k", "v"}, "forbidden-command", "forbidden-set"},
		{[]string{"DEL", "k"}, "forbidden-command", "forbidden-del"},
		{[]string{"FLUSHALL"}, "forbidden-command", "forbidden-flushall"},
		{[]string{"CONFIG", "SET", "maxmemory", "1"}, "forbidden-command", "forbidden-config"},
		{[]string{"KEYS", "*"}, "forbidden-command", "forbidden-keys"},
		{[]string{"EVAL", "return 1", "0"}, "forbidden-command", "forbidden-eval"},
		{[]string{"MONITOR"}, "forbidden-command", "forbidden-monitor"},
		{[]string{"BLPOP", "k", "0"}, "forbidden-command", "forbidden-blpop"},
		{[]string{"HGETALL", "k"}, "unbounded-command", "unbounded-hgetall"},
	}
	for _, tt := range cases {
		res := h.call(t, "execute_command", map[string]any{"alias": "cache.0", "argv": tt.argv})
		if !res.IsError {
			t.Errorf("execute_command %v was not refused: %v", tt.argv, structured(t, res))
			continue
		}
		text := resultText(t, res)
		if !strings.Contains(text, tt.reason) || !strings.Contains(text, tt.rule) {
			t.Errorf("execute_command %v refusal = %q, want it to name reason %s and rule %s", tt.argv, text, tt.reason, tt.rule)
		}
	}

	if n := listener.accepted.Load(); n != 0 {
		t.Errorf("the refused argvs opened %d TCP connections, want none", n)
	}

	events := h.auditEvents(t)
	if len(events) != len(cases) {
		t.Fatalf("audit lines = %d, want %d: %s", len(events), len(cases), h.audit.String())
	}
	for i, tt := range cases {
		assertAuditLine(t, events[i], map[string]any{
			"tool":       "execute_command",
			"identity":   "",
			"subject":    "",
			"alias":      "cache.0",
			"argv":       argvField(tt.argv...),
			"outcome":    "refused",
			"verdict":    "deny",
			"reason":     tt.reason,
			"rule_id":    tt.rule,
			"error_kind": "refused",
			"truncated":  false,
		})
	}
}

func TestAConnectionFailureReachesTheAgentWithoutHostOrPort(t *testing.T) {
	port := deadPort(t)
	h := connect(t, redisConfig(t, port, nil))

	res := h.call(t, "execute_command", map[string]any{"alias": "cache.0", "argv": []string{"GET", "k"}})
	if !res.IsError {
		t.Fatalf("GET against a closed port succeeded: %v", structured(t, res))
	}
	text := resultText(t, res)
	if text != connectionText {
		t.Errorf("agent text = %q, want %q", text, connectionText)
	}
	for _, leaked := range []string{"127.0.0.1", port, "reader", "hunter2"} {
		if strings.Contains(text, leaked) {
			t.Errorf("agent text %q contains %q", text, leaked)
		}
	}
	logged := h.appLog.String()
	if !strings.Contains(logged, "127.0.0.1:"+port) || !strings.Contains(logged, `"kind":"connection"`) {
		t.Errorf("the application log does not carry the full error with host and port: %s", logged)
	}

	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit lines = %d, want 1: %s", len(events), h.audit.String())
	}
	assertAuditLine(t, events[0], map[string]any{
		"tool":       "execute_command",
		"alias":      "cache.0",
		"argv":       argvField("GET", "k"),
		"outcome":    "failed",
		"verdict":    "allow",
		"error_kind": "connection",
		"truncated":  false,
	})
}

func TestADeadlineReachesTheAgentWithoutHostOrPort(t *testing.T) {
	listener := silentListener(t)
	port := listener.port(t)
	h := connect(t, redisConfig(t, port, map[string]string{"CERBERUS_REDIS_COMMAND_TIMEOUT": "300ms"}))

	res := h.call(t, "execute_command", map[string]any{"alias": "cache.3", "argv": []string{"GET", "k"}})
	if !res.IsError {
		t.Fatalf("GET against a silent listener succeeded: %v", structured(t, res))
	}
	text := resultText(t, res)
	if text != deadlineText {
		t.Errorf("agent text = %q, want %q", text, deadlineText)
	}
	for _, leaked := range []string{"127.0.0.1", port} {
		if strings.Contains(text, leaked) {
			t.Errorf("agent text %q contains %q", text, leaked)
		}
	}
	logged := h.appLog.String()
	if !strings.Contains(logged, `"kind":"deadline"`) || !strings.Contains(logged, "redisdb: execute on alias") {
		t.Errorf("the application log does not carry the full deadline error: %s", logged)
	}
	if listener.accepted.Load() == 0 {
		t.Error("the silent listener accepted no connection, so the deadline was not reached through Redis's socket")
	}

	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit lines = %d, want 1: %s", len(events), h.audit.String())
	}
	assertAuditLine(t, events[0], map[string]any{
		"alias":      "cache.3",
		"argv":       argvField("GET", "k"),
		"outcome":    "failed",
		"verdict":    "allow",
		"error_kind": "deadline",
	})
}

func TestAnUnknownAliasIsNamedBackToTheAgent(t *testing.T) {
	listener := silentListener(t)
	h := connect(t, redisConfig(t, listener.port(t), nil))

	res := h.call(t, "inspect_key", map[string]any{"alias": "cache.9", "key": "k"})
	if !res.IsError {
		t.Fatalf("inspect_key on an unknown alias succeeded: %v", structured(t, res))
	}
	text := resultText(t, res)
	if !strings.Contains(text, `"cache.9"`) || !strings.Contains(text, "list_connections") {
		t.Errorf("agent text = %q, want it to name the alias cache.9 and point at list_connections", text)
	}
	if n := listener.accepted.Load(); n != 0 {
		t.Errorf("an unknown alias opened %d TCP connections, want none", n)
	}
	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit lines = %d, want 1: %s", len(events), h.audit.String())
	}
	assertAuditLine(t, events[0], map[string]any{
		"tool":       "inspect_key",
		"alias":      "cache.9",
		"argv":       argvField("TYPE", "k"),
		"outcome":    "failed",
		"verdict":    "",
		"reason":     "",
		"rule_id":    "",
		"error_kind": "unknown_alias",
	})
}

func TestAgentTextByErrorKind(t *testing.T) {
	refusal := redisgate.Decision{Verdict: redisgate.Deny, Reason: redisgate.ReasonForbiddenCommand, RuleID: "forbidden-set", Detail: "the command is refused by this server"}
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"refused", &redisdb.Error{Kind: redisdb.KindRefused, Alias: "cache.0", Decision: &refusal},
			"the command gate refused this argv and nothing was sent to Redis: verdict deny, reason forbidden-command, rule forbidden-set: the command is refused by this server. Call list_commands for the commands and limits this server accepts."},
		{"unknown alias", &redisdb.Error{Kind: redisdb.KindUnknownAlias, Alias: "nope"},
			`no Redis database is configured under the alias "nope"; call list_connections for the aliases this server reads`},
		{"redis error", &redisdb.Error{Kind: redisdb.KindRedisError, Detail: "WRONGTYPE Operation against a key holding the wrong kind of value"},
			"Redis replied with an error: WRONGTYPE Operation against a key holding the wrong kind of value"},
		{"redis acl error naming the user", &redisdb.Error{Kind: redisdb.KindRedisError, Detail: "NOPERM User ro has no permissions to run the 'get' command"}, nopermText},
		{"connection", &redisdb.Error{Kind: redisdb.KindConnection, Detail: "dial tcp 10.0.0.7:6379: connect: connection refused"}, connectionText},
		{"deadline", &redisdb.Error{Kind: redisdb.KindDeadline, Detail: "read tcp 10.0.0.7:6379: i/o timeout"}, deadlineText},
		{"cancelled", &redisdb.Error{Kind: redisdb.KindCancelled, Detail: "context canceled"}, cancelledText},
		{"not from redisdb", net.UnknownNetworkError("tcp 10.0.0.7:6379"), internalFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentText(tt.err); got != tt.want {
				t.Errorf("agentText = %q, want %q", got, tt.want)
			}
		})
	}
}
