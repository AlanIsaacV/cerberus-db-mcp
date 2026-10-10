package redismcp

import (
	"context"
	"fmt"
	"strconv"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

const (
	ToolListConnections = "list_connections"
	ToolListCommands    = "list_commands"
	ToolExecuteCommand  = "execute_command"
	ToolScan            = "scan_keys"
	ToolInspect         = "inspect_key"
)

type ListConnectionsInput struct{}

type Connection struct {
	Alias    string `json:"alias" jsonschema:"the name to pass as the alias argument of the other tools"`
	Database int    `json:"database" jsonschema:"the numbered Redis database this alias reads"`
}

type ListConnectionsResult struct {
	Connections []Connection `json:"connections"`
}

type ListCommandsInput struct{}

type Limits struct {
	MaxElements     int `json:"max_elements" jsonschema:"the most elements one reply array keeps, and the widest range or the most keys, fields or members one command may name"`
	MaxCount        int `json:"max_count" jsonschema:"the largest COUNT a command may carry; every SCAN-family command must carry one"`
	MaxArgs         int `json:"max_args" jsonschema:"the most elements an argv may have, the command name included"`
	MaxArgvBytes    int `json:"max_argv_bytes" jsonschema:"the most bytes an argv may hold in total"`
	ReplyByteBudget int `json:"reply_byte_budget" jsonschema:"the most string bytes one reply keeps; a longer reply is cut and reported as truncated"`
}

type ListCommandsResult struct {
	Commands []redisgate.Command `json:"commands" jsonschema:"every command this server sends to Redis, with its subcommand where it has one and the gate rule that admits it"`
	Limits   Limits              `json:"limits" jsonschema:"the bounds every command and reply is held to"`
}

type ExecuteCommandInput struct {
	Alias string   `json:"alias" jsonschema:"which configured database to run against, as named by list_connections"`
	Argv  []string `json:"argv" jsonschema:"the command and its arguments, one element each, such as [\"HSCAN\", \"user:1\", \"0\", \"COUNT\", \"100\"]; only the read-only, bounded commands list_commands names are sent"`
}

type ExecuteCommandResult struct {
	Reply      any                `json:"reply" jsonschema:"the reply: a string is a JSON string when it is UTF-8 and an object with a single $base64 key otherwise, an integer is a number, a nil reply is null, an array is an array in order, and an error inside an array is an object with a single error key"`
	Truncated  bool               `json:"truncated" jsonschema:"true when the reply is only the beginning of what Redis sent; the same as truncation not being none"`
	Truncation redisdb.Truncation `json:"truncation" jsonschema:"which bound cut the reply: none, element_cap when an array had more elements than max_elements, or byte_budget when its strings passed reply_byte_budget; narrow the command rather than repeating it"`
}

type ScanKeysInput struct {
	Alias  string `json:"alias" jsonschema:"which configured database to scan, as named by list_connections"`
	Cursor string `json:"cursor,omitempty" jsonschema:"the cursor a previous call returned; omit it or pass 0 to start"`
	Match  string `json:"match,omitempty" jsonschema:"an optional glob the key names must match, such as user:*"`
	Type   string `json:"type,omitempty" jsonschema:"an optional Redis type the keys must have: string, hash, list, set, zset or stream"`
	Count  int    `json:"count,omitempty" jsonschema:"how much of the keyspace one call examines, at most max_count from list_commands; omitted, it is max_count"`
}

type ScanKeysResult struct {
	Cursor     string             `json:"cursor" jsonschema:"the cursor for the next call; 0 means the scan has visited the whole keyspace"`
	Keys       []any              `json:"keys" jsonschema:"the key names this call found, each a string or, when not UTF-8, an object with a single $base64 key; a page may be empty while the cursor is not 0"`
	Truncated  bool               `json:"truncated" jsonschema:"true when this page lost key names to max_elements or reply_byte_budget"`
	Truncation redisdb.Truncation `json:"truncation" jsonschema:"which bound cut this page: none, element_cap or byte_budget; when it is not none, repeat the scan from the same cursor with a smaller count"`
}

type InspectKeyInput struct {
	Alias string `json:"alias" jsonschema:"which configured database to read, as named by list_connections"`
	Key   string `json:"key" jsonschema:"the exact key name"`
}

type InspectKeyResult struct {
	Exists      bool   `json:"exists" jsonschema:"false when the key does not exist; no other field is then present"`
	Type        string `json:"type,omitempty" jsonschema:"the Redis type of the key"`
	TTLMillis   *int64 `json:"ttl_ms,omitempty" jsonschema:"the remaining time to live in milliseconds, or -1 when the key does not expire"`
	Encoding    string `json:"encoding,omitempty" jsonschema:"the internal encoding Redis reports for the value"`
	MemoryBytes *int64 `json:"memory_bytes,omitempty" jsonschema:"the bytes Redis estimates the key and its value occupy, sampling one element of an aggregate value"`
	Length      *int64 `json:"length,omitempty" jsonschema:"the length of the value: bytes of a string, fields of a hash, elements of a list, members of a set or sorted set, entries of a stream; absent for other types"`
}

const typeNone = "none"

const memorySamples = "1"

var lengthCommands = map[string]string{
	"string": "STRLEN",
	"hash":   "HLEN",
	"list":   "LLEN",
	"set":    "SCARD",
	"zset":   "ZCARD",
	"stream": "XLEN",
}

func (s *Server) registerTools(srv *sdk.Server) {
	sdk.AddTool(srv, &sdk.Tool{
		Name:        ToolListConnections,
		Description: "List the Redis databases this server can read, each as an alias and the database number behind it. Call this first: every other tool takes an alias listed here.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.listConnections)

	sdk.AddTool(srv, &sdk.Tool{
		Name:        ToolListCommands,
		Description: "List every Redis command execute_command accepts, and the limits every command and reply is held to. A command not listed here is refused before it reaches Redis.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.listCommands)

	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolExecuteCommand,
		Description: "Run one read-only Redis command, given as an argv, against one configured database and return its reply. " +
			"The argv is checked before anything is sent: writes, administration, scripting, blocking commands and commands that return a whole value with no bound are refused with the reason and the rule that refused them. " +
			"SCAN-family commands must carry COUNT, ranges must be bounded, and the reply is cut at max_elements per array and at reply_byte_budget bytes of strings; truncation says which bound cut it.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.executeCommand)

	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolScan,
		Description: "Page through the key names of one configured database with one SCAN per call, optionally filtered by a glob and a type. " +
			"Pass the returned cursor to the next call and stop when it is 0. A page can be empty, or hold slightly more than count names, while the scan continues.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.scanKeys)

	sdk.AddTool(srv, &sdk.Tool{
		Name: ToolInspect,
		Description: "Describe one key without reading its value: whether it exists, its type, its time to live, its encoding, the memory it occupies and its length. " +
			"Use execute_command with a bounded read to see the value itself.",
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.inspectKey)
}

func (s *Server) listConnections(ctx context.Context, _ *sdk.CallToolRequest, _ ListConnectionsInput) (*sdk.CallToolResult, *ListConnectionsResult, error) {
	started := time.Now()
	out := &ListConnectionsResult{Connections: append([]Connection{}, s.connections...)}
	s.record(s.invoked(ctx, ToolListConnections), commandRecord{outcome: OutcomeAllowed, elapsed: time.Since(started)})
	return nil, out, nil
}

func (s *Server) listCommands(ctx context.Context, _ *sdk.CallToolRequest, _ ListCommandsInput) (*sdk.CallToolResult, *ListCommandsResult, error) {
	started := time.Now()
	out := &ListCommandsResult{Commands: redisgate.Allowlist(), Limits: s.limits}
	s.record(s.invoked(ctx, ToolListCommands), commandRecord{outcome: OutcomeAllowed, elapsed: time.Since(started)})
	return nil, out, nil
}

func (s *Server) executeCommand(ctx context.Context, _ *sdk.CallToolRequest, in ExecuteCommandInput) (*sdk.CallToolResult, *ExecuteCommandResult, error) {
	c := s.invoked(ctx, ToolExecuteCommand)
	result, err := s.execute(ctx, c, in.Alias, in.Argv)
	if err != nil {
		return nil, nil, err
	}
	return nil, &ExecuteCommandResult{
		Reply:      encodeReply(result.Reply, result.Truncation),
		Truncated:  result.Truncation != redisdb.TruncationNone,
		Truncation: result.Truncation,
	}, nil
}

func (s *Server) scanKeys(ctx context.Context, _ *sdk.CallToolRequest, in ScanKeysInput) (*sdk.CallToolResult, *ScanKeysResult, error) {
	c := s.invoked(ctx, ToolScan)
	cursor := in.Cursor
	if cursor == "" {
		cursor = "0"
	}
	count := in.Count
	if count == 0 {
		count = s.limits.MaxCount
	}
	argv := []string{"SCAN", cursor, "COUNT", strconv.Itoa(count)}
	if in.Match != "" {
		argv = append(argv, "MATCH", in.Match)
	}
	if in.Type != "" {
		argv = append(argv, "TYPE", in.Type)
	}

	result, err := s.execute(ctx, c, in.Alias, argv)
	if err != nil {
		return nil, nil, err
	}
	reply := result.Reply
	if reply.Type != redisdb.TypeArray || len(reply.Array) != 2 ||
		reply.Array[0].Type != redisdb.TypeString || reply.Array[1].Type != redisdb.TypeArray {
		return nil, nil, s.failed(c, fmt.Errorf("SCAN replied with a %s of %d elements", reply.Type, len(reply.Array)))
	}
	encoded, ok := encodeReply(reply, result.Truncation).([]any)
	if !ok || len(encoded) != 2 {
		return nil, nil, s.failed(c, fmt.Errorf("SCAN's reply did not encode as a two-element array"))
	}
	next, ok := encoded[0].(string)
	if !ok {
		return nil, nil, s.failed(c, fmt.Errorf("SCAN replied with a cursor that is not text"))
	}
	names, ok := encoded[1].([]any)
	if !ok {
		return nil, nil, s.failed(c, fmt.Errorf("SCAN replied with a page that is not an array"))
	}
	return nil, &ScanKeysResult{
		Cursor:     next,
		Keys:       names,
		Truncated:  result.Truncation != redisdb.TruncationNone,
		Truncation: result.Truncation,
	}, nil
}

func (s *Server) inspectKey(ctx context.Context, _ *sdk.CallToolRequest, in InspectKeyInput) (*sdk.CallToolResult, *InspectKeyResult, error) {
	c := s.invoked(ctx, ToolInspect)

	kind, err := s.textReply(ctx, c, in.Alias, []string{"TYPE", in.Key})
	if err != nil {
		return nil, nil, err
	}
	if kind == typeNone {
		return nil, &InspectKeyResult{Exists: false}, nil
	}
	out := &InspectKeyResult{Exists: true, Type: kind}

	if out.TTLMillis, err = s.integerReply(ctx, c, in.Alias, []string{"PTTL", in.Key}); err != nil {
		return nil, nil, err
	}
	if out.Encoding, err = s.textReply(ctx, c, in.Alias, []string{"OBJECT", "ENCODING", in.Key}); err != nil {
		return nil, nil, err
	}
	if out.MemoryBytes, err = s.integerReply(ctx, c, in.Alias, []string{"MEMORY", "USAGE", in.Key, "SAMPLES", memorySamples}); err != nil {
		return nil, nil, err
	}
	if command, ok := lengthCommands[kind]; ok {
		if out.Length, err = s.integerReply(ctx, c, in.Alias, []string{command, in.Key}); err != nil {
			return nil, nil, err
		}
	}
	return nil, out, nil
}

func (s *Server) textReply(ctx context.Context, c invocation, alias string, argv []string) (string, error) {
	result, err := s.execute(ctx, c, alias, argv)
	if err != nil {
		return "", err
	}
	if result.Reply.Type != redisdb.TypeString {
		return "", s.failed(c, fmt.Errorf("%s replied with a %s where text was expected", argv[0], result.Reply.Type))
	}
	return string(result.Reply.Bytes), nil
}

func (s *Server) integerReply(ctx context.Context, c invocation, alias string, argv []string) (*int64, error) {
	result, err := s.execute(ctx, c, alias, argv)
	if err != nil {
		return nil, err
	}
	switch result.Reply.Type {
	case redisdb.TypeNil:
		return nil, nil
	case redisdb.TypeInteger:
		n := result.Reply.Integer
		return &n, nil
	default:
		return nil, s.failed(c, fmt.Errorf("%s replied with a %s where an integer was expected", argv[0], result.Reply.Type))
	}
}
