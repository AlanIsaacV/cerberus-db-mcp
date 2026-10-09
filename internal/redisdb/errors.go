package redisdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

type Kind string

const (
	KindUnknownAlias Kind = "unknown_alias"
	KindRefused      Kind = "refused"
	KindDeadline     Kind = "deadline"
	KindConnection   Kind = "connection"
	KindRedisError   Kind = "redis_error"
	KindCancelled    Kind = "cancelled"
)

var (
	ErrUnknownAlias = errors.New("no redis database is configured under that alias")
	ErrRefused      = errors.New("the command was refused by the gate")
	ErrDeadline     = errors.New("the command outlived its deadline")
	ErrConnection   = errors.New("the redis server could not be reached")
	ErrRedisError   = errors.New("redis replied with an error")
	ErrCancelled    = errors.New("the call was cancelled")
)

var kindSentinels = map[Kind]error{
	KindUnknownAlias: ErrUnknownAlias,
	KindRefused:      ErrRefused,
	KindDeadline:     ErrDeadline,
	KindConnection:   ErrConnection,
	KindRedisError:   ErrRedisError,
	KindCancelled:    ErrCancelled,
}

var connectionErrorCodes = map[string]bool{
	"WRONGPASS": true,
	"NOAUTH":    true,
}

type Error struct {
	Op       string
	Alias    string
	Kind     Kind
	Decision *redisgate.Decision
	Detail   string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("redisdb: ")
	b.WriteString(e.Op)
	if e.Alias != "" {
		fmt.Fprintf(&b, " on alias %q", e.Alias)
	}
	fmt.Fprintf(&b, ": %s: %s", e.Kind, e.Unwrap())
	if e.Decision != nil {
		fmt.Fprintf(&b, ": %s, rule %s", e.Decision.Reason, e.Decision.RuleID)
		if e.Decision.Detail != "" {
			fmt.Fprintf(&b, ": %s", e.Decision.Detail)
		}
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Detail)
	}
	return b.String()
}

func (e *Error) Unwrap() error {
	if sentinel, ok := kindSentinels[e.Kind]; ok {
		return sentinel
	}
	return ErrConnection
}

func executionError(callerCtx, commandCtx context.Context, spec AliasSpec, err error) *Error {
	return &Error{
		Op:     "execute",
		Alias:  spec.Alias,
		Kind:   classify(callerCtx, commandCtx, err),
		Detail: scrub(spec, err.Error()),
	}
}

func classify(callerCtx, commandCtx context.Context, err error) Kind {
	var redisErr redis.Error
	if errors.As(err, &redisErr) {
		code, _, _ := strings.Cut(redisErr.Error(), " ")
		if connectionErrorCodes[code] {
			return KindConnection
		}
		return KindRedisError
	}
	if errors.Is(callerCtx.Err(), context.Canceled) {
		return KindCancelled
	}
	if commandCtx.Err() != nil {
		return KindDeadline
	}
	if deadline, ok := commandCtx.Deadline(); ok && !time.Now().Before(deadline) {
		return KindDeadline
	}
	return KindConnection
}

func scrub(spec AliasSpec, s string) string {
	password := spec.Password.reveal()
	if password == "" {
		return s
	}
	return strings.ReplaceAll(s, password, redacted)
}
