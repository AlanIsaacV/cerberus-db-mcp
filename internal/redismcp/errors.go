package redismcp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
)

const internalFailure = "the server failed to complete the call"

const (
	connectionText = "the Redis server behind this alias could not be reached or did not accept this server's login; nothing was read"
	deadlineText   = "the command did not complete within this server's time limit; nothing was returned"
	cancelledText  = "the call was cancelled before the command completed"
	nopermText     = "Redis refused the command under the permissions of this server's ACL user (NOPERM)"
)

func agentText(err error) string {
	var rErr *redisdb.Error
	if !errors.As(err, &rErr) {
		return internalFailure
	}
	switch rErr.Kind {
	case redisdb.KindRefused:
		if rErr.Decision == nil {
			return internalFailure
		}
		d := rErr.Decision
		text := fmt.Sprintf("the command gate refused this argv and nothing was sent to Redis: verdict %s, reason %s, rule %s", d.Verdict, d.Reason, d.RuleID)
		if d.Detail != "" {
			text += ": " + d.Detail
		}
		return text + ". Call list_commands for the commands and limits this server accepts."
	case redisdb.KindUnknownAlias:
		return fmt.Sprintf("no Redis database is configured under the alias %q; call list_connections for the aliases this server reads", rErr.Alias)
	case redisdb.KindRedisError:
		if strings.HasPrefix(rErr.Detail, "NOPERM") {
			return nopermText
		}
		return "Redis replied with an error: " + rErr.Detail
	case redisdb.KindConnection:
		return connectionText
	case redisdb.KindDeadline:
		return deadlineText
	case redisdb.KindCancelled:
		return cancelledText
	default:
		return internalFailure
	}
}
