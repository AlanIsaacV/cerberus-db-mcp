package redismcp

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeRefused Outcome = "refused"
	OutcomeFailed  Outcome = "failed"
)

type invocation struct {
	tool     string
	identity string
	subject  string
}

type commandRecord struct {
	alias     string
	argv      []string
	outcome   Outcome
	verdict   redisgate.Verdict
	reason    redisgate.Reason
	ruleID    string
	errorKind redisdb.Kind
	truncated bool
	elapsed   time.Duration
}

func (s *Server) invoked(ctx context.Context, tool string) invocation {
	identity, subject := mcpserve.Caller(ctx, s.log, tool)
	return invocation{tool: tool, identity: identity, subject: subject}
}

func (s *Server) record(c invocation, r commandRecord) {
	argv := r.argv
	if argv == nil {
		argv = []string{}
	}
	s.audit.Record(c.tool, c.identity, c.subject, func(ev *zerolog.Event) {
		ev.Str("alias", r.alias).
			Strs("argv", argv).
			Str("outcome", string(r.outcome)).
			Str("verdict", string(r.verdict)).
			Str("reason", string(r.reason)).
			Str("rule_id", r.ruleID).
			Str("error_kind", string(r.errorKind)).
			Bool("truncated", r.truncated).
			Dur("elapsed_ms", r.elapsed)
	})
}

func (s *Server) execute(ctx context.Context, c invocation, alias string, argv []string) (*redisdb.Result, error) {
	started := time.Now()
	result, err := s.executor.Execute(ctx, alias, argv)
	r := commandRecord{alias: alias, argv: argv, elapsed: time.Since(started)}
	if err == nil {
		r.outcome = OutcomeAllowed
		r.verdict = result.Decision.Verdict
		r.reason = result.Decision.Reason
		r.ruleID = result.Decision.RuleID
		r.truncated = result.Truncation != redisdb.TruncationNone
		s.record(c, r)
		return result, nil
	}

	r.outcome = OutcomeFailed
	var rErr *redisdb.Error
	if !errors.As(err, &rErr) {
		s.log.Error().Err(err).
			Str("tool", c.tool).
			Str("alias", alias).
			Msg("a Redis command failed with an error that did not come from internal/redisdb")
		s.record(c, r)
		return nil, &mcpserve.AgentError{Message: internalFailure}
	}

	r.errorKind = rErr.Kind
	switch {
	case rErr.Decision != nil:
		r.outcome = OutcomeRefused
		r.verdict = rErr.Decision.Verdict
		r.reason = rErr.Decision.Reason
		r.ruleID = rErr.Decision.RuleID
	case rErr.Kind != redisdb.KindUnknownAlias:
		r.verdict = redisgate.Allow
	}

	s.log.Warn().
		Str("tool", c.tool).
		Str("alias", alias).
		Str("kind", string(rErr.Kind)).
		Str("detail", rErr.Error()).
		Msg("a Redis command did not return a reply")

	s.record(c, r)
	return nil, &mcpserve.AgentError{Message: agentText(rErr)}
}

func (s *Server) failed(c invocation, err error) error {
	s.log.Error().Err(err).
		Str("tool", c.tool).
		Msg("a Redis reply did not have the shape this tool reads")
	return &mcpserve.AgentError{Message: internalFailure}
}
