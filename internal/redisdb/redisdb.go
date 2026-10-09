package redisdb

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

var ErrNoGate = errors.New("no gate was supplied")

type Executor struct {
	gate     *redisgate.Gate
	settings Settings
	clients  map[string]*aliasClient
	order    []string
}

type aliasClient struct {
	spec   AliasSpec
	client *redis.Client
}

type Result struct {
	Alias      string
	Decision   redisgate.Decision
	Reply      Value
	Truncation Truncation
	Elapsed    time.Duration
}

func New(g *redisgate.Gate, cfg *Config) (*Executor, error) {
	if g == nil {
		return nil, fmt.Errorf("redisdb: new executor: %w", ErrNoGate)
	}
	if cfg == nil || len(cfg.Aliases) == 0 {
		return nil, fmt.Errorf("redisdb: new executor: %w", ErrNoAliases)
	}
	if err := cfg.Settings.validate(); err != nil {
		return nil, err
	}
	if err := refuseUnknownVariables(cfg.Aliases); err != nil {
		return nil, err
	}
	for i, spec := range cfg.Aliases {
		if spec.TLS != "" && !slices.Contains(tlsModes(), spec.TLS) {
			return nil, fmt.Errorf("redisdb: configured alias %d has a TLS mode outside %v: %w", i+1, tlsModes(), ErrInvalidVariable)
		}
	}
	e := &Executor{
		gate:     g,
		settings: cfg.Settings,
		clients:  make(map[string]*aliasClient, len(cfg.Aliases)),
	}
	for i, spec := range cfg.Aliases {
		if _, taken := e.clients[spec.Alias]; taken {
			_ = e.Close()
			return nil, fmt.Errorf("redisdb: configured alias %d repeats an alias name: %w", i+1, ErrDuplicateAlias)
		}
		e.clients[spec.Alias] = &aliasClient{spec: spec, client: redis.NewClient(clientOptions(spec, cfg.Settings))}
		e.order = append(e.order, spec.Alias)
	}
	return e, nil
}

func clientOptions(spec AliasSpec, s Settings) *redis.Options {
	return &redis.Options{
		Addr:                  net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port)),
		Username:              spec.User,
		Password:              spec.Password.reveal(),
		DB:                    spec.Database,
		Protocol:              2,
		DisableIdentity:       true,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
		PoolSize:              s.MaxConns,
		DialTimeout:           s.ConnectTimeout,
		ReadTimeout:           s.CommandTimeout,
		WriteTimeout:          s.CommandTimeout,
		TLSConfig:             tlsConfig(spec),
	}
}

func tlsConfig(spec AliasSpec) *tls.Config {
	switch spec.TLS {
	case TLSRequire:
		return &tls.Config{ServerName: spec.Host}
	case TLSRequireInsecure:
		return &tls.Config{ServerName: spec.Host, InsecureSkipVerify: true}
	default:
		return nil
	}
}

func (e *Executor) Close() error {
	var errs []error
	for _, name := range e.order {
		if err := e.clients[name].client.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Executor) Execute(ctx context.Context, alias string, argv []string) (*Result, error) {
	c, ok := e.clients[alias]
	if !ok {
		return nil, &Error{Op: "execute", Alias: alias, Kind: KindUnknownAlias}
	}

	decision := e.gate.Validate(argv)
	if decision.Verdict != redisgate.Allow {
		return nil, &Error{Op: "execute", Alias: alias, Kind: KindRefused, Decision: &decision}
	}

	started := time.Now()
	commandCtx, cancel := context.WithTimeout(ctx, e.settings.CommandTimeout)
	defer cancel()

	args := make([]any, len(argv))
	for i, a := range argv {
		args[i] = a
	}
	raw, err := c.client.Do(commandCtx, args...).Result()
	if err != nil && err != redis.Nil {
		return nil, executionError(ctx, commandCtx, c.spec, err)
	}

	reply, truncation, err := boundReply(raw, e.settings.MaxElements, e.settings.ReplyByteBudget)
	if err != nil {
		return nil, &Error{Op: "execute", Alias: alias, Kind: KindConnection, Detail: err.Error()}
	}
	return &Result{
		Alias:      alias,
		Decision:   decision,
		Reply:      reply,
		Truncation: truncation,
		Elapsed:    time.Since(started),
	}, nil
}
