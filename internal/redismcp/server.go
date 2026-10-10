package redismcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
)

const (
	ServerName    = "cerberus-redis-mcp"
	serverVersion = "0.1.0"
)

type Deps struct {
	Config                mcpserve.Config
	Executor              *redisdb.Executor
	Redis                 *redisdb.Config
	Log                   zerolog.Logger
	Audit                 *mcpserve.Auditor
	Middleware            func(http.Handler) http.Handler
	UnauthenticatedRoutes []mcpserve.UnauthenticatedRoute
	Ready                 func(addr string)
}

type Server struct {
	cfg                   mcpserve.Config
	executor              *redisdb.Executor
	connections           []Connection
	limits                Limits
	log                   zerolog.Logger
	audit                 *mcpserve.Auditor
	middleware            func(http.Handler) http.Handler
	unauthenticatedRoutes []mcpserve.UnauthenticatedRoute
	ready                 func(addr string)
}

var (
	ErrNoExecutor    = errors.New("no executor was supplied")
	ErrNoAuditor     = errors.New("no auditor was supplied")
	ErrNoRedisConfig = errors.New("no redis configuration was supplied")
)

func New(deps Deps) (*Server, error) {
	if deps.Executor == nil {
		return nil, fmt.Errorf("redismcp: new server: %w", ErrNoExecutor)
	}
	if deps.Audit == nil {
		return nil, fmt.Errorf("redismcp: new server: %w", ErrNoAuditor)
	}
	if deps.Redis == nil {
		return nil, fmt.Errorf("redismcp: new server: %w", ErrNoRedisConfig)
	}
	if err := deps.Config.Validate(); err != nil {
		return nil, err
	}
	connections := make([]Connection, 0, len(deps.Redis.Aliases))
	for _, spec := range deps.Redis.Aliases {
		connections = append(connections, Connection{Alias: spec.Alias, Database: spec.Database})
	}
	gateLimits := deps.Redis.Settings.GateLimits()
	return &Server{
		cfg:         deps.Config,
		executor:    deps.Executor,
		connections: connections,
		limits: Limits{
			MaxElements:     gateLimits.MaxElements,
			MaxCount:        gateLimits.MaxCount,
			MaxArgs:         gateLimits.MaxArgs,
			MaxArgvBytes:    gateLimits.MaxBytes,
			ReplyByteBudget: deps.Redis.Settings.ReplyByteBudget,
		},
		log:                   deps.Log,
		audit:                 deps.Audit,
		middleware:            deps.Middleware,
		unauthenticatedRoutes: deps.UnauthenticatedRoutes,
		ready:                 deps.Ready,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return s.core().Handler()
}

func (s *Server) Run(ctx context.Context) error {
	return s.core().Run(ctx)
}

func (s *Server) core() *mcpserve.Server {
	return &mcpserve.Server{
		Config:                s.cfg,
		Name:                  ServerName,
		Version:               serverVersion,
		RegisterTools:         s.registerTools,
		Close:                 s.closeExecutor,
		Log:                   s.log,
		Middleware:            s.middleware,
		UnauthenticatedRoutes: s.unauthenticatedRoutes,
		Ready:                 s.ready,
	}
}

func (s *Server) closeExecutor() {
	if err := s.executor.Close(); err != nil {
		s.log.Warn().Err(err).Msg("closing the redis clients reported an error")
		return
	}
	s.log.Info().Msg("redis clients closed")
}
