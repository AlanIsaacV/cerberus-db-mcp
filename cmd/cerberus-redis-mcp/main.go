package main

import (
	"context"
	"os"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/authflow"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redismcp"
)

func main() {
	log := mcpserve.NewLogger(os.Stdout)

	if err := run(log); err != nil {
		log.Error().Err(err).Msg("cerberus-redis-mcp is exiting on an error")
		os.Exit(1)
	}
}

func unauthenticated(routes []authflow.Route) []mcpserve.UnauthenticatedRoute {
	out := make([]mcpserve.UnauthenticatedRoute, 0, len(routes))
	for _, route := range routes {
		out = append(out, mcpserve.UnauthenticatedRoute{Pattern: route.Pattern, Handler: route.Handler})
	}
	return out
}

func run(log zerolog.Logger) error {
	cfg, err := mcpserve.LoadConfig()
	if err != nil {
		return err
	}
	log = log.Level(cfg.LogLevel)

	authCfg, err := auth.LoadConfig()
	if err != nil {
		return err
	}
	flowCfg, err := authflow.LoadConfig()
	if err != nil {
		return err
	}
	flow, err := authflow.New(*flowCfg, *authCfg, cfg.Path, log)
	if err != nil {
		return err
	}
	middleware, err := auth.NewMiddleware(*authCfg, flowCfg.PublicBaseURL, log)
	if err != nil {
		return err
	}

	log.Info().
		Str("google_client_id", authCfg.ClientID).
		Strs("allowed_identities", authCfg.AllowedEmails).
		Strs("allowed_identities_normalised", authCfg.Allowlist()).
		Msg("callers must present a Google credential this client issued, held by an allowlisted identity")

	redisCfg, err := redisdb.LoadConfig()
	if err != nil {
		return err
	}
	g, err := redisgate.New(redisCfg.Settings.GateLimits())
	if err != nil {
		return err
	}
	executor, err := redisdb.New(g, redisCfg)
	if err != nil {
		return err
	}

	srv, err := redismcp.New(redismcp.Deps{
		Config:                *cfg,
		Executor:              executor,
		Redis:                 redisCfg,
		Log:                   log,
		Audit:                 mcpserve.NewAuditor(os.Stdout),
		Middleware:            middleware,
		UnauthenticatedRoutes: unauthenticated(flow.Routes()),
	})
	if err != nil {
		_ = executor.Close()
		return err
	}

	return srv.Run(context.Background())
}
