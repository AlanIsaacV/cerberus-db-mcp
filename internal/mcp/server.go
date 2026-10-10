// Package mcp serves internal/db's executor to an AI agent over the Model
// Context Protocol, on stateless Streamable HTTP.
//
// It is the only place in this process where a value crosses from the database
// layer to something outside it, which makes three things this package's alone
// to keep:
//
//   - What the agent may read. Every error that reaches a tool result goes
//     through [db.Error.Agent], which selects from a fixed allowlist and never
//     consults the engine's own words. Anything arriving here that is not a
//     [db.Error] is a defect in this package and becomes one sentence that says
//     nothing — see [internalFailure]. Nothing in a tool's arguments, its result
//     or its error names a host, a port, a database, a user or a password.
//   - What a driver value becomes. encoding/json's defaults are wrong for
//     database values in ways that are silent, so every value crosses through
//     one converter with a defined form per class — see rows.go.
//   - What was attempted. Every call writes exactly one audit event, including
//     the calls the gate refused, because a log of only what ran cannot answer
//     the question that matters against a database this project does not own.
//
// Authentication is not this package's. [Deps.Middleware] is the seam it arrives
// through, and a server built without one guards its endpoint with nothing, which
// is why the listener binds to loopback unless an operator changes one variable on
// purpose — see [Config.Address].
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
)

// serverName and serverVersion identify this implementation in the MCP
// handshake.
const (
	serverName    = "cerberus-db-mcp"
	serverVersion = "0.1.0"
	healthPath    = mcpserve.HealthPath
	healthBody    = mcpserve.HealthBody

	failureClassRouteNotFound         = mcpserve.FailureClassRouteNotFound
	failureClassMethodNotAllowed      = mcpserve.FailureClassMethodNotAllowed
	failureClassAsteriskRequestTarget = mcpserve.FailureClassAsteriskRequestTarget
)

func NewLogger(w io.Writer) zerolog.Logger {
	return mcpserve.NewLogger(w)
}

// Deps is everything the server needs and nothing it can build for itself.
type Deps struct {
	Config Config
	// Executor is the database layer. [Server.Run] closes it on the way out; a
	// caller that only builds a [Server.Handler] keeps that responsibility.
	Executor *db.Executor
	Gate     *gate.Gate
	// Log is the application log: startup, shutdown, and the operator-facing side
	// of every failure. It is not the audit stream — see [Auditor].
	Log zerolog.Logger
	// Audit is where one event per tool call goes. It is required: a server that
	// could serve calls without recording them would make the audit stream's
	// completeness depend on a caller remembering to supply a writer.
	Audit *Auditor
	// Middleware is the authentication seam.
	//
	// It is a plain http.Handler decorator because that is the shape internal/auth's
	// validator has, and because a seam with no type of its own cannot acquire
	// assumptions about what a caller presents. Nil means no wrapping — which is
	// what keeps every test that builds a Server without one working, and is why
	// refusing to start without authentication is the binary's property rather than
	// this constructor's.
	Middleware func(http.Handler) http.Handler
	// UnauthenticatedRoutes are endpoints whose authentication belongs to a
	// dependency other than this transport. They are mounted beside healthz;
	// the MCP path remains the only endpoint this package decorates.
	UnauthenticatedRoutes []UnauthenticatedRoute
	// Ready, when non-nil, is called once with the address the listener actually
	// bound. It exists because "127.0.0.1:0" is the only way to run this server in
	// a test without choosing a port that might be in use, and the resolved port
	// is not knowable from the configuration.
	Ready func(addr string)
}

type UnauthenticatedRoute = mcpserve.UnauthenticatedRoute

// Server is the MCP transport over one executor.
type Server struct {
	cfg                   Config
	executor              *db.Executor
	gate                  *gate.Gate
	log                   zerolog.Logger
	audit                 *Auditor
	middleware            func(http.Handler) http.Handler
	unauthenticatedRoutes []UnauthenticatedRoute
	ready                 func(addr string)
}

// ErrNoExecutor and ErrNoAuditor report a server built without a dependency
// that has no sensible default. Both are sentinels rather than panics for the
// reason [db.ErrNoGate] is: these are the construction mistakes that would leave
// a guarantee unenforced, and an error at startup is easier to notice in a
// deploy log than a stack trace.
var (
	ErrNoExecutor = errors.New("no executor was supplied")
	ErrNoAuditor  = errors.New("no auditor was supplied")
)

// New builds a server. It validates the configuration it was handed, so a
// [Config] assembled by hand is held to the same rules as one that was loaded.
func New(deps Deps) (*Server, error) {
	if deps.Executor == nil {
		return nil, fmt.Errorf("mcp: new server: %w", ErrNoExecutor)
	}
	if deps.Audit == nil {
		return nil, fmt.Errorf("mcp: new server: %w", ErrNoAuditor)
	}
	if err := deps.Config.validate(); err != nil {
		return nil, err
	}
	return &Server{
		cfg:                   deps.Config,
		executor:              deps.Executor,
		gate:                  deps.Gate,
		log:                   deps.Log,
		audit:                 deps.Audit,
		middleware:            deps.Middleware,
		unauthenticatedRoutes: deps.UnauthenticatedRoutes,
		ready:                 deps.Ready,
	}, nil
}

// Handler builds the mux with the MCP endpoint mounted at the configured path,
// wrapped in the authentication seam.
//
// It is exported so that the whole transport can be exercised through
// httptest.NewServer by a real MCP client, which is the only way to test that
// what this package registers is what a client actually sees.
func (s *Server) Handler() http.Handler {
	return s.core().Handler()
}

func (s *Server) registerRoutes(mux *http.ServeMux) []string {
	return s.core().RegisterRoutes(mux)
}

func (s *Server) warnIfReachableBeyondThisHost(addr string) {
	s.core().WarnIfReachableBeyondThisHost(addr)
}

func (s *Server) core() *mcpserve.Server {
	return &mcpserve.Server{
		Config:                s.cfg.shared(),
		Name:                  serverName,
		Version:               serverVersion,
		RegisterTools:         s.registerTools,
		Close:                 s.closeExecutor,
		Hangup:                s.reloadGate,
		Log:                   s.log,
		Middleware:            s.middleware,
		UnauthenticatedRoutes: s.unauthenticatedRoutes,
		Ready:                 s.ready,
	}
}

func (s *Server) closeExecutor() {
	s.executor.Close()
	s.log.Info().Msg("database pools closed")
}

// Run listens, serves, and shuts down on SIGINT, SIGTERM or a cancelled ctx.
//
// It owns the process's whole lifetime on purpose, so that the binary's main can
// be a shell that builds dependencies and calls this: the ordering in
// [mcpserve.Server.Run] — stop accepting, drain within a bound, then close the
// pools — is a property worth testing, and it cannot be tested where it cannot
// be reached.
//
// The executor is closed here, last. That order matters because closing pools
// first would fail the in-flight queries this shutdown is waiting to drain, and
// because internal/db's Close leaves its registry populated: a query that
// arrives after it reaches a closed pool and is reported as
// database-unavailable, which is the honest answer from a process that is
// stopping, rather than a panic.
func (s *Server) Run(ctx context.Context) error {
	return s.core().Run(ctx)
}
