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
// Authentication is deliberately absent. [Deps.Middleware] is the seam it will
// arrive through and its default is a no-op, and because there is nothing
// guarding the endpoint in this objective the listener binds to loopback unless
// an operator changes one variable on purpose — see [Config.Address].
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
)

// serverName and serverVersion identify this implementation in the MCP
// handshake.
const (
	serverName    = "cerberus-db-mcp"
	serverVersion = "0.1.0"
)

// readHeaderTimeout bounds how long a client may take to send its request
// headers. It is a constant rather than a variable because there is no
// deployment of this process for which a slow header is legitimate, and the one
// thing it prevents — a connection held open sending nothing — costs the same
// whether or not anybody configured it.
const readHeaderTimeout = 10 * time.Second

// NewLogger builds the application logger.
//
// It exists so that the two streams this process writes have the same shape by
// construction: JSON, one object per line, timestamped. The alternative is the
// binary's main assembling one by hand, which makes the shape of the operator's
// log a property of a file that is otherwise supposed to decide nothing.
func NewLogger(w io.Writer) zerolog.Logger {
	return zerolog.New(w).With().Timestamp().Logger()
}

// Deps is everything the server needs and nothing it can build for itself.
type Deps struct {
	Config Config
	// Executor is the database layer. [Server.Run] closes it on the way out; a
	// caller that only builds a [Server.Handler] keeps that responsibility.
	Executor *db.Executor
	// Log is the application log: startup, shutdown, and the operator-facing side
	// of every failure. It is not the audit stream — see [Auditor].
	Log zerolog.Logger
	// Audit is where one event per tool call goes. It is required: a server that
	// could serve calls without recording them would make the audit stream's
	// completeness depend on a caller remembering to supply a writer.
	Audit *Auditor
	// Middleware is the authentication seam.
	//
	// It is a plain http.Handler decorator because that is the shape the next
	// objective's bearer-token validator already has, and because a seam with no
	// type of its own cannot acquire assumptions about tokens before there is a
	// validator to have them. Nil means no wrapping, which for this objective is
	// the only behaviour there is.
	Middleware func(http.Handler) http.Handler
	// Ready, when non-nil, is called once with the address the listener actually
	// bound. It exists because "127.0.0.1:0" is the only way to run this server in
	// a test without choosing a port that might be in use, and the resolved port
	// is not knowable from the configuration.
	Ready func(addr string)
}

// Server is the MCP transport over one executor.
type Server struct {
	cfg        Config
	executor   *db.Executor
	log        zerolog.Logger
	audit      *Auditor
	middleware func(http.Handler) http.Handler
	ready      func(addr string)
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
		cfg:        deps.Config,
		executor:   deps.Executor,
		log:        deps.Log,
		audit:      deps.Audit,
		middleware: deps.Middleware,
		ready:      deps.Ready,
	}, nil
}

// Handler builds the mux with the MCP endpoint mounted at the configured path,
// wrapped in the authentication seam.
//
// It is exported so that the whole transport can be exercised through
// httptest.NewServer by a real MCP client, which is the only way to test that
// what this package registers is what a client actually sees.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(s.cfg.Path, s.middlewareOrPassThrough()(s.mcpHandler()))
	return mux
}

func (s *Server) middlewareOrPassThrough() func(http.Handler) http.Handler {
	if s.middleware == nil {
		return func(h http.Handler) http.Handler { return h }
	}
	return s.middleware
}

func (s *Server) mcpHandler() http.Handler {
	srv := sdk.NewServer(&sdk.Implementation{Name: serverName, Version: serverVersion}, nil)
	s.registerTools(srv)
	// The same SDK server answers every request, and there is no session behind
	// it. Stateless means the SDK gives each request a temporary session with
	// default initialisation parameters,
	// ignores Mcp-Session-Id and answers GET and DELETE with 405 — behaviour that
	// changed in the SDK's v1.7.0 and is accepted here rather than restored
	// through its compatibility flag. Nothing this server does spans two calls:
	// there is no cursor, no cached result and no per-client state, so a session
	// would be a thing to expire rather than a thing to use, and its absence is
	// what lets more than one replica sit behind one tunnel later.
	return sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return srv },
		&sdk.StreamableHTTPOptions{Stateless: true},
	)
}

// Run listens, serves, and shuts down on SIGINT, SIGTERM or a cancelled ctx.
//
// It owns the process's whole lifetime on purpose, so that the binary's main can
// be a shell that builds dependencies and calls this: the ordering below — stop
// accepting, drain within a bound, then close the pools — is a property worth
// testing, and it cannot be tested where it cannot be reached.
//
// The executor is closed here, last. That order matters because closing pools
// first would fail the in-flight queries this shutdown is waiting to drain, and
// because internal/db's Close leaves its registry populated: a query that
// arrives after it reaches a closed pool and is reported as
// database-unavailable, which is the honest answer from a process that is
// stopping, rather than a panic.
func (s *Server) Run(ctx context.Context) error {
	// Registered before the listener binds, so that a signal arriving in the
	// window between "the port is open" and "we are watching for signals" cannot
	// kill the process with the default disposition.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The executor is this function's from here on, and this is what makes that
	// unconditional: every return path below closes the pools, and a deferred
	// close is the only version of that which cannot be skipped by a branch
	// somebody adds later. It runs after the HTTP shutdown below has returned,
	// which is the order that lets in-flight queries finish.
	defer func() {
		s.executor.Close()
		s.log.Info().Msg("database pools closed")
	}()

	listener, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		// The address is the operator's own value and is named back to them; there
		// is nothing else in this error.
		return fmt.Errorf("mcp: listen on %s: %w", s.cfg.Address, err)
	}

	addr := listener.Addr().String()
	if !s.cfg.IsLoopback() {
		// A warning rather than a refusal: the deployment objective puts an
		// authenticating middleware and a tunnel in front of this process, and a
		// server that refused to bind anything but loopback would have to be
		// changed to be deployed. What must not happen is that it goes unnoticed.
		s.log.Warn().
			Str("address", addr).
			Msg("the listener is not on a loopback address; this process performs no authentication of its own, so anything that can reach this address can read every configured database")
	}
	s.log.Info().Str("address", addr).Str("path", s.cfg.Path).Msg("serving MCP over streamable HTTP")
	if s.ready != nil {
		s.ready(addr)
	}

	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		// Serve stopped on its own, which is a failure rather than a shutdown.
		if err != nil {
			return fmt.Errorf("mcp: serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	s.log.Info().Dur("timeout_ms", s.cfg.ShutdownTimeout).Msg("shutting down")

	// A context of its own, not derived from ctx: ctx is why we are here, so a
	// shutdown deadline built on top of it would already be cancelled and would
	// drain nothing.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownTimeout)
	defer cancel()

	shutdownErr := httpServer.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		// The bound expired with calls still in flight. It is reported and not
		// retried: this process holds pools against a third party's server, and
		// waiting longer for our own client is not worth holding their sessions.
		s.log.Warn().Err(shutdownErr).Msg("the HTTP server did not drain within its bound; closing anyway")
	}

	// Serve's own error is collected so that a failure racing the shutdown is not
	// lost, but ErrServerClosed — which is what Shutdown makes Serve return — has
	// already been folded into nil above.
	if err := <-serveErr; err != nil {
		return fmt.Errorf("mcp: serve: %w", err)
	}
	if shutdownErr != nil {
		return fmt.Errorf("mcp: shutdown: %w", shutdownErr)
	}
	return nil
}
