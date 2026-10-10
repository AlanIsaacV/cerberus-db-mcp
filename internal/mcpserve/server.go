package mcpserve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/httplog"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse"
)

const (
	HealthPath = "/healthz"
	HealthBody = "ok\n"

	// ServeMux owns these refusals before a registered handler runs. They
	// need distinct names because an operator investigating a bad path needs a
	// different answer from one investigating a method that an existing path does
	// not accept, or from one investigating an HTTP/1.1 asterisk request target.
	FailureClassRouteNotFound         = "route_not_found"
	FailureClassMethodNotAllowed      = "method_not_allowed"
	FailureClassAsteriskRequestTarget = "asterisk_request_target"
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

// UnauthenticatedRoute is an externally supplied HTTP endpoint mounted without
// the MCP authentication seam. Its meaning belongs to the caller that supplied
// it; this package only owns the transport registration.
type UnauthenticatedRoute struct {
	Pattern string
	Handler http.Handler
}

type Server struct {
	Config                Config
	Name                  string
	Version               string
	RegisterTools         func(*sdk.Server)
	Close                 func()
	Hangup                func()
	Log                   zerolog.Logger
	Middleware            func(http.Handler) http.Handler
	UnauthenticatedRoutes []UnauthenticatedRoute
	Ready                 func(addr string)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	return httplog.WithPanicRecovery(s.withMuxRefusals(mux, s.RegisterRoutes(mux)), s.Log)
}

// RegisterRoutes mounts every endpoint this server serves and returns the
// patterns in registration order so the refusal wrapper can discover the
// methods the mux accepts.
func (s *Server) RegisterRoutes(mux *http.ServeMux) []string {
	patterns := make([]string, 0, len(s.UnauthenticatedRoutes)+2)
	// Health only says that this HTTP server can answer. It deliberately avoids
	// the MCP handler and its middleware, so a probe never authenticates, opens a
	// connection to a data source, or adds an audit event.
	healthPattern := "GET " + HealthPath
	mux.HandleFunc(healthPattern, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, HealthBody)
	})
	patterns = append(patterns, healthPattern)
	for _, route := range s.UnauthenticatedRoutes {
		mux.Handle(route.Pattern, route.Handler)
		patterns = append(patterns, route.Pattern)
	}
	mux.Handle(s.Config.Path, s.middlewareOrPassThrough()(httplog.WithStatusLine(s.mcpHandler(), s.Log)))
	patterns = append(patterns, s.Config.Path)
	return patterns
}

// withMuxRefusals preserves ServeMux's decision for every registered pattern and
// every redirect, and observes only the two canonical-path cases where the mux
// would synthesize a refusal without entering application code. An empty matched
// pattern can also describe a non-canonical clean-path redirect that matched
// nothing, so canonicity is part of that distinction. In particular, it decorates
// the handler rather than the ResponseWriter: the MCP SDK reaches the original
// writer's flusher through a ResponseController, and substituting a writer here
// would silently break streaming unless it declares Unwrap() http.ResponseWriter,
// as internal/httplog does.
func (s *Server) withMuxRefusals(mux *http.ServeMux, patterns []string) http.Handler {
	methods := map[string]struct{}{"HEAD": {}}
	for _, pattern := range patterns {
		if method, _, found := strings.Cut(pattern, " "); found {
			methods[method] = struct{}{}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ServeMux.ServeHTTP owns this HTTP/1.1 request-target special case. Handler
		// does not reach it, so delegation preserves the mux's status and headers.
		if r.RequestURI == "*" {
			refuse.Log(r, s.Log, refuse.Params{
				Level:        zerolog.WarnLevel,
				Status:       http.StatusBadRequest,
				FailureClass: FailureClassAsteriskRequestTarget,
			})
			mux.ServeHTTP(w, r)
			return
		}

		handler, pattern := mux.Handler(r)
		if pattern != "" || (r.Method != http.MethodConnect && r.URL.EscapedPath() != serveMuxCleanPath(r.URL.EscapedPath())) {
			handler.ServeHTTP(w, r)
			return
		}

		allowed := make([]string, 0, len(methods))
		for method := range methods {
			candidate := *r
			candidate.Method = method
			if _, matchedPattern := mux.Handler(&candidate); matchedPattern != "" {
				allowed = append(allowed, method)
			}
		}
		if len(allowed) != 0 {
			sort.Strings(allowed)
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			refuse.Write(w, r, s.Log, refuse.Params{
				Level:        zerolog.WarnLevel,
				Status:       http.StatusMethodNotAllowed,
				OAuth:        false,
				Body:         "Method Not Allowed",
				FailureClass: FailureClassMethodNotAllowed,
			})
			return
		}

		refuse.Write(w, r, s.Log, refuse.Params{
			Level:        zerolog.WarnLevel,
			Status:       http.StatusNotFound,
			OAuth:        false,
			Body:         "404 page not found",
			FailureClass: FailureClassRouteNotFound,
		})
	})
}

// serveMuxCleanPath mirrors net/http's unexported cleanPath behavior. The
// refusal wrapper needs the same canonicalization to distinguish a missing route
// from the mux's own clean-path redirect, because both can have an empty pattern.
func serveMuxCleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root; put it back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

func (s *Server) middlewareOrPassThrough() func(http.Handler) http.Handler {
	if s.Middleware == nil {
		return func(h http.Handler) http.Handler { return h }
	}
	return s.Middleware
}

// WarnIfReachableBeyondThisHost says what binding a non-loopback address means
// for this particular server.
//
// It is a warning rather than a refusal because a server that refused to bind
// anything but loopback would have to be changed to be deployed, and the
// deployment this repository is for puts a tunnel in front of the listener. What
// must not happen is that the exposure goes unnoticed.
//
// The two texts differ because the danger does. With no middleware there is
// nothing between the listener and every configured data source, and that is the
// sentence an operator has to read. With one installed, saying the same thing
// would be false in exactly the situation where an operator most needs the line to
// be accurate — so it says what this package can actually know: the listener is
// reachable beyond this host, and requests are answered by whatever authenticates
// them. Which middleware that is, and what it checks, is not this package's to
// claim: s.Middleware == nil is the whole of what it can see.
//
// It is a method of its own so that both texts can be asserted without a test
// binding a public interface. Run calls it once, immediately after the listener
// binds and before it reports the address.
func (s *Server) WarnIfReachableBeyondThisHost(addr string) {
	if s.Config.IsLoopback() {
		return
	}
	if s.Middleware == nil {
		s.Log.Warn().
			Str("address", addr).
			Msg("the listener is not on a loopback address; this process performs no authentication of its own, so anything that can reach this address can read every configured data source")
		return
	}
	s.Log.Warn().
		Str("address", addr).
		Msg("the listener is not on a loopback address, so it is reachable beyond this host; every request to it is authenticated by the configured middleware")
}

func (s *Server) mcpHandler() http.Handler {
	srv := sdk.NewServer(&sdk.Implementation{Name: s.Name, Version: s.Version}, nil)
	s.RegisterTools(srv)
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

func (s *Server) Run(ctx context.Context) error {
	// Registered before the listener binds, so that a signal arriving in the
	// window between "the port is open" and "we are watching for signals" cannot
	// kill the process with the default disposition.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	defer signal.Stop(hangup)

	// What Close releases is this function's from here on, and this is what makes
	// that unconditional: every return path below calls Close, and a deferred
	// close is the only version of that which cannot be skipped by a branch
	// somebody adds later. It runs after the HTTP shutdown below has returned,
	// which is the order that lets in-flight calls finish.
	defer func() {
		if s.Close != nil {
			s.Close()
		}
	}()

	listener, err := net.Listen("tcp", s.Config.Address)
	if err != nil {
		// The address is the operator's own value and is named back to them; there
		// is nothing else in this error.
		return fmt.Errorf("mcp: listen on %s: %w", s.Config.Address, err)
	}

	addr := listener.Addr().String()
	s.WarnIfReachableBeyondThisHost(addr)
	s.Log.Info().Str("address", addr).Str("path", s.Config.Path).Msg("serving MCP over streamable HTTP")
	if s.Ready != nil {
		s.Ready(addr)
	}

	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          httplog.NewServerErrorLog(s.Log),
	}

	serveErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

serving:
	for {
		select {
		case err := <-serveErr:
			// Serve stopped on its own, which is a failure rather than a shutdown.
			if err != nil {
				return fmt.Errorf("mcp: serve: %w", err)
			}
			return nil
		case <-hangup:
			s.onHangup()
		case <-ctx.Done():
			break serving
		}
	}

	s.Log.Info().Dur("timeout_ms", s.Config.ShutdownTimeout).Msg("shutting down")

	// A context of its own, not derived from ctx: ctx is why we are here, so a
	// shutdown deadline built on top of it would already be cancelled and would
	// drain nothing.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.Config.ShutdownTimeout)
	defer cancel()

	shutdownErr := httpServer.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		// The bound expired with calls still in flight. It is reported and not
		// retried: this process holds connections to a third party's server, and
		// waiting longer for our own client is not worth holding their sessions.
		s.Log.Warn().Err(shutdownErr).Msg("the HTTP server did not drain within its bound; closing anyway")
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

func (s *Server) onHangup() {
	if s.Hangup == nil {
		s.Log.Warn().Msg("SIGHUP received but this server has nothing to reload; it keeps serving")
		return
	}
	s.Hangup()
}
