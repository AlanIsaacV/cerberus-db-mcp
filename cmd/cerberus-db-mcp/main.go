// Command cerberus-db-mcp serves this repository's gated, read-only database
// executor to an AI agent over the Model Context Protocol.
//
// It is a shell, deliberately. Every decision this process makes lives in a
// package that can be tested without a process: internal/gate decides whether a
// statement is a read, internal/db owns the pools and the bounds every
// execution runs under, and internal/mcp owns the transport and — in
// [mcp.Server.Run] — the whole lifetime, down to the signals, the drain and the
// order in which the pools are closed. What is left here is the wiring, and
// wiring is the one thing a main can hold without putting a guarantee somewhere
// no test can reach.
//
// Authentication is internal/auth's, and this file is only its wiring: it loads
// that package's configuration, asks it for the one decorator it hands out, and
// assigns it into internal/mcp's seam. Nothing here reads anything a client
// presented — internal/auth's guards_test.go scans this directory to keep that
// so, and it fails on a variable here merely named after a credential. The
// loopback default on CERBERUS_MCP_ADDRESS is the outer half of the same
// boundary, so nothing in this file may resolve, default or substitute a listen
// address.
package main

import (
	"context"
	"os"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcp"
)

func main() {
	// Built before anything that can fail, so that the first failure already has
	// somewhere to be reported. It goes to stdout, as does the audit stream;
	// internal/mcp's Auditor tags its records with a "stream" field so the two
	// remain separable when they share a destination.
	log := mcp.NewLogger(os.Stdout)

	if err := run(log); err != nil {
		// Err(err) and nothing else. The errors that arrive here are built to be
		// read by an operator without carrying a credential — internal/db's Secret
		// redacts on every formatting verb, and all three configuration loaders name
		// the variable they rejected instead of quoting its value. Reformatting one
		// here, with %+v or by assembling a message out of its parts, is the way
		// that discipline gets defeated from outside the package that keeps it.
		log.Error().Err(err).Msg("cerberus-db-mcp is exiting on an error")
		os.Exit(1)
	}
}

// run builds the dependencies and hands the process to the server.
//
// The order is a startup order: everything that can be refused is refused before
// anything listens, and the last statement is the only one that blocks.
func run(log zerolog.Logger) error {
	cfg, err := mcp.LoadConfig()
	if err != nil {
		return err
	}

	// Beside the server's own configuration, and before the audit destination is
	// opened, because the three variables read here are the ones whose absence would
	// otherwise start a server that works: internal/mcp reads a nil Middleware as
	// no wrapping — which is what keeps every test that builds a Server without one
	// working — so this call is the whole of what stands between an unset variable
	// and a database reader that admits whoever reaches the listener. Refusing here
	// also means a deployment that was never going to be authenticated leaves no
	// audit file behind as evidence that it started.
	//
	// It is early for the reason db.Open's comment below draws the line on: what the
	// environment settles is settled before anything binds, and what depends on
	// somebody else being reachable is not. Nothing here asks Google anything, so
	// whether Tokeninfo is up has no say in whether this process starts.
	authCfg, err := auth.LoadConfig()
	if err != nil {
		return err
	}

	middleware, err := auth.NewMiddleware(*authCfg, log)
	if err != nil {
		return err
	}

	// Unredacted, and the argument for it: a client ID is a public identifier. This
	// process also holds a sealing master secret, but that value is deliberately
	// absent from this record; it is sensitive whereas a client ID is not. Checking
	// somebody else's credential needs no Google client secret, and a client ID
	// differing from the one the agent was configured with answers 401 to every
	// request and produces no other symptom — so both values side by side in a deploy
	// log turn an afternoon into a minute.
	// The allowlist is beside it twice, and the pair is the point. The raw entries are
	// what reads against the variable an operator set; the normalised ones are what a
	// request is actually compared with, so the trailing comma that admits nobody and
	// the stray space that would have been trimmed are visible as a difference between
	// two lists rather than inferred from a count. An email an identity provider
	// vouched for is not a credential, which is why internal/auth logs one on every
	// refusal too.
	log.Info().
		Str("google_client_id", authCfg.ClientID).
		Strs("allowed_identities", authCfg.AllowedEmails).
		Strs("allowed_identities_normalised", authCfg.Allowlist()).
		Msg("callers must present a Google credential this client issued, held by an allowlisted identity")

	// The empty overlay path is the embedded baseline ruleset and nothing else.
	// An overlay can remove a baseline rule and add a safe-function allowance, so
	// it is an input capable of weakening this process — the argument internal/db
	// makes about connection parameters in config.go:74-79 — and no variable in
	// this objective supplies a path, so the binary cannot load one by accident.
	g, err := gate.New("")
	if err != nil {
		return err
	}

	// Opens no connection and pings nothing: reachability is not a configuration
	// property here, so a downed VPN or a bad password surfaces on the first query
	// instead of stopping the process from starting. What does fail here is
	// configuration — a malformed alias, and the three foreign driver variables
	// internal/db refuses to start beside — and it fails before anything binds.
	executor, err := db.Open(g)
	if err != nil {
		return err
	}

	srv, err := mcp.New(mcp.Deps{
		Config:   *cfg,
		Executor: executor,
		Log:      log,
		Audit:    mcp.NewAuditor(os.Stdout),
		// Wraps the MCP endpoint only, which is internal/mcp's own arrangement and
		// not something this file chooses.
		Middleware: middleware,
	})
	if err != nil {
		// The executor is not closed on this path and does not need to be: nothing
		// above it has dialled anything, so there is no session held against
		// somebody else's server, and the process is one return from exiting. Past
		// this point Run owns the executor and closes it after the drain.
		return err
	}

	// Run installs the signal handlers itself, so a plain Background context is
	// what it wants: a context this file cancelled would be a second, competing
	// shutdown path over the one that is tested.
	return srv.Run(context.Background())
}
