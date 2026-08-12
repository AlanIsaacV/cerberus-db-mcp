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
// The process has no authentication of its own in this objective. What stands
// in for it is the loopback default on CERBERUS_MCP_ADDRESS, so nothing in this
// file may resolve, default or substitute a listen address.
package main

import (
	"context"
	"os"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcp"
)

func main() {
	// Built before anything that can fail, so that the first failure already has
	// somewhere to be reported. It goes to stdout because that is where the audit
	// stream goes by default too, and internal/mcp's Auditor tags its records with
	// a "stream" field precisely so the two remain separable when they share a
	// destination.
	log := mcp.NewLogger(os.Stdout)

	if err := run(log); err != nil {
		// Err(err) and nothing else. The errors that arrive here are built to be
		// read by an operator without carrying a credential — internal/db's Secret
		// redacts on every formatting verb, and both configuration loaders name the
		// variable they rejected instead of quoting its value. Reformatting one
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

	auditWriter, closeAudit, err := mcp.OpenAuditWriter(cfg.Audit)
	if err != nil {
		return err
	}
	defer func() {
		// Reported rather than returned: by the time this runs the server has
		// already stopped for its own reason, and losing that reason to a failure
		// closing a file would be trading the interesting error for the dull one.
		if err := closeAudit(); err != nil {
			log.Error().Err(err).Msg("closing the audit destination")
		}
	}()

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
		Audit:    mcp.NewAuditor(auditWriter),
		// Middleware is left nil, which internal/mcp reads as no wrapping. The
		// authentication objective fills this field and changes nothing else here.
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
