package db

import (
	"slices"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// These two accessors reach inside an [Executor] and exist only for tests, so
// they live in a test file: the production binary does not carry them, and no
// non-test call site can grow up around them.

// connFor returns one alias's pool. It exists for the integration tests, which
// have to reach past [Executor.Execute] to test the containment layer on its own:
// with the gate in the way, no write ever reaches a transaction, and the
// rollback is then untested rather than proven.
func (e *Executor) connFor(alias string) (conn, bool) {
	c, ok := e.conns[alias]
	return c, ok
}

// engineAliases lists the aliases configured for one engine, for tests that are
// specific to a dialect.
func (e *Executor) engineAliases(engine gate.Engine) []string {
	var out []string
	for _, name := range e.order {
		if e.conns[name].spec().Engine == engine {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
