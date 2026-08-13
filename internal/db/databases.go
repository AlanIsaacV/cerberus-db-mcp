package db

import (
	"slices"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// DatabaseList is what [Executor.ListDatabases] returns. It is [Result] with the
// answer in place of columns and rows, so that a caller writes the same audit line
// for both calls without learning a second shape.
type DatabaseList struct {
	Alias  string
	Engine gate.Engine
	// Decision is the gate's Allow for the discovery statement, carried for the
	// same reason [Result] carries one: an audit line that cannot say why a
	// statement was permitted is an audit line that assumes it.
	Decision gate.Decision
	// Databases are the names this login can see, with the engine's own system
	// databases removed, in the order the engine returned them.
	Databases []string
	// Truncated reports that the row cap stopped the read. It is a fact about the
	// rows the statement returned and not about the names left after the exclusion
	// list ran, so it stays true even when everything the cap cut off would have
	// been excluded anyway.
	Truncated bool
	RowCap    int
	Elapsed   time.Duration
}

// discovery is one engine's answer to "which databases are there": the fixed
// statement, and the names its result never reports.
//
// The statements themselves live in the per-engine files, beside that engine's DSN
// and session setup, because each one is a fact about a dialect and reads as one
// there. This is only the dispatch, and it has the same shape as [openConn]'s for
// the same reason.
type discovery struct {
	statement string
	// exclude are the databases the engine keeps for itself. They are dropped here
	// rather than written into the statement so that each statement stays the
	// shortest text that answers the question, and so that the list stays a list —
	// reviewable against an engine's documentation without reading SQL.
	//
	// The comparison is exact, and therefore case-sensitive. Every name on these
	// lists is spelled in lower case by the engine that creates it, and this
	// package folds case nowhere.
	exclude []string
}

func discoveryFor(engine gate.Engine) (discovery, bool) {
	switch engine {
	case gate.PostgreSQL:
		return discovery{statement: postgresDatabases, exclude: postgresSystemDatabases}, true
	case gate.MySQL:
		return discovery{statement: mysqlDatabases, exclude: mysqlSystemDatabases}, true
	case gate.SQLServer:
		return discovery{statement: sqlServerDatabases, exclude: sqlServerSystemDatabases}, true
	default:
		return discovery{}, false
	}
}

// names turns the discovery statement's rows into database names and drops the
// excluded ones.
func (d discovery) names(rows [][]any) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		// The first column, because all three statements select exactly one and a
		// second one could only arrive from a statement somebody edited.
		name := databaseName(row[0])
		if name == "" || slices.Contains(d.exclude, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// databaseName reads a name out of one cell of a discovery result.
//
// The three drivers do not agree on the Go type of a name column — MySQL hands
// back []byte for every column, and [normalise] has already turned that into a
// string only where the bytes are valid UTF-8 — so both spellings are accepted. A
// value that is neither cannot come from any of the three statements, and it is
// dropped rather than rendered: whatever an arbitrary Go value formats as, it is not
// a database name, and this list is a list an agent will hand back as an alias.
func databaseName(v any) string {
	switch name := v.(type) {
	case string:
		return name
	case []byte:
		return string(name)
	default:
		return ""
	}
}
