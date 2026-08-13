package mcp

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This file holds the assertions that are about the source rather than about a
// run. Three of this objective's guarantees are absolute — no grant is ever
// supplied, no listen address but loopback is ever defaulted to, no dependency
// arrives here unnoticed — and an absolute claim is one no behavioural test can
// establish, because passing a hundred cases says nothing about the hundred and
// first. internal/db and internal/gate make the same argument in their own
// deps_test.go, and this is the same check for the same reason.
//
// Two of the three are claims about the objective and not about this package, so
// they are scanned over cmd/cerberus-db-mcp as well: "no code path in this
// objective can supply a gate.Grant" and "there is no other listen-address
// default" are both false the moment the binary's main acquires one, and the
// next objective edits that file to inject the authentication middleware.

// cmdDir is the rest of this objective's non-test source, relative to this
// package's directory — which is where `go test` runs a package's tests, and is
// the only path base available to a test.
const cmdDir = "../../cmd/cerberus-db-mcp"

// requiredSources are files the whole-objective scans must actually have
// parsed, named rather than counted.
//
// A scan that resolves zero files passes every assertion it makes, which is the
// failure mode that matters for a guard: it reports success for having looked at
// nothing. Naming the files means a moved or renamed directory fails loudly and
// says which path it looked in, instead of quietly narrowing what is guarded.
var requiredSources = []string{
	"config.go",
	"server.go",
	"tools.go",
	path.Join(cmdDir, "main.go"),
}

// allowedImports is the whole of what this package's non-test files may import.
//
// It is enumerated rather than filtered because this is the boundary package:
// everything the agent can reach, and everything this process exposes to a
// network, passes through here. A new dependency should be a line somebody had
// to add in review — the deployment target is a Raspberry Pi 4B with 2 GB of RAM
// running six other services, and the binary must stay a static linux/arm64
// build with CGO_ENABLED=0, neither of which survives an unnoticed edge.
var allowedImports = map[string]bool{
	"context":                     true,
	"database/sql/driver":         true, // for the Valuer a decimal arrives as
	"encoding/base64":             true,
	"errors":                      true,
	"fmt":                         true,
	"io":                          true,
	"math":                        true,
	"net":                         true,
	"net/http":                    true,
	"os":                          true,
	"os/signal":                   true,
	"reflect":                     true,
	"strconv":                     true,
	"strings":                     true,
	"sync":                        true, // for the lock that keeps one audit record one line
	"syscall":                     true,
	"time":                        true,
	"github.com/caarlos0/env/v11": true,
	"github.com/modelcontextprotocol/go-sdk/mcp": true,
	"github.com/rs/zerolog":                      true,
	// internal/auth is read from, never configured from: this package uses its
	// Identity and the context accessor that carries one to a tool handler, so that
	// an audit record can name its caller. Everything about proving who a caller is
	// — the token, the Tokeninfo request, the allowlist — stays behind the
	// func(http.Handler) http.Handler seam in [Deps.Middleware], and this package
	// learning any of it would move a credential into the boundary package.
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth": true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db":   true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate": true,
}

// forbiddenImportSubstrings names what must never appear here whatever the
// allowlist says. A database driver imported from this package would mean a
// query path that does not go through internal/db, and therefore one that skips
// the gate, the row cap and the rolled-back transaction.
var forbiddenImportSubstrings = []string{
	"go-sql-driver",
	"jackc/pgx",
	"go-mssqldb",
	"os/exec",
}

func nonTestFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// path.Join(".", x) is x, so this package's own files keep their bare
		// names and every message about them reads as it did.
		out = append(out, path.Join(dir, name))
	}
	if len(out) == 0 {
		t.Fatalf("no non-test source files were found in %s", dir)
	}
	return out
}

func parseFiles(t *testing.T, dirs ...string) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := gotoken.NewFileSet()
	files := make(map[string]*ast.File)
	for _, dir := range dirs {
		for _, name := range nonTestFiles(t, dir) {
			f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			files[name] = f
		}
	}
	return fset, files
}

// parsePackageFiles is the scan for the rules that are this package's own.
func parsePackageFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	return parseFiles(t, ".")
}

// parseObjectiveFiles is the scan for the rules that are the objective's:
// everything in internal/mcp plus everything in cmd/cerberus-db-mcp, checked
// against [requiredSources] so that a scan which found nothing fails here rather
// than passing downstream.
func parseObjectiveFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	fset, files := parseFiles(t, ".", cmdDir)
	scanned := make([]string, 0, len(files))
	for name := range files {
		scanned = append(scanned, name)
	}
	slices.Sort(scanned)
	for _, want := range requiredSources {
		if _, ok := files[want]; !ok {
			t.Fatalf("the source scan did not reach %s; it found %v. This guard covers the whole objective, and a scan that misses a directory asserts nothing about it",
				want, scanned)
		}
	}
	t.Logf("scanned %d files: %v", len(scanned), scanned)
	return fset, files
}

// TestPackageImportsNothingItShouldNot is scoped to this package's own
// directory, and stays that way.
//
// An import allowlist is a per-package rule: cmd/cerberus-db-mcp legitimately
// imports internal/db and internal/gate directly, which this package's list
// permits, but it would also be the natural place for a future dependency that
// has no business here — so folding one list over both directories would either
// license imports here or forbid them there. What does extend to cmd/ are the
// two absolute claims below, which are about the objective rather than about a
// package's dependency surface.
func TestPackageImportsNothingItShouldNot(t *testing.T) {
	_, files := parsePackageFiles(t)
	for name, f := range files {
		for _, spec := range f.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", name, spec.Path.Value, err)
			}
			if !allowedImports[path] {
				t.Errorf("%s imports %q, which is not on this package's allowed import list", name, path)
			}
			for _, bad := range forbiddenImportSubstrings {
				if strings.Contains(path, bad) {
					t.Errorf("%s imports %q: every query must go through internal/db", name, path)
				}
			}
		}
	}
}

// TestExecuteIsCalledOnceWithNoGrants is acceptance criterion 4's second half.
//
// The gate's escalation exists so that what it cannot classify can be sent to a
// human, and a Grant is that human's answer. This objective supplies none: there
// is no configuration that produces one, no tool argument that accepts one, and
// exactly one call to Execute in the whole layer, with a literal nil where the
// grants go. Asserting it here rather than in a behavioural test is the point —
// a test that calls the tools can only show that the grants were empty on the
// paths it happened to take.
//
// The scan is the objective's and not this package's: a main that reached the
// executor directly would supply grants from outside anything this package can
// see.
func TestExecuteIsCalledOnceWithNoGrants(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	calls := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Execute" {
				return true
			}
			calls++
			line := fset.Position(call.Pos()).Line
			if len(call.Args) != 4 {
				t.Errorf("%s:%d calls Execute with %d arguments; the fourth is the grant slice", name, line, len(call.Args))
				return true
			}
			ident, ok := call.Args[3].(*ast.Ident)
			if !ok || ident.Name != "nil" {
				t.Errorf("%s:%d passes something other than a literal nil as Execute's grants", name, line)
			}
			return true
		})
	}
	if calls != 1 {
		t.Errorf("found %d calls to Execute in this objective, want exactly 1", calls)
	}
}

// TestNoGrantIsNamedAnywhereInThisLayer closes the other routes to the same
// thing: a grant built from configuration, a grant carried on a tool's input, a
// helper that assembles one for a caller to pass. None of them exists in either
// directory of this objective, and none can appear without this failing.
func TestNoGrantIsNamedAnywhereInThisLayer(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if strings.Contains(id.Name, "Grant") {
				t.Errorf("%s:%d names %s; nothing in this objective may construct, hold or accept a gate.Grant",
					name, fset.Position(id.Pos()).Line, id.Name)
			}
			return true
		})
	}
}

// TestListDatabasesIsOneCallThroughTheExecutorAndNothingElse is the source half of
// "list_databases runs its statement through the same gate as execute_query".
//
// The gate is not something this layer consults for that tool: it is inside
// [db.Executor.ListDatabases], which resolves the alias, validates its own
// per-engine constant and only then borrows the connection. What this layer can get
// wrong is having a second route — a copy of the statement handed to Execute, a
// pattern appended to it, a second call somewhere that skips the audit line — and
// each of those is one more call to this method than there should be. One call, two
// arguments, and the second is the alias.
//
// It is scanned over the objective rather than this package, for the reason
// TestExecuteIsCalledOnceWithNoGrants is: a main that reached the executor directly
// would run a discovery statement nothing here can see.
func TestListDatabasesIsOneCallThroughTheExecutorAndNothingElse(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	calls := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ListDatabases" {
				return true
			}
			calls++
			if len(call.Args) != 2 {
				t.Errorf("%s:%d calls ListDatabases with %d arguments; it takes a context and an alias, and nothing that could change the statement",
					name, fset.Position(call.Pos()).Line, len(call.Args))
			}
			return true
		})
	}
	if calls != 1 {
		t.Errorf("found %d calls to ListDatabases in this objective, want exactly 1", calls)
	}
}

// TestNoSQLIsWrittenAnywhereInThisLayer is acceptance criterion 10's "no exemption
// added anywhere", for the part of the repository this layer owns.
//
// Every statement this process sends is one of exactly two things: the agent's own
// text, which the gate sees, or one of internal/db's per-engine discovery
// constants, which the gate also sees. A statement written here would be a third
// kind — one this layer could hand to a driver, or hand to Execute alongside an
// alias the agent did not name, without any rule having allowed it. There is no such
// statement, and there is no way to add one without this failing.
//
// The check is on string literals, so the Go keyword `select` and the word
// "selects" in a comment are not candidates. Struct tags are literals too, and the
// jsonschema descriptions in tools.go are what a widening of this list would trip
// over first — which is the correct outcome: a tool description is not the place a
// statement is kept either.
func TestNoSQLIsWrittenAnywhereInThisLayer(t *testing.T) {
	// Fragments no string in this layer has a reason to contain. The three
	// engine-specific ones are the discovery statements' own spellings, which is
	// where a copy would most plausibly come from.
	sqlSpellings := []string{"select ", "show databases", "pg_database", "sys.databases", "information_schema"}

	fset, files := parseObjectiveFiles(t)
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			lowered := strings.ToLower(value)
			for _, spelling := range sqlSpellings {
				if strings.Contains(lowered, spelling) {
					t.Errorf("%s:%d contains %q; no SQL statement may be written in this layer, because a statement kept here is one this process could send without the gate having allowed it",
						name, fset.Position(lit.Pos()).Line, spelling)
				}
			}
			return true
		})
	}
}

// TestNoOtherListenAddressDefaultExists is acceptance criterion 9's source half.
//
// The loader test shows that the default resolves to loopback today. This shows
// there is nowhere else it could come from: no fallback assignment for an empty
// value, no every-interface spelling written down anywhere. The two together are
// what make "reaching 0.0.0.0 requires a deliberate change" a claim about the
// code rather than about one code path.
//
// "Nowhere else" includes the binary's main, which is where a resolved address,
// a fallback for an empty variable or a flag would most naturally be written.
func TestNoOtherListenAddressDefaultExists(t *testing.T) {
	fset, files := parseObjectiveFiles(t)

	// Every spelling of "every interface" that net.Listen accepts.
	everyInterface := []string{"0.0.0.0", "[::]", "::"}
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			// Struct tags are string literals too, which is what puts the one real
			// default in reach of this walk.
			if strings.Contains(value, "envDefault:") {
				return true
			}
			for _, spelling := range everyInterface {
				if strings.Contains(value, spelling) {
					t.Errorf("%s:%d contains %q; this process has no authentication and must not name an every-interface address anywhere",
						name, fset.Position(lit.Pos()).Line, spelling)
				}
			}
			return true
		})
	}

	// And the one default there is, read off the struct tag rather than off a
	// loaded value, so that a change to the tag fails here even if some other
	// default happened to compensate for it.
	field, ok := reflect.TypeFor[Config]().FieldByName("Address")
	if !ok {
		t.Fatal("Config has no Address field")
	}
	if got := field.Tag.Get("envDefault"); got != "127.0.0.1:8080" {
		t.Errorf("Config.Address envDefault = %q, want a loopback address", got)
	}
}
