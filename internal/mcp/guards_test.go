package mcp

import (
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io"
	"os"
	"path"
	"path/filepath"
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

// repoDir is the repository root relative to this package, where `go test`
// starts this package's tests.
const repoDir = "../.."

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

// requiredWholeModuleSources anchors both whole-module guards' root walks to
// the same set. One readable literal is safer than two byte-identical lists:
// an update cannot leave one absolute claim scanning less of the module, while
// each package remains explicit for review when it is added.
var requiredWholeModuleSources = []string{
	path.Join(repoDir, "cmd/cerberus-db-mcp/main.go"),
	path.Join(repoDir, "internal/auth/config.go"),
	path.Join(repoDir, "internal/authflow/config.go"),
	path.Join(repoDir, "internal/db/config.go"),
	path.Join(repoDir, "internal/gate/engine.go"),
	path.Join(repoDir, "internal/mcp/audit.go"),
	path.Join(repoDir, "internal/refuse/refuse.go"),
	path.Join(repoDir, "tools/reachability/main.go"),
	path.Join(repoDir, "tools/wide-schema/main.go"),
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
	"path":                        true, // the wrapper must decide path canonicity as net/http does, or it turns ServeMux's 307 redirect into a 404
	"reflect":                     true,
	"sort":                        true, // the wrapper must match net/http's sorted-set Allow value byte for byte
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
	// internal/refuse is the shared refusal seam this boundary reaches for the
	// responses its mux writes itself.
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse": true,
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

func parseRepositoryFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	return parseRepositoryFilesAt(t, repoDir)
}

// excludedRepositoryDirectory reports whether entry is a directory excluded from
// module-owned buildable source: any dot-prefixed directory, vendor, or deploy.
// Those directories hold editor metadata, vendored third-party code, or
// deployment assets; parsing them would make the guard depend on those inputs
// and could report third-party code as this repository's violation. The root is never
// excluded, because a relative root such as "../.." has a dotted base name and
// excluding it would prevent the walk from scanning anything.
func excludedRepositoryDirectory(root, name string, entry os.DirEntry) bool {
	return name != root && entry.IsDir() && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "deploy")
}

// parseRepositoryFilesAt is parseRepositoryFiles with its root made explicit so
// a guard demonstration can inspect a real copied tree. The guard reads source
// from disk; an overlay changes what Go compiles, not what this walk parses.
func parseRepositoryFilesAt(t *testing.T, root string) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := gotoken.NewFileSet()
	files := make(map[string]*ast.File)
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if excludedRepositoryDirectory(root, name, entry) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		files[name] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk non-test source under %s: %v", root, err)
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
	requireScanned(t, files, requiredSources)
	return fset, files
}

// requireScanned is the anti-vacuity check every whole-tree scan runs first: a
// scan that resolved no files, or missed a directory, passes every assertion it
// makes by having looked at nothing.
func requireScanned(t *testing.T, files map[string]*ast.File, required []string) {
	t.Helper()
	scanned := make([]string, 0, len(files))
	for name := range files {
		scanned = append(scanned, name)
	}
	slices.Sort(scanned)
	for _, want := range required {
		if _, ok := files[want]; !ok {
			t.Fatalf("the source scan did not reach %s; it found %v. This guard covers the whole objective, and a scan that misses a directory asserts nothing about it",
				want, scanned)
		}
	}
	t.Logf("scanned %d files: %v", len(scanned), scanned)
}

type fatalReporter interface {
	Helper()
	Fatalf(string, ...any)
}

// requirePackageDirectoryAnchors makes the readable anchor literals prove they
// cover every package the root walk found. requireScanned catches a stale named
// file; this catches the opposite failure, where a newly added package has no
// name in the list and the guard would otherwise say nothing about it.
func requirePackageDirectoryAnchors(t fatalReporter, root string, files map[string]*ast.File, anchors []string) {
	t.Helper()
	missing := unanchoredPackageDirectories(t, root, files, anchors)
	if len(missing) != 0 {
		t.Fatalf("the source scan found package directories with no required anchor: %v", missing)
	}
}

func unanchoredPackageDirectories(t fatalReporter, root string, files map[string]*ast.File, anchors []string) []string {
	t.Helper()
	packages := map[string]bool{}
	for name := range files {
		relative, err := filepath.Rel(root, name)
		if err != nil {
			t.Fatalf("make %s relative to %s: %v", name, root, err)
		}
		packages[filepath.Dir(relative)] = true
	}
	anchored := map[string]bool{}
	for _, anchor := range anchors {
		relative, err := filepath.Rel(root, anchor)
		if err != nil {
			t.Fatalf("make anchor %s relative to %s: %v", anchor, root, err)
		}
		anchored[filepath.Dir(relative)] = true
	}
	missing := make([]string, 0)
	for directory := range packages {
		if !anchored[directory] {
			missing = append(missing, directory)
		}
	}
	slices.Sort(missing)
	return missing
}

// packageAnchorFailureRecorder lets the real guard report its failure against a
// copied tree without ending this demonstration test at the first Fatalf.
type packageAnchorFailureRecorder struct {
	message string
}

func (*packageAnchorFailureRecorder) Helper() {}

func (r *packageAnchorFailureRecorder) Fatalf(format string, arguments ...any) {
	r.message = fmt.Sprintf(format, arguments...)
}

func anchorsAt(t *testing.T, root string, anchors []string) []string {
	t.Helper()
	out := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		relative, err := filepath.Rel(repoDir, anchor)
		if err != nil {
			t.Fatalf("make anchor %s relative to %s: %v", anchor, repoDir, err)
		}
		out = append(out, filepath.Join(root, relative))
	}
	return out
}

// copyRepositoryTree copies the source tree on disk for demonstrations that a
// root-walk guard can fail. It shares the walk's exclusions so editor metadata,
// vendor trees and deployment assets cannot make either a copy or the guard
// depend on files this module does not own.
func copyRepositoryTree(t *testing.T, destination string) {
	t.Helper()
	err := filepath.WalkDir(repoDir, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if excludedRepositoryDirectory(repoDir, name, entry) {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(repoDir, name)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		input, err := os.Open(name)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		t.Fatalf("copy repository tree: %v", err)
	}
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

// TestNoSourceSetsZerologGlobalLevel is acceptance criterion 8. The auditor
// owns an independent logger, so a process-wide level would let this application's
// logger configuration suppress audit records without touching the auditor.
func TestNoSourceSetsZerologGlobalLevel(t *testing.T) {
	fset, files := parseRepositoryFiles(t)
	requireScanned(t, files, requiredWholeModuleSources)
	requirePackageDirectoryAnchors(t, repoDir, files, requiredWholeModuleSources)
	for name, f := range files {
		zerologNames := map[string]bool{}
		dotImported := false
		for _, spec := range f.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil || imported != "github.com/rs/zerolog" {
				continue
			}
			if spec.Name == nil {
				zerologNames["zerolog"] = true
				continue
			}
			switch spec.Name.Name {
			case ".":
				dotImported = true
			case "_":
			default:
				zerologNames[spec.Name.Name] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "SetGlobalLevel" {
				if ident, ok := selector.X.(*ast.Ident); ok && zerologNames[ident.Name] {
					t.Errorf("%s:%d calls zerolog.SetGlobalLevel; the audit logger must remain outside application level control",
						name, fset.Position(call.Pos()).Line)
				}
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && dotImported && ident.Name == "SetGlobalLevel" {
				t.Errorf("%s:%d calls zerolog.SetGlobalLevel; the audit logger must remain outside application level control",
					name, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}
}

type refusalSeamViolation struct {
	Path string
	Line int
	Rule string
}

// refusalSeamViolations finds response writes that bypass the one place which
// logs a refusal before it reaches the client. It is deliberately name-based:
// source guards cannot prove a selector's type without becoming a second type
// checker, and a false positive is answered by naming the file, not by making a
// universal guard quieter.
func refusalSeamViolations(fset *gotoken.FileSet, filePath, exemptPath string, file *ast.File) []refusalSeamViolation {
	if filepath.Clean(filePath) == filepath.Clean(exemptPath) {
		return nil
	}
	violations := []refusalSeamViolation{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		line := fset.Position(call.Pos()).Line
		switch selector.Sel.Name {
		case "Error":
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || receiver.Name != "http" {
				return true
			}
			violations = append(violations, refusalSeamViolation{
				Path: filePath,
				Line: line,
				Rule: "calls http.Error outside the refusal seam",
			})
		case "WriteHeader":
			if len(call.Args) == 1 && allowedResponseStatus(call.Args[0]) {
				return true
			}
			violations = append(violations, refusalSeamViolation{
				Path: filePath,
				Line: line,
				Rule: "writes a status outside the success and redirect allowlist",
			})
		}
		return true
	})
	return violations
}

// allowedResponseStatus keeps only statuses that can complete a normal or
// redirect response outside the refusal seam. Everything else belongs to the
// seam because it must leave the refusal's log line before reaching a client.
func allowedResponseStatus(argument ast.Expr) bool {
	if literal, ok := argument.(*ast.BasicLit); ok && literal.Kind == gotoken.INT {
		status, err := strconv.ParseInt(literal.Value, 0, 64)
		return err == nil && status < 400
	}
	selector, ok := argument.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || receiver.Name != "http" {
		return false
	}
	return map[string]bool{
		"StatusOK":               true,
		"StatusCreated":          true,
		"StatusAccepted":         true,
		"StatusNoContent":        true,
		"StatusFound":            true,
		"StatusSeeOther":         true,
		"StatusMovedPermanently": true,
		"StatusNotModified":      true,
	}[selector.Sel.Name]
}

// TestRefusalSeamPredicate pins the syntactic boundary the root walk enforces.
// These sources are parsed rather than compiled so this exercises exactly what
// a future source file presents to the guard, including selectors the type
// checker cannot resolve in isolation.
func TestRefusalSeamPredicate(t *testing.T) {
	const source = `package candidate
func reply(w interface{}) {
	http.Error(nil, "failed", http.StatusInternalServerError)
	w.WriteHeader(http.StatusInternalServerError)
	w.WriteHeader(500)
	w.WriteHeader(http.StatusNoContent)
	w.WriteHeader(http.StatusOK)
	http.Redirect(nil, nil, "/next", http.StatusFound)
}
`
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "candidate.go", source, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	violations := refusalSeamViolations(fset, "candidate.go", "internal/refuse/refuse.go", file)
	if got, want := len(violations), 3; got != want {
		t.Fatalf("violations = %v, want %d violations", violations, want)
	}
	for index, wantLine := range []int{3, 4, 5} {
		if got := violations[index].Line; got != wantLine {
			t.Errorf("violation %d line = %d, want %d", index, got, wantLine)
		}
	}
	if exempted := refusalSeamViolations(fset, "internal/refuse/refuse.go", "internal/refuse/refuse.go", file); len(exempted) != 0 {
		t.Errorf("exempt seam file violations = %v, want none", exempted)
	}
}

// TestRefusalSeamGuardFindsAnInjectedResponse proves the guard can fail where
// it matters: over a real copy of the tree. An overlay would change compilation
// inputs but not the source files parseRepositoryFilesAt reads from disk.
func TestRefusalSeamGuardFindsAnInjectedResponse(t *testing.T) {
	copy := t.TempDir()
	copyRepositoryTree(t, copy)
	injectedPath := filepath.Join(copy, "internal", "mcp", "config.go")
	original, err := os.ReadFile(injectedPath)
	if err != nil {
		t.Fatalf("read injection target: %v", err)
	}
	injected := string(original) + "\nfunc refusalSeamGuardDemonstration() {\n\thttp.Error(nil, \"injected\", http.StatusInternalServerError)\n}\n"
	if err := os.WriteFile(injectedPath, []byte(injected), 0o644); err != nil {
		t.Fatalf("inject http.Error: %v", err)
	}
	wantLine := strings.Count(injected[:strings.Index(injected, "http.Error")], "\n") + 1
	fset, files := parseRepositoryFilesAt(t, copy)
	requireScanned(t, files, anchorsAt(t, copy, requiredWholeModuleSources))
	requirePackageDirectoryAnchors(t, copy, files, anchorsAt(t, copy, requiredWholeModuleSources))
	var violations []refusalSeamViolation
	for name, file := range files {
		violations = append(violations, refusalSeamViolations(fset, name, filepath.Join(copy, "internal", "refuse", "refuse.go"), file)...)
	}
	for _, violation := range violations {
		if violation.Path == injectedPath && violation.Line == wantLine {
			return
		}
	}
	t.Errorf("injected response %s:%d was not reported; violations = %v", injectedPath, wantLine, violations)
}

// TestPackageAnchorDerivationFindsAnUnanchoredPackage demonstrates the stale
// list failure on a disk copy. The list remains a readable literal; deriving it
// would hide the package a reviewer needs to notice when it is added.
func TestPackageAnchorDerivationFindsAnUnanchoredPackage(t *testing.T) {
	copy := t.TempDir()
	copyRepositoryTree(t, copy)
	packageDirectory := filepath.Join(copy, "internal", "seamguardfixture")
	if err := os.MkdirAll(packageDirectory, 0o755); err != nil {
		t.Fatalf("make unanchored package directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDirectory, "fixture.go"), []byte("package seamguardfixture\n"), 0o644); err != nil {
		t.Fatalf("write unanchored package file: %v", err)
	}
	_, files := parseRepositoryFilesAt(t, copy)
	anchors := anchorsAt(t, copy, requiredWholeModuleSources)
	requireScanned(t, files, anchors)
	reporter := &packageAnchorFailureRecorder{}
	requirePackageDirectoryAnchors(reporter, copy, files, anchors)
	want := filepath.Join("internal", "seamguardfixture")
	if reporter.message == "" {
		t.Fatal("the package-anchor derivation did not fail for the unanchored package")
	}
	if !strings.Contains(reporter.message, want) {
		t.Errorf("package-anchor failure = %q, want it to name %s", reporter.message, want)
	}
}

// TestNoSourceWritesErrorResponseOutsideRefusalSeam is the whole-module claim:
// every repository-owned error response first reaches refuse.Write, which logs
// it. The exemption is the named seam file, not its directory, so another file
// added beside it cannot write a response without this guard seeing it.
func TestNoSourceWritesErrorResponseOutsideRefusalSeam(t *testing.T) {
	fset, files := parseRepositoryFiles(t)
	requireScanned(t, files, requiredWholeModuleSources)
	requirePackageDirectoryAnchors(t, repoDir, files, requiredWholeModuleSources)
	for name, file := range files {
		for _, violation := range refusalSeamViolations(fset, name, path.Join(repoDir, "internal/refuse/refuse.go"), file) {
			t.Errorf("%s:%d %s", violation.Path, violation.Line, violation.Rule)
		}
	}
}
