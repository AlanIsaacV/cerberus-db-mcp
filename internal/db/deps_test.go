package db

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the whole of what this package's non-test files may import.
// It is enumerated rather than filtered for the same reason the gate's list is:
// this package is where credentials, sockets and TLS live, and a new dependency
// here should be a line somebody had to add in review rather than something that
// arrived behind a transitive edge.
var allowedImports = map[string]bool{
	"context":                         true,
	"database/sql":                    true,
	"database/sql/driver":             true,
	"errors":                          true,
	"fmt":                             true,
	"net":                             true,
	"net/url":                         true,
	"os":                              true, // reading the environment, and nothing else
	"slices":                          true,
	"strconv":                         true,
	"strings":                         true,
	"time":                            true,
	"unicode/utf8":                    true,
	"github.com/caarlos0/env/v11":     true,
	"github.com/go-sql-driver/mysql":  true,
	"github.com/jackc/pgx/v5":         true,
	"github.com/jackc/pgx/v5/pgconn":  true,
	"github.com/jackc/pgx/v5/pgxpool": true,
	"github.com/microsoft/go-mssqldb": true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate": true,
}

// forbiddenImportSubstrings names what must never appear, in the terms the
// acceptance criterion uses. This package is deliberately exercisable from
// `go test` with nothing running, and it stays that way only if it never learns
// about a transport.
var forbiddenImportSubstrings = []string{
	"modelcontextprotocol",
	"net/http",
	"net/rpc",
}

func nonTestFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatal("no non-test source files were found")
	}
	return out
}

func TestPackageImportsNothingItShouldNot(t *testing.T) {
	fset := gotoken.NewFileSet()
	for _, name := range nonTestFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
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
					t.Errorf("%s imports %q", name, path)
				}
			}
		}
	}
}

// TestPackageContainsNoCommit is the containment guarantee expressed as a
// property of the source rather than of a test run. Every execution here runs
// inside a transaction that is rolled back on every exit path, and the reason
// that is airtight is that there is nothing in the package that could commit one.
// A reviewer can check that claim by reading; this checks it on every build.
func TestPackageContainsNoCommit(t *testing.T) {
	fset := gotoken.NewFileSet()
	for _, name := range nonTestFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "Commit" {
				t.Errorf("%s:%d calls Commit", name, fset.Position(sel.Pos()).Line)
			}
			return true
		})
	}
}

// TestTestOnlyLeversAreTestOnly guards the two levers that exist so that a
// guarantee can be tested rather than assumed: a writable transaction, and a
// MySQL connection without its server-side time bound. Both weaken this layer if
// they are ever used in earnest, and both are unexported, so the only thing
// stopping that is a check like this one.
//
// The declaration of each constant is allowed, in the file that declares it.
// Every other appearance in a non-test file is a failure.
func TestTestOnlyLeversAreTestOnly(t *testing.T) {
	levers := map[string]string{
		"txWritable":   "execute.go",
		"boundOmitted": "mysql.go",
	}
	fset := gotoken.NewFileSet()
	for _, name := range nonTestFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		declared := declaredConstNames(f)
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			home, isLever := levers[id.Name]
			if !isLever || declared[id.Pos()] {
				return true
			}
			line := fset.Position(id.Pos()).Line
			t.Errorf("%s:%d uses %s, which exists only for the test that proves the bound it removes; it is declared in %s and must be named nowhere else outside a test", name, line, id.Name, home)
			return true
		})
	}
}

// declaredConstNames collects the positions of the names a const declaration
// introduces, so that a declaration is not mistaken for a use.
func declaredConstNames(f *ast.File) map[gotoken.Pos]bool {
	out := map[gotoken.Pos]bool{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != gotoken.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				out[name.Pos()] = true
			}
		}
	}
	return out
}
