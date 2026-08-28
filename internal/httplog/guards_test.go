package httplog

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
//
// It is enumerated rather than filtered because this package sits on every
// handler's request path at the listener and holds the module's only
// ResponseWriter wrapper. A new dependency should be a line somebody had to
// add in review: this is where a dependency could affect every response, and
// an unnoticed edge could compromise the static linux/arm64 build with
// CGO_ENABLED=0 required by the Raspberry Pi deployment.
var allowedImports = map[string]bool{
	"io":                    true,
	"log":                   true, // adapts net/http's standard-library diagnostics into the application stream
	"net/http":              true,
	"runtime/debug":         true, // captures the stack for recovered panics without recording their potentially sensitive values
	"strings":               true,
	"time":                  true,
	"github.com/rs/zerolog": true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse": true,
}

// forbiddenImportSubstrings names what must never appear here whatever the
// allowlist says. This observability layer sits on every request path, so a
// driver or subprocess dependency here would create a database or command path
// outside the package that owns those boundaries.
var forbiddenImportSubstrings = []string{
	"os/exec",
	"go-sql-driver",
	"jackc/pgx",
	"go-mssqldb",
}

// parsePackageFiles reads the source tree rather than the compiled package: a
// go test overlay must not be able to change what this guard sees.
func parsePackageFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := gotoken.NewFileSet()
	files := make(map[string]*ast.File)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = file
	}
	if len(files) == 0 {
		t.Fatal("no non-test source files were found in .")
	}
	return fset, files
}

// TestPackageImportsNothingItShouldNot is scoped to this package's own
// directory, and stays that way: an import allowlist is a per-package rule.
func TestPackageImportsNothingItShouldNot(t *testing.T) {
	_, files := parsePackageFiles(t)
	for name, file := range files {
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", name, spec.Path.Value, err)
			}
			if !allowedImports[imported] {
				t.Errorf("%s imports %q, which is not on this package's allowed import list", name, imported)
			}
			for _, bad := range forbiddenImportSubstrings {
				if strings.Contains(imported, bad) {
					t.Errorf("%s imports %q: every request-path dependency must stay outside database drivers and subprocesses", name, imported)
				}
			}
		}
	}
}
