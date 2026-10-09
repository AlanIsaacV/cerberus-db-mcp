package redisdb

import (
	"go/parser"
	gotoken "go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var allowedImports = map[string]bool{
	"context":                      true,
	"crypto/tls":                   true,
	"errors":                       true,
	"fmt":                          true,
	"net":                          true,
	"os":                           true,
	"reflect":                      true,
	"slices":                       true,
	"strconv":                      true,
	"strings":                      true,
	"time":                         true,
	"unicode":                      true,
	"github.com/caarlos0/env/v11":  true,
	"github.com/redis/go-redis/v9": true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate": true,
}

var forbiddenImportSubstrings = []string{
	"modelcontextprotocol",
	"net/http",
	"database/sql",
	"go-sql-driver",
	"jackc/pgx",
	"go-mssqldb",
}

var forbiddenImports = []string{
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db",
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate",
}

var requiredSourceFiles = []string{"config.go", "errors.go", "redisdb.go", "reply.go"}

func TestPackageImportsNothingItShouldNot(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	for _, want := range requiredSourceFiles {
		if !slices.Contains(names, want) {
			t.Fatalf("%s was not found among the package's non-test sources %v", want, names)
		}
	}

	fset := gotoken.NewFileSet()
	for _, name := range names {
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
			for _, bad := range forbiddenImports {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports %q", name, path)
				}
			}
		}
	}
}
