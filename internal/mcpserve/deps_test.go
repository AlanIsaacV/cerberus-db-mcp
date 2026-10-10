package mcpserve

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
	"context":                     true,
	"errors":                      true,
	"fmt":                         true,
	"io":                          true,
	"net":                         true,
	"net/http":                    true,
	"os":                          true,
	"os/signal":                   true,
	"path":                        true,
	"sort":                        true,
	"strconv":                     true,
	"strings":                     true,
	"sync":                        true,
	"syscall":                     true,
	"time":                        true,
	"github.com/caarlos0/env/v11": true,
	"github.com/modelcontextprotocol/go-sdk/mcp":             true,
	"github.com/rs/zerolog":                                  true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth":    true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/httplog": true,
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse":  true,
}

var forbiddenImportSubstrings = []string{
	"database/sql",
	"sql/driver",
	"go-sql-driver",
	"jackc/pgx",
	"go-mssqldb",
	"os/exec",
}

var forbiddenImports = []string{
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db",
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate",
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcp",
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb",
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate",
}

var requiredSourceFiles = []string{"audit.go", "caller.go", "config.go", "server.go"}

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
