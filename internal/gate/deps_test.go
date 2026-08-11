package gate

import (
	"go/parser"
	gotoken "go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the whole of what the gate's non-test files may import. The
// package's value is that its verdict depends on nothing but its input, so the
// list is enumerated rather than filtered: a new entry has to be argued for in
// review instead of slipping in behind a transitive dependency.
//
// "time" is absent on purpose even though os pulls it in transitively — the gate
// itself must not read a clock, so no source file of its own may name it.
var allowedImports = map[string]bool{
	"bytes":         true,
	"embed":         true,
	"encoding/json": true,
	"errors":        true,
	"fmt":           true,
	"os":            true, // reading the ruleset overlay, and nothing else
	"slices":        true,
	"strings":       true,
	"sync":          true,
	"sync/atomic":   true,
}

// forbiddenSubstrings names what must never appear anywhere in the closure, in
// the terms the acceptance criterion uses. The corresponding whole-closure check
// is `go list -deps ./internal/gate`, which the CI workflow runs.
var forbiddenSubstrings = []string{"net", "database/sql", "driver", "mcp", "time", "os/exec", "crypto/tls"}

func TestPackageImportsNothingItShouldNot(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := gotoken.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
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
				t.Fatalf("%s imports %q, which is not on the gate's allowed import list", name, path)
			}
			for _, bad := range forbiddenSubstrings {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Fatalf("%s imports %q", name, path)
				}
			}
			if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
				t.Fatalf("%s imports %q, which is not a standard library package", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("no non-test source files were checked")
	}
}
