package redisgate

import (
	"go/build"
	"go/parser"
	gotoken "go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var allowedImports = map[string]bool{
	"errors":  true,
	"strconv": true,
	"strings": true,
}

var forbiddenClosure = []string{"net", "time", "os/exec", "crypto/tls"}

var requiredSourceFiles = []string{"allowlist.go", "catalogue.go", "gate.go", "rules.go"}

func nonTestSources(t *testing.T) []string {
	t.Helper()
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
	return names
}

func TestEachSourceFileImportsOnlyTheAllowedList(t *testing.T) {
	fset := gotoken.NewFileSet()
	for _, name := range nonTestSources(t) {
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
				t.Errorf("%s imports %q, which is not on the redisgate allowed import list", name, path)
			}
		}
	}
}

func TestDependencyClosureIsStandardAndOffline(t *testing.T) {
	ctx := build.Default
	ctx.CgoEnabled = false
	pkg, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("load the package: %v", err)
	}
	for _, want := range requiredSourceFiles {
		if !slices.Contains(pkg.GoFiles, want) {
			t.Fatalf("the build of this directory does not include %s; it compiles %v", want, pkg.GoFiles)
		}
	}
	closure := map[string]bool{}
	var walk func(path, srcDir string)
	walk = func(path, srcDir string) {
		if path == "C" || closure[path] {
			return
		}
		closure[path] = true
		p, err := ctx.Import(path, srcDir, 0)
		if err != nil {
			t.Fatalf("resolve %q: %v", path, err)
		}
		if !p.Goroot {
			t.Errorf("the closure reaches %q, which is not a standard library package", path)
			return
		}
		for _, imp := range p.Imports {
			walk(imp, p.Dir)
		}
	}
	for _, imp := range pkg.Imports {
		walk(imp, pkg.Dir)
	}
	for _, want := range []string{"errors", "strconv", "strings", "runtime"} {
		if !closure[want] {
			t.Fatalf("the closure walk did not reach %q; it resolved %d packages and cannot vouch for the rest", want, len(closure))
		}
	}
	for path := range closure {
		for _, bad := range forbiddenClosure {
			if path == bad || strings.HasPrefix(path, bad+"/") {
				t.Errorf("the closure contains %q", path)
			}
		}
	}
}
