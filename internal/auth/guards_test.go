package auth

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This file holds the assertions that are about the source rather than about a
// run, following the precedent internal/mcp/guards_test.go and internal/db's
// deps_test.go set. Three of this package's guarantees are absolute — the raw
// token never reaches a logger, no endpoint but Google's over HTTPS is ever named,
// no dependency arrives here unnoticed — and an absolute claim is one no
// behavioural test can establish, because a hundred passing cases say nothing
// about the hundred and first.
//
// The scans that are about the objective rather than about this package cover
// cmd/cerberus-db-mcp too: the binary is where the middleware is wired in, and
// "the token is handled here and nowhere else" is false the moment main learns
// what a token is.

// cmdDir is the binary's source, relative to this package's directory — which is
// where `go test` runs a package's tests, and is the only path base available to a
// test. internal/mcp's own guards resolve it the same way on purpose: a moved or
// renamed directory fails these tests loudly instead of quietly narrowing what is
// guarded.
const cmdDir = "../../cmd/cerberus-db-mcp"

// mcpDir is the transport package, resolved the same way and for the same reason.
//
// It is scanned by the token guard alone. internal/mcp is everything downstream of
// this package's middleware: it is where a request goes after being admitted, and
// it is therefore where somebody debugging a call would reach for the inbound
// headers. It is deliberately not scanned by the endpoint or configuration guards,
// which are about rules that are internal/auth's own.
const mcpDir = "../mcp"

// requiredSources are the files these scans must actually have parsed, named
// rather than counted.
//
// A scan that resolves zero files passes every assertion it makes, which is the
// failure mode that matters for a guard: it reports success for having looked at
// nothing. Naming the files means a rename fails here and says which path it
// looked in — ADR 01KZT76QT9ECEMKYGKXVZ5XPPJ.
var requiredSources = []string{
	"config.go",
	"identity.go",
	"middleware.go",
	sealingFile,
	tokenFile,
	path.Join(cmdDir, "main.go"),
}

// requiredTokenScanSources are the files the token guard must have parsed: the
// ones above, plus the three files in internal/mcp that write somewhere a person
// reads — the transport's own log, the audit stream, and the tool handlers.
var requiredTokenScanSources = append([]string{
	path.Join(mcpDir, "server.go"),
	path.Join(mcpDir, "tools.go"),
	path.Join(mcpDir, "audit.go"),
}, requiredSources...)

// tokenFile is the one file in this repository that holds a raw bearer token. The
// guards below are written in terms of that fact, so the name is a constant: if the
// token handling moves, these scans must be rewritten rather than silently pointed
// at a file that no longer has anything to hide.
const tokenFile = "tokeninfo.go"

// sealingFile holds credentials this process issued. Like [tokenFile], it is a
// deliberately narrow place for credential material and must not import a
// logger or formatter.
const sealingFile = "sealing.go"

// allowedImports is the whole of what this package's non-test files may import.
//
// It is enumerated rather than filtered for the reason internal/mcp's is: this is
// the other boundary package, and everything a client presents to this process
// passes through here before anything else looks at it. A new dependency should be
// a line somebody had to add in review — the deployment target is a Raspberry Pi
// and the binary must stay a static linux/arm64 build with CGO_ENABLED=0, which no
// dependency with a cgo edge survives.
var allowedImports = map[string]bool{
	"container/list":              true, // the LRU, so that a cache needs no dependency
	"context":                     true,
	"crypto/aes":                  true,
	"crypto/cipher":               true,
	"crypto/hkdf":                 true,
	"crypto/rand":                 true,
	"crypto/sha256":               true, // the cache key, and the only lasting form of a token
	"encoding/base64":             true,
	"encoding/hex":                true,
	"encoding/json":               true,
	"errors":                      true,
	"fmt":                         true,
	"io":                          true,
	"net/http":                    true,
	"net/url":                     true,
	"os":                          true,
	"strconv":                     true,
	"strings":                     true,
	"sync":                        true,
	"time":                        true,
	"github.com/caarlos0/env/v11": true,
	"github.com/rs/zerolog":       true,
}

// forbiddenImportSubstrings names what must never appear here whatever the
// allowlist says.
//
// An OAuth library would mean this package could acquire, refresh or store a
// credential, and it acquires none: it validates a credential issued elsewhere
// and holds only the sealing master secret, which it never acquires from a third
// party. The MCP SDK would mean it had learned about the protocol it
// guards, and the seam it hands out is a plain net/http decorator precisely so that
// it cannot. A database driver here would be a query path that never saw the gate.
var forbiddenImportSubstrings = []string{
	"oauth2",
	"go-sdk",
	"jwt",
	"os/exec",
	"go-sql-driver",
	"jackc/pgx",
	"go-mssqldb",
}

// tokenBearingStems are the substrings that make an identifier one the guard below
// treats as holding the credential: any spelling of it, any casing, and anything
// built out of one — accessToken, rawCredential, presentedSecret.
//
// A stem list rather than exact names because the leak this guard missed once was
// spelled `presented`, and enumerating exact spellings is a game the next edit
// wins. It is over-broad by construction, which is the safe direction: the cost of
// a false positive here is renaming a variable in review.
var tokenBearingStems = []string{"token", "bearer", "credential", "secret", "presented", "key"}

// tokenBearingIdents are the exact names of the structural carriers — the URL the
// token is a query parameter of, the request that URL is on, the header values it
// was parsed out of. They are matched exactly because they are ordinary words that
// would match half the repository as substrings.
var tokenBearingIdents = []string{
	"endpoint", "query", "req", "resp", "values", "authorization", "creds", "header",
}

// carriesTheToken reports whether an identifier of this name in file is one the
// token guard treats as holding the credential or something derived from it.
func carriesTheToken(file, name string) bool {
	lower := strings.ToLower(name)
	for _, stem := range tokenBearingStems {
		// A bare key is the conventional iterator over a database row's map keys,
		// which internal/mcp renders as a JSON property name. It is exempt only
		// there: key material in internal/auth must remain visible to this guard.
		if stem == "key" && lower == "key" && strings.HasPrefix(file, mcpDir+"/") {
			continue
		}
		if strings.Contains(lower, stem) {
			return true
		}
	}
	return slices.Contains(tokenBearingIdents, name)
}

// holdsTheTokenItself is the narrower question the rebinding check asks: is this
// identifier in file the credential, or a name that merely mentions one.
//
// A stem at the end of a name is the thing itself — token, accessToken,
// rawCredential. A stem in the middle is usually a name *about* it:
// failureTokenRejected is the class a rejection is logged under, and copying that
// into a local is not a credential moving anywhere.
func holdsTheTokenItself(file, name string) bool {
	lower := strings.ToLower(name)
	for _, stem := range tokenBearingStems {
		if stem == "key" && lower == "key" && strings.HasPrefix(file, mcpDir+"/") {
			continue
		}
		if strings.HasSuffix(lower, stem) {
			return true
		}
	}
	return slices.Contains(tokenBearingIdents, name)
}

// loggingSinks are the calls that put a value somewhere a person can read it: a
// zerolog field or message, a formatted string, an HTTP response body. The list is
// zerolog's field vocabulary rather than a check on the receiver's type, because a
// test has no types — which makes it over-broad, and over-broad is the safe
// direction for a guard.
var loggingSinks = map[string]bool{
	"Msg": true, "Msgf": true, "Send": true, "Print": true, "Printf": true, "Println": true,
	"Str": true, "Strs": true, "Bytes": true, "Hex": true, "RawJSON": true, "Stringer": true,
	"Interface": true, "Any": true, "Fields": true, "Err": true, "AnErr": true,
	"Errorf": true, "Sprintf": true, "Sprint": true, "Sprintln": true, "Fprintf": true, "Fprintln": true,
	"Write": true, "WriteString": true, "Error": true,
}

// nonRenderingPackages are the packages whose functions share a name with a
// logging sink and render nothing: strings.Fields, slices.Contains.
var nonRenderingPackages = map[string]bool{"strings": true, "slices": true}

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
		// path.Join(".", x) is x, so this package's own files keep their bare names
		// and every message about them reads as it did.
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
// everything in internal/auth plus everything in cmd/cerberus-db-mcp, checked
// against [requiredSources] so that a scan which found nothing fails here rather
// than passing downstream.
func parseObjectiveFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	fset, files := parseFiles(t, ".", cmdDir)
	requireScanned(t, files, requiredSources)
	return fset, files
}

// parseTokenScanFiles is the scan for the one claim that reaches past this
// objective's own files: internal/auth, the binary, and internal/mcp, which is
// everything the credential could have travelled into.
func parseTokenScanFiles(t *testing.T) (*gotoken.FileSet, map[string]*ast.File) {
	t.Helper()
	fset, files := parseFiles(t, ".", cmdDir, mcpDir)
	requireScanned(t, files, requiredTokenScanSources)
	return fset, files
}

// requireScanned is the anti-vacuity check every scan here runs first: a scan that
// resolved no files, or that missed a directory, passes every assertion it makes by
// having looked at nothing — ADR 01KZT76QT9ECEMKYGKXVZ5XPPJ.
func requireScanned(t *testing.T, files map[string]*ast.File, required []string) {
	t.Helper()
	scanned := make([]string, 0, len(files))
	for name := range files {
		scanned = append(scanned, name)
	}
	slices.Sort(scanned)
	for _, want := range required {
		if _, ok := files[want]; !ok {
			t.Fatalf("the source scan did not reach %s; it found %v. This guard covers more than one directory, and a scan that misses one asserts nothing about it",
				want, scanned)
		}
	}
	t.Logf("scanned %d files: %v", len(scanned), scanned)
}

// TestPackageImportsNothingItShouldNot is scoped to this package's own directory,
// and stays that way: an import allowlist is a per-package rule, and
// cmd/cerberus-db-mcp legitimately imports things that have no business here.
func TestPackageImportsNothingItShouldNot(t *testing.T) {
	_, files := parsePackageFiles(t)
	for name, f := range files {
		for _, spec := range f.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", name, spec.Path.Value, err)
			}
			if !allowedImports[imported] {
				t.Errorf("%s imports %q, which is not on this package's allowed import list", name, imported)
			}
			for _, bad := range forbiddenImportSubstrings {
				if strings.Contains(imported, bad) {
					t.Errorf("%s imports %q: this package validates a credential issued elsewhere and holds only the sealing master secret, which it never acquires from a third party", name, imported)
				}
			}
		}
	}
}

// TestTheRawTokenNeverReachesALogger is acceptance criterion 6's source half, over
// internal/auth, the binary, and internal/mcp — everywhere in this process the
// credential could have been carried to.
//
// What it establishes, and what it does not, both need saying, because an earlier
// version of this comment claimed the whole property and a leak walked through it: a
// `presented := token` beside a log line on a real code path left every test in this
// package green, because the guard matched names and `presented` was not one of
// them.
//
// It is a name-based scan. It cannot do dataflow analysis, so it cannot see a token
// handed to a function that logs it under a parameter name of its own, and it cannot
// see one rendered by a sink this file does not know is a sink. What it does check is
// four things that are worth something together:
//
//   - The token lives in one file, named in [tokenFile], and that file imports no
//     logger and no formatter. The file that has the credential has nothing to write
//     it with.
//   - No logging sink anywhere in the scanned directories is handed an identifier
//     whose name carries the credential — see [carriesTheToken], which matches stems
//     rather than exact spellings for the reason above.
//   - The raw token is not given a second name. Any bare rebinding of a
//     token-bearing identifier to one that is not fails, which is what closes the
//     rename this guard was defeated by.
//   - The scan actually found the token where it claims it is, so a rename turns
//     this into a failure rather than into a guard over nothing.
//
// The reason that is enough is not in this file. The middleware deletes the inbound
// Authorization header on every path before anything downstream runs, so in
// internal/mcp there is no credential left to leak — the scan there is guarding
// against a re-read of a header that is gone, not against handling something that is
// present.
func TestTheRawTokenNeverReachesALogger(t *testing.T) {
	fset, files := parseTokenScanFiles(t)

	// One: the two files holding credentials cannot log or format.
	for _, source := range []string{tokenFile, sealingFile} {
		for _, spec := range files[source].Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s: %v", spec.Path.Value, err)
			}
			if imported == "github.com/rs/zerolog" || imported == "fmt" || imported == "log" || imported == "log/slog" {
				t.Errorf("%s imports %q; the file that holds credentials must have nothing to write them with", source, imported)
			}
		}
	}

	// Two: no logging sink anywhere in this objective is handed a token-bearing
	// identifier.
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !loggingSinks[sel.Sel.Name] {
				return true
			}
			// The names above are zerolog's and fmt's, and two of them — Fields, Split
			// — are also strings' and slices'. Those packages render nothing for
			// anybody to read, so a call on one of them is not a sink whatever it is
			// called. Nothing else is excused: http.Error writes a response body and is
			// meant to be caught here.
			if receiver, ok := sel.X.(*ast.Ident); ok && nonRenderingPackages[receiver.Name] {
				return true
			}
			for _, arg := range call.Args {
				ast.Inspect(arg, func(inner ast.Node) bool {
					id, ok := inner.(*ast.Ident)
					if !ok {
						return true
					}
					if carriesTheToken(name, id.Name) {
						t.Errorf("%s:%d passes %s to %s, which renders a value where a person can read it; the bearer token and everything derived from it must not reach one",
							name, fset.Position(id.Pos()).Line, id.Name, sel.Sel.Name)
					}
					return true
				})
			}
			return true
		})
	}

	// Three: the token is not given a second name that check two would not recognise.
	// A copy under an unrecognised name is how check two was defeated once, and a bare
	// rebinding is the only way to make one: every other use of the token — the hash,
	// the query parameter, the call to the validator — wraps it in a call or a
	// conversion, so nothing legitimate in these files is an assignment whose whole
	// right-hand side is the identifier. Together with check two this closes the
	// naming hole: every name the credential lives under is one [carriesTheToken]
	// answers yes to, so every sink it could reach through a variable is checked.
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			var rhs []ast.Expr
			var lhs []ast.Expr
			switch node := n.(type) {
			case *ast.AssignStmt:
				lhs, rhs = node.Lhs, node.Rhs
			case *ast.ValueSpec:
				rhs = node.Values
				for _, ident := range node.Names {
					lhs = append(lhs, ident)
				}
			case *ast.KeyValueExpr:
				// A struct field is a name the token can live under too, and a field named
				// for anything else is the same rename by another route.
				if _, ok := node.Key.(*ast.Ident); !ok {
					return true
				}
				lhs, rhs = []ast.Expr{node.Key}, []ast.Expr{node.Value}
			default:
				return true
			}
			for i, value := range rhs {
				source, ok := value.(*ast.Ident)
				if !ok || !holdsTheTokenItself(name, source.Name) {
					continue
				}
				if i < len(lhs) {
					if target, ok := lhs[i].(*ast.Ident); ok && carriesTheToken(name, target.Name) {
						// Still named as what it is, so the checks above still see it.
						continue
					}
				}
				t.Errorf("%s:%d rebinds %s under a name this guard does not recognise as a credential; the raw token may not acquire a second name, because every check on it is written in terms of the first",
					name, fset.Position(source.Pos()).Line, source.Name)
			}
			return true
		})
	}

	// Four: the scan found the thing it is guarding. If the token stops being
	// spelled like this, the checks above are satisfied by a file that no longer
	// contains what they are about, and this is what says so.
	found := 0
	ast.Inspect(files[tokenFile], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "token" {
			found++
		}
		return true
	})
	if found == 0 {
		t.Fatalf("no identifier named \"token\" appears in %s, so this guard is asserting nothing. The token handling has moved or been renamed, and these scans have to be rewritten rather than left passing",
			tokenFile)
	}
	t.Logf("%s mentions the token in %d places, all of them in a file that cannot log", tokenFile, found)
}

// TestNothingInTheBinaryHandlesABearerTokenItself is the other half of the same
// claim, over the directory this package's scans would otherwise say nothing about.
//
// cmd/cerberus-db-mcp is where the middleware is wired in, and it is the natural
// place for somebody to add a header check, a token read from a file, or a debug
// line about what a client sent. Any of those is a credential path outside the one
// file that is guarded, so none of them may exist.
func TestNothingInTheBinaryHandlesABearerTokenItself(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	for name, f := range files {
		if !strings.HasPrefix(name, cmdDir) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Ident:
				if strings.Contains(strings.ToLower(node.Name), "token") {
					t.Errorf("%s:%d names %s; the bearer token is internal/auth's alone and the binary only assigns the middleware",
						name, fset.Position(node.Pos()).Line, node.Name)
				}
			case *ast.BasicLit:
				if node.Kind != gotoken.STRING {
					return true
				}
				value, err := strconv.Unquote(node.Value)
				if err != nil {
					return true
				}
				lower := strings.ToLower(value)
				if strings.Contains(lower, "authorization") || strings.Contains(lower, "bearer") {
					t.Errorf("%s:%d contains %q; reading or naming the Authorization header outside internal/auth is a second credential path",
						name, fset.Position(node.Pos()).Line, value)
				}
			}
			return true
		})
	}
}

// TestTheOnlyEndpointNamedInTheSourceIsGooglesOverHTTPS is what makes "this
// process asks Google and nobody else" a claim about the code.
//
// The token travels in the query string of that URL, so a second endpoint — a
// staging one, a configurable one, a mock left behind — is a credential handed to
// whoever runs it, and a plain-http one is a credential on the wire. The
// alternative to this scan is trusting that no future edit adds a variable for it.
func TestTheOnlyEndpointNamedInTheSourceIsGooglesOverHTTPS(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	found := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(value, "://") {
				return true
			}
			found++
			if value != tokeninfoURL {
				t.Errorf("%s:%d names the endpoint %q; the only URL this objective may contain is Google's Tokeninfo endpoint over HTTPS",
					name, fset.Position(lit.Pos()).Line, value)
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no URL literal was found anywhere in this objective, so this guard is asserting nothing about which endpoint the token is sent to")
	}
	if !strings.HasPrefix(tokeninfoURL, "https://") {
		t.Errorf("tokeninfoURL = %q, which is not HTTPS; the token is a query parameter of it", tokeninfoURL)
	}
}

// TestTheAllowlistCannotBeEmptiedByConfiguration is the source half of criterion 7.
//
// The loader tests show that today's code refuses an absent and an empty allowlist.
// This says there is nowhere else an allowlist could come from: no default on the
// struct tag, and no fallback that would turn an unset variable into a usable
// value. A default here would not be a convenience — it would be either "everyone"
// or "nobody", and both start a server that looks authenticated.
func TestTheAllowlistCannotBeEmptiedByConfiguration(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(value, "envDefault:") {
				return true
			}
			if strings.Contains(value, "CERBERUS_AUTH_") {
				t.Errorf("%s:%d gives a CERBERUS_AUTH_* variable a default: %q. None of these three variables has a safe default",
					name, fset.Position(lit.Pos()).Line, value)
			}
			return true
		})
	}
}
