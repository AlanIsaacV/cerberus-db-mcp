package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// This file exists because this package reported "no test files" while holding the
// last mile of the objective's first guarantee. Two edits here compile, leave the
// whole suite green and produce a server that admits anybody: moving
// auth.LoadConfig below db.Open, and deleting `Middleware: middleware` from the
// mcp.Deps literal. The second is invisible to internal/mcp's own suite by design —
// a nil Middleware means no wrapping, and nearly every test there builds a Server
// that way, so "no middleware" is that package's normal state and cannot fail
// anything in it.

// lockedBuffer is the application log, readable while the server is still writing
// to it from its own goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// testEnvironment is a whole usable environment for one run of [run], with the
// audit stream pointed into the test's own directory.
//
// It sets the two PG* variables and MSSQL_USE_EPA to the empty string, which
// internal/db reads as unset, so that a developer's own shell cannot make this test
// fail on a refusal that is about their psql habits.
func testEnvironment(t *testing.T, address string) (auditPath string) {
	t.Helper()
	auditPath = filepath.Join(t.TempDir(), "audit.jsonl")

	t.Setenv("CERBERUS_MCP_ADDRESS", address)
	t.Setenv("CERBERUS_MCP_PATH", "/mcp")
	t.Setenv("CERBERUS_MCP_SHUTDOWN_TIMEOUT", "5s")
	t.Setenv("CERBERUS_MCP_AUDIT", auditPath)

	t.Setenv("CERBERUS_DB_ALIASES", "warehouse")
	t.Setenv("CERBERUS_DB_WAREHOUSE_ENGINE", "postgresql")
	// Nothing is dialled at startup — db.Open opens no connection and pings nothing —
	// so this alias never has to be reachable for the wiring to be under test.
	t.Setenv("CERBERUS_DB_WAREHOUSE_HOST", "127.0.0.1")
	t.Setenv("CERBERUS_DB_WAREHOUSE_PORT", "1")
	t.Setenv("CERBERUS_DB_WAREHOUSE_DATABASE", "warehouse")
	t.Setenv("CERBERUS_DB_WAREHOUSE_USER", "reader")
	t.Setenv("CERBERUS_DB_WAREHOUSE_PASSWORD", "hunter2")
	t.Setenv("CERBERUS_DB_WAREHOUSE_TLS", "disable")

	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv("MSSQL_USE_EPA", "")
	return auditPath
}

// TestTheProcessRefusesToStartWithoutAuthenticationBeforeItOpensAnythingElse is
// acceptance criterion 7 at the only place it is a property of the process rather
// than of a loader: the order of the calls in [run].
//
// The absent audit file is the observable half. internal/auth's own tests show that
// the configuration is refused; what they cannot show is that it is refused *first*.
// An audit file created by a start that was never going to be authenticated is
// evidence of a deployment that did not happen, sitting in the place an operator
// goes to find out what did.
func TestTheProcessRefusesToStartWithoutAuthenticationBeforeItOpensAnythingElse(t *testing.T) {
	auditPath := testEnvironment(t, "127.0.0.1:0")
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "")

	err := run(zerolog.New(&lockedBuffer{}))
	if !errors.Is(err, auth.ErrNoClientID) {
		t.Fatalf("run() = %v, want an error wrapping auth.ErrNoClientID", err)
	}
	if _, statErr := os.Stat(auditPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v, want the file not to exist: the audit destination was opened by a start that was refused",
			auditPath, statErr)
	}

	t.Run("and it refuses the same way when only the allowlist is missing", func(t *testing.T) {
		t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
		t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "")

		err := run(zerolog.New(&lockedBuffer{}))
		if !errors.Is(err, auth.ErrNoAllowlist) {
			t.Fatalf("run() = %v, want an error wrapping auth.ErrNoAllowlist", err)
		}
		if _, statErr := os.Stat(auditPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("os.Stat(%s) = %v, want the file not to exist", auditPath, statErr)
		}
	})
}

// TestTheListenerTheBinaryStartsAnswersAnUnauthenticatedRequestWithAChallenge is
// the assertion that fails when `Middleware: middleware` is deleted from the
// mcp.Deps literal in [run].
//
// It is the wiring end to end rather than a source scan, because what has to be true
// is that the process this file starts refuses a caller — not that a particular line
// is present. A request with no credential is answered by internal/auth before
// anything reaches the SDK and without asking Google anything, so this needs no
// network and no token: 401 with a challenge is a sentence only the middleware can
// produce here, and an unwrapped SDK handler answers such a request with something
// else entirely.
func TestTheListenerTheBinaryStartsAnswersAnUnauthenticatedRequestWithAChallenge(t *testing.T) {
	address := reservedAddress(t)
	auditPath := testEnvironment(t, address)
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	// Written with a stray space and a trailing comma, so the startup log's two
	// allowlist fields are visibly different values.
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", " One@Example.test ,")

	appLog := &lockedBuffer{}
	runErr := make(chan error, 1)
	go func() { runErr <- run(zerolog.New(appLog)) }()

	resp := postWhenServing(t, "http://"+address+"/mcp", runErr)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d: the process this binary starts served a request that presented no credential",
			resp.StatusCode, http.StatusUnauthorized)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("the refusal carries no WWW-Authenticate; nothing but the authentication middleware answers a request here that way")
	}

	// The audit destination was opened this time, which is what makes its absence in
	// the test above evidence of an ordering rather than of a path nothing writes.
	if _, err := os.Stat(auditPath); err != nil {
		t.Errorf("os.Stat(%s) = %v, want the audit destination to have been opened by a start that succeeded", auditPath, err)
	}

	// Both forms of the allowlist, which is what an operator debugging a 403 reads:
	// the entries as they were set, and the entries a request is actually matched
	// against.
	logged := appLog.String()
	if !strings.Contains(logged, `" One@Example.test "`) {
		t.Errorf("the startup log does not carry the allowlist as it was configured: %s", logged)
	}
	if !strings.Contains(logged, `"one@example.test"`) {
		t.Errorf("the startup log does not carry the normalised allowlist the middleware matches on: %s", logged)
	}

	// A real signal, for the reason internal/mcp's own lifecycle test gives: Run
	// registers a handler for SIGTERM before it binds, and this package runs no test
	// in parallel with another, so nothing else can be in flight when it lands. It is
	// sent only after the server answered, which is what says the handler is
	// installed.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run() = %v, want a clean shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}

// reservedAddress is a loopback address with a port the kernel has just confirmed
// was free.
//
// [run] takes its address from the environment and reports the resolved one only
// through a Ready callback it does not pass, so unlike every test inside
// internal/mcp this one cannot use port 0 and be told what it got. The window
// between closing this listener and the server binding is the price of testing the
// binary's own wiring.
func reservedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return address
}

// postWhenServing posts once the listener is accepting, failing the test if run
// returned instead of serving.
func postWhenServing(t *testing.T, endpoint string, runErr <-chan error) *http.Response {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("run returned before it was serving: %v", err)
		default:
		}
		resp, err := http.Post(endpoint, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err == nil {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listener never answered at %s: %v", endpoint, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
