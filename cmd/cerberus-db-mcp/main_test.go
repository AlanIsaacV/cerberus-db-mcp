package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/authflow"
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

// testEnvironment is a whole usable environment for one run of [run].
//
// It sets the two PG* variables and MSSQL_USE_EPA to the empty string, which
// internal/db reads as unset, so that a developer's own shell cannot make this test
// fail on a refusal that is about their psql habits.
func testEnvironment(t *testing.T, address string) {
	t.Helper()

	t.Setenv("CERBERUS_MCP_ADDRESS", address)
	t.Setenv("CERBERUS_MCP_PATH", "/mcp")
	t.Setenv("CERBERUS_MCP_SHUTDOWN_TIMEOUT", "5s")
	// The flow's configuration is supplied beside auth's because every test that
	// reaches run supplies the resource-server configuration itself. It remains
	// required even when a test only drives MCP: startup must not expose one path
	// while the authorization callback is misconfigured.
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_SECRET", "test-client-secret")
	t.Setenv("CERBERUS_AUTH_PUBLIC_BASE_URL", "https://public.example.test/")
	t.Setenv("CERBERUS_AUTH_CLIENT_REDIRECT_URIS", "https://client.example.test/callback")

	t.Setenv("CERBERUS_DB_ALIASES", "warehouse")
	t.Setenv("CERBERUS_DB_WAREHOUSE_ENGINE", "postgresql")
	// Nothing is dialled at startup — db.Open opens no connection and pings nothing —
	// so this alias never has to be reachable for the wiring to be under test.
	t.Setenv("CERBERUS_DB_WAREHOUSE_HOST", "127.0.0.1")
	t.Setenv("CERBERUS_DB_WAREHOUSE_PORT", "1")
	// Plural, and required on this engine: a PostgreSQL connection is bound to one
	// database by the protocol. The alias this produces is "warehouse.warehouse",
	// which nothing in this file asserts on — what is under test here is the order
	// of the calls in [run] and the listener it ends up with.
	t.Setenv("CERBERUS_DB_WAREHOUSE_DATABASES", "warehouse")
	t.Setenv("CERBERUS_DB_WAREHOUSE_USER", "reader")
	t.Setenv("CERBERUS_DB_WAREHOUSE_PASSWORD", "hunter2")
	t.Setenv("CERBERUS_DB_WAREHOUSE_TLS", "disable")

	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv("MSSQL_USE_EPA", "")
}

// TestTheCompiledBinaryRefusesUnusableNewAuthenticationConfiguration is
// acceptance criterion 7 at the process boundary. A loader test alone cannot
// show that main reports its refusal instead of proceeding to open the database
// or listener, so each row executes the CGO-disabled binary the test compiled.
func TestTheCompiledBinaryRefusesUnusableNewAuthenticationConfiguration(t *testing.T) {
	binary := compiledBinary(t)
	testEnvironment(t, "127.0.0.1:0")
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "one@example.test")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	for _, tt := range []struct {
		name     string
		variable string
		value    string
	}{
		{
			name:     "a missing Google client secret",
			variable: "CERBERUS_AUTH_GOOGLE_CLIENT_SECRET",
		},
		{
			name:     "a Google client secret with whitespace",
			variable: "CERBERUS_AUTH_GOOGLE_CLIENT_SECRET",
			value:    "bad client secret",
		},
		{
			name:     "a missing public base URL",
			variable: "CERBERUS_AUTH_PUBLIC_BASE_URL",
		},
		{
			name:     "a public base URL with an http scheme and a query",
			variable: "CERBERUS_AUTH_PUBLIC_BASE_URL",
			value:    "http://public.example.test/?bad=1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			environ := environmentWithout(os.Environ(), tt.variable)
			if tt.value != "" {
				environ = append(environ, tt.variable+"="+tt.value)
			}

			command := exec.Command(binary)
			command.Env = environ
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("the compiled binary started successfully with unusable authentication configuration")
			}
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
				t.Fatalf("the compiled binary did not exit non-zero: %v", err)
			}
			if !bytes.Contains(output, []byte(tt.variable)) {
				t.Errorf("the startup refusal did not name %s", tt.variable)
			}
			if tt.value != "" && bytes.Contains(output, []byte(tt.value)) {
				t.Error("the startup refusal quoted an unusable authentication configuration value")
			}
		})
	}
}

// compiledBinary builds the command under test instead of using the go test
// process itself: main's exit and stdout error path are the behaviour criterion
// 7 needs to observe. CGO stays disabled to match the image's binary.
func compiledBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cerberus-db-mcp")
	command := exec.Command("go", "build", "-o", binary, ".")
	command.Env = append(environmentWithout(os.Environ(), "CGO_ENABLED"), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build command binary: %v\n%s", err, output)
	}
	return binary
}

// environmentWithout copies an environment after removing each named variable.
// A child process cannot distinguish an empty required value from an absent one,
// but this helper makes the missing-variable rows prove the latter.
func environmentWithout(environ []string, names ...string) []string {
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	copy := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, found := strings.Cut(entry, "=")
		if found && removed[name] {
			continue
		}
		copy = append(copy, entry)
	}
	return copy
}

// TestTheProcessRefusesToStartWithoutAuthenticationBeforeItOpensAnythingElse is
// acceptance criterion 7 at the only place it is a property of the process rather
// than of a loader: the order of the calls in [run].
//
// internal/auth's own tests show that the configuration is refused; this test
// keeps the process wiring on that same early path.
func TestTheProcessRefusesToStartWithoutAuthenticationBeforeItOpensAnythingElse(t *testing.T) {
	testEnvironment(t, "127.0.0.1:0")
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "")

	err := run(zerolog.New(&lockedBuffer{}))
	if !errors.Is(err, auth.ErrNoClientID) {
		t.Fatalf("run() = %v, want an error wrapping auth.ErrNoClientID", err)
	}
	t.Run("and it refuses the same way when only the allowlist is missing", func(t *testing.T) {
		t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
		t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "")

		err := run(zerolog.New(&lockedBuffer{}))
		if !errors.Is(err, auth.ErrNoAllowlist) {
			t.Fatalf("run() = %v, want an error wrapping auth.ErrNoAllowlist", err)
		}
	})
}

func TestTheProcessRefusesToStartWithoutAClientRedirectRegistryBeforeItOpensAnythingElse(t *testing.T) {
	testEnvironment(t, "127.0.0.1:0")
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "one@example.test")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("CERBERUS_AUTH_CLIENT_REDIRECT_URIS", "")

	err := run(zerolog.New(&lockedBuffer{}))
	if !errors.Is(err, authflow.ErrNoClientRedirectURIs) {
		t.Fatalf("run() = %v, want an error wrapping authflow.ErrNoClientRedirectURIs", err)
	}
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
	testEnvironment(t, address)
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	sealingMaterial := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", sealingMaterial)
	// Written with a stray space and a trailing comma, so the startup log's two
	// allowlist fields are visibly different values.
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", " One@Example.test ,")

	appLog := &lockedBuffer{}
	runErr := make(chan error, 1)
	go func() { runErr <- run(zerolog.New(appLog)) }()

	resp := postWhenServing(t, "http://"+address+"/mcp", "", runErr)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d: the process this binary starts served a request that presented no credential",
			resp.StatusCode, http.StatusUnauthorized)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("the refusal carries no WWW-Authenticate; nothing but the authentication middleware answers a request here that way")
	}

	// Both forms of the allowlist, which is what an operator debugging a 403 reads:
	// the entries as they were set, and the entries a request is actually matched
	// against.
	logged := appLog.String()
	if strings.Contains(logged, sealingMaterial) {
		t.Error("the startup log contains the sealing material")
	}
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

// TestANetworkFacingListenerTheBinaryStartsAuthenticatesBeforeTheSDKChecksTheHost
// closes criterion 4 where both its topology and its real authentication middleware
// are present: a cloudflared request reaches the non-loopback listener under its
// Docker service name, without a credential.
func TestANetworkFacingListenerTheBinaryStartsAuthenticatesBeforeTheSDKChecksTheHost(t *testing.T) {
	address := reservedNetworkFacingAddress(t)
	testEnvironment(t, address)
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "one@example.test")

	appLog := &lockedBuffer{}
	runErr := make(chan error, 1)
	go func() { runErr <- run(zerolog.New(appLog)) }()

	resp := postWhenServing(t, "http://"+address+"/mcp", "cerberus-db-mcp:8080", runErr)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d: the non-loopback listener did not let the real authentication middleware refuse the unauthenticated request",
			resp.StatusCode, http.StatusUnauthorized)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("the refusal carries no WWW-Authenticate; the real authentication middleware did not answer this request")
	}
	if string(body) != "unauthorized\n" {
		t.Errorf("body = %q, want the authentication middleware's unauthorized response", body)
	}
	// The real authentication middleware wraps the SDK handler, so it refuses this
	// unauthenticated request before the SDK sees its Host header. This test therefore
	// cannot distinguish the bind address, and an assertion that the SDK did not
	// refuse the request could never fail. TestANonLoopbackListenerDoesNotRefuseAForeignHostHeader
	// in internal/mcp is the discriminating guard: it runs without middleware, so the
	// SDK itself answers.
	if !strings.Contains(appLog.String(), `"failure_class":"absent_header"`) {
		t.Errorf("the application log has no absent-header authentication refusal: %s", appLog.String())
	}

	shutdownRun(t, runErr)
}

// TestTheListenerTheBinaryStartsMountsTheAuthorizationEndpointAndItsCallback is
// the assertion that fails when the UnauthenticatedRoutes literal is deleted
// from the mcp.Deps literal in [run] — the same class of edit, in the same
// literal, as the one the middleware test above covers.
//
// internal/mcp's own criterion-1 test drives all three paths, but it mounts
// stub handlers it supplies itself through Deps, so it is green for a process
// that mounts none: which routes exist in the shipped process is a property of
// this file's wiring and of nothing else. Deleting the field there leaves seven
// green packages and an authorization flow that 404s in production, and the
// next objective edits that same literal to add /token and the discovery
// documents.
//
// Nothing here reaches Google. The authorization endpoint seals its state and
// answers with a redirect without asking anyone anything, and the callback
// refuses a response carrying no code before it would exchange one — so what is
// under test is which handler answered, on a listener started from the
// environment by [run]. A 404 says the route is not mounted and a 401 says the
// authentication middleware wrapped something it must not; both fail here.
func TestTheListenerTheBinaryStartsMountsTheAuthorizationEndpointAndItsCallback(t *testing.T) {
	address := reservedAddress(t)
	testEnvironment(t, address)
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", "1234567890-abcdefghijklmnop.apps.googleusercontent.com")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "one@example.test")

	appLog := &lockedBuffer{}
	runErr := make(chan error, 1)
	go func() { runErr <- run(zerolog.New(appLog)) }()

	// A well-formed authorization request, so that the endpoint gets as far as
	// the redirect: a malformed one is refused by the same handler and would
	// leave this test unable to tell the flow's own 400 from anybody else's.
	// The challenge is RFC 7636's example value; the endpoint checks that one is
	// present and that the method is S256, not what it hashes.
	authorizationQuery := url.Values{
		"redirect_uri":          {"https://client.example.test/callback"},
		"state":                 {"the-client-own-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"response_type":         {"code"},
	}

	for _, tt := range []struct {
		name               string
		path               string
		want               int
		wantChallenge      bool
		wantLocationPrefix string
	}{
		{
			name:               "the authorization endpoint redirects to Google without a credential",
			path:               authflow.AuthorizationPath + "?" + authorizationQuery.Encode(),
			want:               http.StatusFound,
			wantLocationPrefix: "https://accounts.google.com/",
		},
		{
			// Google's callback arrives with no credential of this server's and
			// must be answered by the flow rather than challenged. Empty here, so
			// the answer is the flow's own refusal of an unusable authorization
			// response — which only the mounted handler can produce.
			name: "the callback refuses an unusable response without a credential",
			path: authflow.CallbackPath,
			want: http.StatusBadRequest,
		},
		{
			// The other half of criterion 1, in the same process and the same mux:
			// mounting the flow unwrapped must not have unwrapped the endpoint the
			// middleware exists for.
			name:          "the MCP endpoint is still wrapped and still refuses",
			path:          "/mcp",
			want:          http.StatusUnauthorized,
			wantChallenge: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := getWhenServing(t, "http://"+address+tt.path, runErr)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("the process this binary starts serves no handler at %s: the mcp.Deps literal in run mounts it nowhere", tt.path)
			}
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
			if challenged := resp.Header.Get("WWW-Authenticate") != ""; challenged != tt.wantChallenge {
				t.Errorf("WWW-Authenticate present = %v, want %v: %q", challenged, tt.wantChallenge, resp.Header.Get("WWW-Authenticate"))
			}
			location := resp.Header.Get("Location")
			if tt.wantLocationPrefix == "" {
				if location != "" {
					t.Errorf("Location = %q, want none", location)
				}
				return
			}
			if !strings.HasPrefix(location, tt.wantLocationPrefix) {
				t.Errorf("Location = %q, want a redirect to %s", location, tt.wantLocationPrefix)
			}
		})
	}

	shutdownRun(t, runErr)
}

// getWhenServing is [postWhenServing] for the flow's two GET endpoints, with
// redirects left unfollowed: the authorization endpoint's answer is a redirect
// to Google, and a client that followed it would turn this test into one that
// needs the internet and Google's consent screen to pass.
func getWhenServing(t *testing.T, endpoint string, runErr <-chan error) *http.Response {
	t.Helper()
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("run returned before it was serving: %v", err)
		default:
		}
		resp, err := client.Get(endpoint)
		if err == nil {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listener never answered at %s: %v", endpoint, err)
		}
		time.Sleep(5 * time.Millisecond)
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

// reservedNetworkFacingAddress reserves a wildcard port and returns an address
// that reaches it through this host's network-facing interface.
func reservedNetworkFacingAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserve a network-facing port: %v", err)
	}
	address := nonLoopbackAddress(t, listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return address
}

// nonLoopbackAddress mirrors internal/mcp's test-only helper because its
// unexported package-local form cannot cross into the command package. The SDK
// examines the accepted local address, so dialing the wildcard listener through
// loopback would not exercise the deployed Docker topology.
func nonLoopbackAddress(t *testing.T, listenerAddress string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		t.Fatalf("split listener address %q: %v", listenerAddress, err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list network interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), port)
			}
		}
	}
	t.Fatal("deployment-critical DNS-rebinding and authentication guard could not run: this environment needs an up, non-loopback IPv4 interface to exercise a network-facing listener")
	return ""
}

// postWhenServing posts once the listener is accepting, failing the test if run
// returned instead of serving.
func postWhenServing(t *testing.T, endpoint, host string, runErr <-chan error) *http.Response {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("run returned before it was serving: %v", err)
		default:
		}
		req, err := http.NewRequest(http.MethodPost, endpoint,
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if host != "" {
			req.Host = host
		}
		resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
		if err == nil {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listener never answered at %s: %v", endpoint, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func shutdownRun(t *testing.T, runErr <-chan error) {
	t.Helper()
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
