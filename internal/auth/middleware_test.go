package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// handlerReached is the status the handler behind the middleware answers with.
//
// It is deliberately not 200: every status this middleware can produce on its own
// is a rejection, so a distinctive success status means a test can tell "the
// request reached the thing being protected" from "something upstream answered
// happily". Nothing else in this suite answers 418.
const handlerReached = http.StatusTeapot

func discardLogger() zerolog.Logger { return zerolog.New(io.Discard) }

// authHarness is one middleware over one fake Tokeninfo endpoint, with a handler
// behind it that records what it saw.
//
// The handler is a bare http.HandlerFunc and not an MCP server, which is the
// point. The go-sdk answers 403 by itself when a loopback listener is asked for a
// non-loopback Host, so a 403 observed through the real transport could be either
// that protection or this allowlist. Behind a handler that has no opinion about
// anything, a 403 can only have come from here.
type authHarness struct {
	url       string
	tokeninfo *fakeTokeninfo
	appLog    *bytes.Buffer
	// reached counts the requests that got past the middleware. Every rejection
	// test asserts on it, because a status code alone does not say that no tool ran.
	reached atomic.Int64

	mu                     sync.Mutex
	identity               Identity
	identityOK             bool
	authorizationAtHandler []string
	authorizationAfter     []string
}

func serveBehindAuth(t *testing.T, cfg Config, f *fakeTokeninfo) *authHarness {
	t.Helper()
	return serveBehindAuthWithin(t, cfg, f, 2*time.Second)
}

func serveBehindAuthWithin(t *testing.T, cfg Config, f *fakeTokeninfo, timeout time.Duration) *authHarness {
	t.Helper()
	h := &authHarness{tokeninfo: f, appLog: &bytes.Buffer{}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.reached.Add(1)
		id, ok := IdentityFrom(r.Context())
		h.mu.Lock()
		h.identity, h.identityOK = id, ok
		h.authorizationAtHandler = r.Header.Values("Authorization")
		h.mu.Unlock()
		w.WriteHeader(handlerReached)
		_, _ = w.Write([]byte("the protected handler ran"))
	})
	v := newValidator(cfg.ClientID, f.url, newHTTPClient(timeout), time.Now)
	guarded := newMiddleware(cfg, zerolog.New(h.appLog), v)(next)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guarded.ServeHTTP(w, r)
		h.mu.Lock()
		h.authorizationAfter = r.Header.Values("Authorization")
		h.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	h.url = server.URL
	return h
}

func serveBehindAuthAt(t *testing.T, cfg Config, f *fakeTokeninfo, now func() time.Time) *authHarness {
	t.Helper()
	h := &authHarness{tokeninfo: f, appLog: &bytes.Buffer{}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.reached.Add(1)
		id, ok := IdentityFrom(r.Context())
		h.mu.Lock()
		h.identity, h.identityOK = id, ok
		h.authorizationAtHandler = r.Header.Values("Authorization")
		h.mu.Unlock()
		w.WriteHeader(handlerReached)
		_, _ = w.Write([]byte("the protected handler ran"))
	})
	sealer := testSealer(t, cfg.SealingSecret)
	v := newValidator(cfg.ClientID, f.url, newHTTPClient(2*time.Second), now)
	guarded := newMiddlewareWithSealer(cfg, zerolog.New(h.appLog), v, sealer, now)(next)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guarded.ServeHTTP(w, r)
		h.mu.Lock()
		h.authorizationAfter = r.Header.Values("Authorization")
		h.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	h.url = server.URL
	return h
}

// get sends one request carrying the given Authorization header values: none for
// an absent header, more than one for a repeated one.
func (h *authHarness) get(t *testing.T, authorization ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url, strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for _, value := range authorization {
		req.Header.Add("Authorization", value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *authHarness) observedIdentity() (Identity, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.identity, h.identityOK
}

func (h *authHarness) observedAuthorization() (atHandler, after []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.authorizationAtHandler...), append([]string(nil), h.authorizationAfter...)
}

// rejections is every line the middleware wrote to the application log, decoded.
func (h *authHarness) rejections(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.appLog.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("the application log line %q is not JSON: %v", line, err)
		}
		out = append(out, record)
	}
	return out
}

// challengeFor is the WWW-Authenticate a rejection of this class must carry, and
// the empty string for the classes that must carry none.
//
// It is a table written out here rather than a call into the code, so that a change
// to which classes are challenged has to be made twice by somebody who meant it. A
// challenge tells a spec-compliant MCP or OAuth client "your credential is not
// acceptable, reauthorize": right for a header shape and for a token Google
// refused, wrong for a Google timeout, a 429 or a shed slot, where the credential
// may be perfect and a retry is the correct response.
func challengeFor(t *testing.T, class string) string {
	t.Helper()
	switch class {
	case failureAbsentHeader, failureRepeatedHeader, failureMalformedHeader, failureTokenRejected:
		return `Bearer realm="cerberus-db-mcp"`
	case failureSealedCredentialExpired, failureSealedCredentialCorrupt, failureSealedCredentialWrongPurpose:
		return `Bearer realm="cerberus-db-mcp"`
	case failureUnavailable, failureNoTokenValidation, failureNoSealedCredentialValidation,
		failureNotAllowlisted, failureEmailUnverified, failureNoEmailInToken:
		return ""
	}
	// A class this table has never heard of. The test cannot know what the right
	// answer is, and guessing either way would be an assertion about nothing.
	t.Fatalf("no expected WWW-Authenticate is recorded for the failure class %q; add it to challengeFor deliberately", class)
	return ""
}

// assertRejected is the whole of what a rejection has to be: the status on the
// wire, the challenge that class does or does not carry, no handler run, and one
// log line naming the class.
func (h *authHarness) assertRejected(t *testing.T, resp *http.Response, status int, class string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status = %d, want %d", resp.StatusCode, status)
	}
	if got, want := resp.Header.Get("WWW-Authenticate"), challengeFor(t, class); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q for a %s rejection", got, want, class)
	}
	if got := h.reached.Load(); got != 0 {
		t.Errorf("the protected handler ran %d times; a refused request must reach no handler", got)
	}
	records := h.rejections(t)
	if len(records) != 1 {
		t.Fatalf("the application log holds %d lines, want exactly 1 for one rejection: %s", len(records), h.appLog)
	}
	if records[0]["failure_class"] != class {
		t.Errorf("failure_class = %v, want %q", records[0]["failure_class"], class)
	}
	if records[0]["level"] != "warn" {
		t.Errorf("level = %v, want warn", records[0]["level"])
	}
	// The audit stream is not this middleware's to write. A request that reached no
	// tool has no tool, alias, statement or verdict to record, and a stream shaped
	// around a tool call cannot carry an event with all of them empty.
	if _, ok := records[0]["stream"]; ok {
		t.Errorf("the rejection carries a stream field, so it was written as an audit event: %v", records[0])
	}
}

// assertRefusalShape is the byte-identity check behind
// [TestTheRefusalShapesAreTheOnesFromBeforeTheAuthorizationServer]: the status, the
// WWW-Authenticate header values whole rather than joined, the class in the log,
// and the auth_refusal field that says which of this listener's 403s this is.
//
// It compares the header as a slice because "no challenge" and "one challenge" are
// not the only two states a header can be in: a second Set somewhere would produce
// two values, which Header.Get hides by answering the first.
func (h *authHarness) assertRefusalShape(t *testing.T, resp *http.Response, status int, class string, challenge []string, authRefusal string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status = %d, want %d", resp.StatusCode, status)
	}
	if got := resp.Header.Values("WWW-Authenticate"); !slices.Equal(got, challenge) {
		t.Errorf("WWW-Authenticate = %q, want %q for a %s refusal", got, challenge, class)
	}
	if got := h.reached.Load(); got != 0 {
		t.Errorf("the protected handler ran %d times; a refused request must reach no handler", got)
	}
	records := h.rejections(t)
	if len(records) != 1 {
		t.Fatalf("the application log holds %d lines, want exactly 1 for one refusal: %s", len(records), h.appLog)
	}
	if records[0]["failure_class"] != class {
		t.Errorf("failure_class = %v, want %q", records[0]["failure_class"], class)
	}
	got, present := records[0]["auth_refusal"]
	switch {
	case authRefusal == "" && present:
		t.Errorf("a %d refusal carries auth_refusal = %v; that field is what tells this package's 403 apart from the SDK's, and putting it on anything else takes the distinction away",
			status, got)
	case authRefusal != "" && got != authRefusal:
		t.Errorf("auth_refusal = %v, want %q", got, authRefusal)
	}
}

func (h *authHarness) assertAuthorizationGone(t *testing.T) {
	t.Helper()
	atHandler, after := h.observedAuthorization()
	if len(atHandler) != 0 {
		t.Errorf("the handler behind the middleware still sees an Authorization header: %q", atHandler)
	}
	if len(after) != 0 {
		t.Errorf("the request still carries an Authorization header after the middleware answered: %q", after)
	}
}

func allowlistOf(addresses ...string) Config {
	return Config{ClientID: testClientID, AllowedEmails: addresses, SealingSecret: testSealingSecret}
}

// TestARequestWithNoUsableBearerTokenNeverReachesTheHandler is acceptance
// criterion 2.
func TestARequestWithNoUsableBearerTokenNeverReachesTheHandler(t *testing.T) {
	for _, tt := range []struct {
		name          string
		authorization []string
		class         string
	}{
		{"no Authorization header at all", nil, failureAbsentHeader},
		{"two Authorization headers", []string{"Bearer one", "Bearer two"}, failureRepeatedHeader},
		{"two headers where only the second is a bearer token", []string{"Basic dXNlcjpwdw==", "Bearer one"}, failureRepeatedHeader},
		{"a Basic credential", []string{"Basic dXNlcjpwdw=="}, failureMalformedHeader},
		{"a scheme this server does not implement", []string{"Token abc123"}, failureMalformedHeader},
		{"Bearer with nothing after it", []string{"Bearer"}, failureMalformedHeader},
		{"Bearer with only trailing space after it", []string{"Bearer "}, failureMalformedHeader},
		{"a token with no scheme in front of it", []string{"abc123"}, failureMalformedHeader},
		{"a scheme and two words after it", []string{"Bearer abc 123"}, failureMalformedHeader},
		{"an empty Authorization header", []string{""}, failureMalformedHeader},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The endpoint answers a valid identity, so this test cannot pass because
			// validation happened to fail: nothing here should reach it at all.
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, tt.authorization...)
			h.assertRejected(t, resp, http.StatusUnauthorized, tt.class)

			if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="cerberus-db-mcp"` {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge naming the realm", got)
			}
			// A malformed header must not cost a request to Google. Otherwise anything
			// that can reach this listener can spend this deployment's Tokeninfo quota.
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a request with no usable token, want 0", got)
			}
		})
	}
}

// TestATokenGoogleWillNotVouchForIsAnsweredUnauthorized is acceptance criterion 3,
// through the middleware rather than at the validator: the point here is the status
// on the wire and the handler that did not run.
//
// The two validation_unavailable rows are also where the challenge's per-class rule
// is exercised from the other side. Criterion 3 asks for the 401 and says nothing
// about a challenge; assertRejected is what holds each of these classes to the one
// it should carry, which for a throttled or failing endpoint is none — those are
// not statements about the caller's credential, and a client that reauthorizes over
// them has been sent to do the one thing that cannot help.
func TestATokenGoogleWillNotVouchForIsAnsweredUnauthorized(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		class  string
	}{
		{"a token Tokeninfo reports as invalid", http.StatusBadRequest, `{"error":"invalid_token"}`, failureTokenRejected},
		{"a token issued to another application", http.StatusOK,
			tokeninfoBody("other.apps.googleusercontent.com", testClientID, "sub-1", "one@example.test", "3599", "true"), failureTokenRejected},
		{"a token another application asked for", http.StatusOK,
			tokeninfoBody(testClientID, "other.apps.googleusercontent.com", "sub-1", "one@example.test", "3599", "true"), failureTokenRejected},
		// An absolute epoch second in 2020: past under the reading that can apply to
		// it, and not readable as seconds-remaining at all.
		{"a token whose expiry has passed", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "one@example.test", "1600000000", "true"), failureTokenRejected},
		{"a token whose expiry cannot be read one way", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "one@example.test", "200000", "true"), failureTokenRejected},
		{"an endpoint that is throttling this deployment", http.StatusTooManyRequests, `{"error":"rate_limited"}`, failureUnavailable},
		{"an endpoint that is failing", http.StatusInternalServerError, ``, failureUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(tt.status, tt.body))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, "Bearer ya29.a-token")
			h.assertRejected(t, resp, http.StatusUnauthorized, tt.class)
		})
	}
}

// TestAGoogleFailureIsNotAnsweredWithAReauthorizationChallenge is the class
// distinction on its own, because the cost of getting it wrong is paid by every
// connected agent at once.
//
// A 401 carrying WWW-Authenticate is an instruction to reauthorize. Sent for a
// Google timeout, a 429, a shed concurrency slot or a response over the size cap,
// it turns a transient fault on somebody else's endpoint into a reauthorization
// flow for every client that was working a second ago — when the credential they
// hold is fine and the only correct response is to try again. The challenge on the
// classes that *are* about the credential is asserted in the two criterion 2 and 3
// tests above.
func TestAGoogleFailureIsNotAnsweredWithAReauthorizationChallenge(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"an endpoint that is throttling this deployment", respondWith(http.StatusTooManyRequests, `{"error":"rate_limited"}`)},
		{"an endpoint that is failing", respondWith(http.StatusInternalServerError, ``)},
		{"an endpoint whose answer is unreadable", respondWith(http.StatusOK, `{"aud":`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, tt.handler)
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, "Bearer ya29.a-token")
			h.assertRejected(t, resp, http.StatusUnauthorized, failureUnavailable)
			if got := resp.Header.Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q on a %s 401; nothing the caller presents is what failed here, so a challenge sends them to reauthorize instead of to retry",
					got, failureUnavailable)
			}
		})
	}
}

// TestTheCredentialIsGoneFromTheRequestByTheTimeAnythingDownstreamRuns is the
// structural half of "the token lives in internal/auth and nowhere else".
//
// The source guards can say that no code in this repository logs the token. What
// they cannot say is that the token is not *there* to be logged: the go-sdk hands a
// tool handler the inbound header map by reference as CallToolRequest.Extra.Header
// and sanitises nothing, so for as long as the middleware leaves the header on the
// request, one debug line added in internal/mcp — a package that is not supposed to
// know what a token is — prints a live credential. Deleting it on every path is what
// removes the thing rather than the mention of it, and this asserts both paths,
// because a deletion that only happens on success leaves the credential behind on
// exactly the requests somebody is debugging.
func TestTheCredentialIsGoneFromTheRequestByTheTimeAnythingDownstreamRuns(t *testing.T) {
	const token = "ya29.a0AfB_DOWNSTREAM-EVIDENCE"

	for _, tt := range []struct {
		name    string
		status  int
		body    string
		want    int
		reached int64
	}{
		{
			name: "a request the middleware admits", status: http.StatusOK,
			body: acceptedBody("one@example.test"), want: handlerReached, reached: 1,
		},
		{
			name: "a request the middleware refuses", status: http.StatusBadRequest,
			body: `{"error":"invalid_token"}`, want: http.StatusUnauthorized, reached: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(tt.status, tt.body))

			var (
				mu           sync.Mutex
				seenByNext   []string
				seenAfterAll []string
				reached      atomic.Int64
			)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				mu.Lock()
				seenByNext = r.Header.Values("Authorization")
				mu.Unlock()
				w.WriteHeader(handlerReached)
			})
			v := newValidator(testClientID, f.url, newHTTPClient(2*time.Second), time.Now)
			guarded := newMiddleware(allowlistOf("one@example.test"), discardLogger(), v)(next)
			// The middleware hands next a shallow copy of the request, which shares this
			// header map, so what is observed here is what every layer after the
			// middleware would see — on the refused path too, where there is no next
			// handler to ask.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				guarded.ServeHTTP(w, r)
				mu.Lock()
				seenAfterAll = r.Header.Values("Authorization")
				mu.Unlock()
			}))
			t.Cleanup(server.Close)

			req, err := http.NewRequest(http.MethodPost, server.URL, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// The middleware still decided what it was supposed to decide: a deletion
			// that broke authentication would pass every assertion below.
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
			if got := reached.Load(); got != tt.reached {
				t.Errorf("the protected handler ran %d times, want %d", got, tt.reached)
			}
			// And Google was asked, which is what says the header was read before it was
			// deleted rather than deleted before it was read.
			if got := f.requests.Load(); got != 1 {
				t.Errorf("Tokeninfo saw %d requests, want 1: the credential must be read before it is removed", got)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(seenByNext) != 0 {
				t.Errorf("the handler behind the middleware still sees an Authorization header: %q", seenByNext)
			}
			if len(seenAfterAll) != 0 {
				t.Errorf("the request still carries an Authorization header after the middleware answered: %q", seenAfterAll)
			}
		})
	}
}

// TestAnIdentityThatIsNotOnTheAllowlistIsAnsweredForbidden is acceptance
// criterion 4. The 403 and the 401 are different answers to different questions,
// and this is the one whose answer an operator can change.
func TestAnIdentityThatIsNotOnTheAllowlistIsAnsweredForbidden(t *testing.T) {
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("stranger@example.test")))
	h := serveBehindAuth(t, allowlistOf("one@example.test", "two@example.test"), f)

	resp := h.get(t, "Bearer ya29.a-token")
	h.assertRejected(t, resp, http.StatusForbidden, failureNotAllowlisted)

	// No challenge on a 403: the credential was fine and presenting it again, or
	// presenting a fresh one, changes nothing.
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q on a 403; a 403 is not an authentication challenge", got)
	}
	record := h.rejections(t)[0]
	// The one 403 this process can answer that is not the allowlist's comes from the
	// SDK's DNS-rebinding protection, which produces no line here at all. These two
	// fields are what tells a reader which 403 they are looking at.
	if record["auth_refusal"] != "identity_allowlist" {
		t.Errorf("auth_refusal = %v, want identity_allowlist so this 403 is distinguishable from the SDK's", record["auth_refusal"])
	}
	// The address is logged in full: an allowlist refusal is nearly always an
	// operator who has not added a colleague yet, and a line that does not say who
	// leaves them guessing.
	if record["email"] != "stranger@example.test" {
		t.Errorf("email = %v, want the address that was refused", record["email"])
	}
	if record["subject"] == "" {
		t.Error("the rejection does not carry the Google subject it refused")
	}
}

// TestATokenCarryingNoEmailIsRefusedAsThatRatherThanAsAnUnknownIdentity is a
// subcase of criterion 4 — Tokeninfo accepted the token, no allowlisted address
// matched, so it is a 403 — told apart from the other one in the log.
//
// It matters because whether Tokeninfo returns `email` and `email_verified` for an
// *access* token is still an open question of this objective. If it does not, every
// correctly configured caller is refused, and under one shared class the log would
// send an operator to add an address to a list that is already right, over and over,
// with the empty email field as the only hint that there was never an address to
// add.
func TestATokenCarryingNoEmailIsRefusedAsThatRatherThanAsAnUnknownIdentity(t *testing.T) {
	for _, tt := range []struct {
		name  string
		email string
	}{
		{"a response with no email field at all", ``},
		{"a response whose email field is empty", `"email":"",`},
		{"a response whose email field is a space", `"email":" ",`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"aud":%q,"azp":%q,"sub":"sub-1","scope":"openid email profile","exp":3599,%s"email_verified":true}`,
				testClientID, testClientID, tt.email)
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, "Bearer ya29.a-token")
			h.assertRejected(t, resp, http.StatusForbidden, failureNoEmailInToken)

			record := h.rejections(t)[0]
			// Still one of this package's 403s and not the SDK's, which is what the
			// auth_refusal field is for; the class is what says which of ours it is.
			if record["auth_refusal"] != "identity_allowlist" {
				t.Errorf("auth_refusal = %v, want identity_allowlist so this 403 is distinguishable from the SDK's", record["auth_refusal"])
			}
			// The message has to send the operator somewhere other than their allowlist,
			// because their allowlist is not what is wrong.
			message, _ := record["message"].(string)
			if !strings.Contains(message, "no email address") {
				t.Errorf("message = %q, want a line saying Google returned no address to match", message)
			}
			if strings.Contains(message, "is not allowed on this server") {
				t.Errorf("message = %q, which diagnoses an allowlist that has nothing wrong with it", message)
			}
			const wantMessage = "request refused before any tool: Google vouched for this token and returned no email address with it, so there is nothing for the allowlist to match; check that the client requested the email scope before changing the allowlist"
			if message != wantMessage {
				t.Errorf("message = %q, want %q", message, wantMessage)
			}
		})
	}
}

func TestAnAllowlistedAddressWhoseEmailIsNotVerifiedIsAnsweredForbidden(t *testing.T) {
	body := tokeninfoBody(testClientID, testClientID, "sub-1", "one@example.test", "3599", "false")
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
	h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

	resp := h.get(t, "Bearer ya29.a-token")
	h.assertRejected(t, resp, http.StatusForbidden, failureEmailUnverified)
	if record := h.rejections(t)[0]; record["email_verified"] != false {
		t.Errorf("email_verified = %v, want false: the class and the field must agree", record["email_verified"])
	}
}

// TestAnUnverifiedAddressIsRefusedEvenWhenTheFieldIsMerelyPresent is the narrow
// version of the same claim, and the reason it is separate is that "present" and
// "true" are the two readings of the same field, and only one of them is an
// identity Google will stand behind.
func TestAnUnverifiedAddressIsRefusedEvenWhenTheFieldIsMerelyPresent(t *testing.T) {
	for _, verified := range []string{`"false"`, `"maybe"`, `1`, `null`, `""`} {
		t.Run(verified, func(t *testing.T) {
			body := tokeninfoBody(testClientID, testClientID, "sub-1", "one@example.test", "3599", verified)
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, "Bearer ya29.a-token")
			h.assertRejected(t, resp, http.StatusForbidden, failureEmailUnverified)
		})
	}
}

// TestAnAllowlistedIdentityReachesTheHandlerCarryingItsSubjectAndEmail is the
// positive path, and the identity it asserts on is the one internal/mcp reads off
// the handler's context to fill an audit event.
func TestAnAllowlistedIdentityReachesTheHandlerCarryingItsSubjectAndEmail(t *testing.T) {
	body := tokeninfoBody(testClientID, testClientID, "108134201943512340987", "One@Example.test", "3599", "true")
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
	// Written in a different case from the address Google returns, which is the
	// ordinary state of an operator-typed allowlist.
	h := serveBehindAuth(t, allowlistOf("one@example.TEST"), f)

	resp := h.get(t, "bearer ya29.a-token") // a lowercase scheme is still a bearer token
	if resp.StatusCode != handlerReached {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (%s), want the protected handler to have answered", resp.StatusCode, body)
	}
	if got := h.reached.Load(); got != 1 {
		t.Errorf("the protected handler ran %d times, want 1", got)
	}
	id, ok := h.observedIdentity()
	if !ok {
		t.Fatal("the handler found no identity on its context; nothing downstream could audit this call")
	}
	if id.Subject != "108134201943512340987" {
		t.Errorf("Subject = %q, want the Google sub from the response", id.Subject)
	}
	// Google's own spelling of the address, not the allowlist's: what is recorded is
	// what the identity provider said, and the allowlist is only how it was matched.
	if id.Email != "One@Example.test" {
		t.Errorf("Email = %q, want the address Google returned", id.Email)
	}
	if lines := h.appLog.String(); lines != "" {
		t.Errorf("an admitted request wrote to the application log: %s", lines)
	}
}

// TestASealedCredentialReachesTheHandlerAsTheSameIdentity is acceptance
// criterion 6. The sealed route is local, so Google must not see a request; the
// identity after the branch is nevertheless the same shape the Google route puts
// in the context.
func TestASealedCredentialReachesTheHandlerAsTheSameIdentity(t *testing.T) {
	for _, tt := range []struct {
		name    string
		subject string
		email   string
	}{
		{"a verified allowlisted identity", "108134201943512340987", "One@Example.test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			f := newFakeTokeninfo(t, respondWith(http.StatusInternalServerError, ""))
			cfg := allowlistOf("one@example.TEST")
			h := serveBehindAuthAt(t, cfg, f, clock.now)
			sealed, err := testSealer(t, cfg.SealingSecret).SealAccess(AccessCredential{
				Subject: tt.subject, Email: tt.email, Verified: true, ExpiresAt: clock.now().Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("SealAccess: %v", err)
			}

			resp := h.get(t, "Bearer "+sealed)
			if resp.StatusCode != handlerReached {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d (%s), want the protected handler to have answered", resp.StatusCode, body)
			}
			if got := h.reached.Load(); got != 1 {
				t.Errorf("the protected handler ran %d times, want 1", got)
			}
			id, ok := h.observedIdentity()
			if !ok {
				t.Fatal("the handler found no identity on its context")
			}
			if id != (Identity{Subject: tt.subject, Email: tt.email}) {
				t.Errorf("Identity = %#v, want %#v", id, Identity{Subject: tt.subject, Email: tt.email})
			}
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a sealed credential, want 0", got)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

// TestASealedCredentialWithAnIdentityTheServerWillNotAdmitIsForbidden is
// acceptance criterion 7. The allowlist is deliberately evaluated after
// unsealing on every request, so removing an address applies immediately.
func TestASealedCredentialWithAnIdentityTheServerWillNotAdmitIsForbidden(t *testing.T) {
	for _, tt := range []struct {
		name     string
		identity AccessCredential
		allowed  []string
		class    string
		message  string
	}{
		{
			name:     "an absent email",
			identity: AccessCredential{Subject: "sub-1", Verified: true},
			allowed:  []string{"one@example.test"},
			class:    failureNoEmailInToken,
			message:  "request refused before any tool: this server's sealed credential carried no usable subject or email address; replace the local credential or investigate the local credential issuer before changing the allowlist",
		},
		{
			name:     "an absent subject",
			identity: AccessCredential{Email: "one@example.test", Verified: true},
			allowed:  []string{"one@example.test"},
			class:    failureNoEmailInToken,
			message:  "request refused before any tool: this server's sealed credential carried no usable subject or email address; replace the local credential or investigate the local credential issuer before changing the allowlist",
		},
		{
			name:     "an unverified allowlisted email",
			identity: AccessCredential{Subject: "sub-1", Email: "one@example.test"},
			allowed:  []string{"one@example.test"},
			class:    failureEmailUnverified,
		},
		{
			name:     "a verified email outside the current allowlist",
			identity: AccessCredential{Subject: "sub-1", Email: "removed@example.test", Verified: true},
			allowed:  []string{"one@example.test"},
			class:    failureNotAllowlisted,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			f := newFakeTokeninfo(t, respondWith(http.StatusInternalServerError, ""))
			cfg := allowlistOf(tt.allowed...)
			h := serveBehindAuthAt(t, cfg, f, clock.now)
			tt.identity.ExpiresAt = clock.now().Add(time.Hour)
			sealed, err := testSealer(t, cfg.SealingSecret).SealAccess(tt.identity)
			if err != nil {
				t.Fatalf("SealAccess: %v", err)
			}

			resp := h.get(t, "Bearer "+sealed)
			h.assertRejected(t, resp, http.StatusForbidden, tt.class)
			if record := h.rejections(t)[0]; record["auth_refusal"] != "identity_allowlist" {
				t.Errorf("auth_refusal = %v, want identity_allowlist", record["auth_refusal"])
			}
			if tt.message != "" {
				if got := h.rejections(t)[0]["message"]; got != tt.message {
					t.Errorf("message = %q, want %q", got, tt.message)
				}
			}
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a sealed credential, want 0", got)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

// TestASealedCredentialThatCannotAuthenticateIsChallenged is acceptance
// criterion 8. The clock is hand-wound: expiry is a boundary condition, never a
// reason to make the suite wait.
func TestASealedCredentialThatCannotAuthenticateIsChallenged(t *testing.T) {
	for _, tt := range []struct {
		name    string
		seal    func(*Sealer, time.Time) (string, error)
		advance time.Duration
		class   string
	}{
		{
			name: "an expired access credential",
			seal: func(s *Sealer, now time.Time) (string, error) {
				return s.SealAccess(AccessCredential{Subject: "sub-1", Email: "one@example.test", Verified: true, ExpiresAt: now.Add(time.Hour)})
			},
			advance: time.Hour,
			class:   failureSealedCredentialExpired,
		},
		{
			name: "a tampered access credential",
			seal: func(s *Sealer, now time.Time) (string, error) {
				sealed, err := s.SealAccess(AccessCredential{Subject: "sub-1", Email: "one@example.test", Verified: true, ExpiresAt: now.Add(time.Hour)})
				if err != nil {
					return "", err
				}
				last := "A"
				if strings.HasSuffix(sealed, last) {
					last = "B"
				}
				return sealed[:len(sealed)-1] + last, nil
			},
			class: failureSealedCredentialCorrupt,
		},
		{
			name: "a refresh credential presented as access",
			seal: func(s *Sealer, _ time.Time) (string, error) {
				return s.SealRefresh(RefreshCredential{UpstreamSecret: "upstream-refresh-secret"})
			},
			class: failureSealedCredentialWrongPurpose,
		},
		{
			name: "a credential with a future version",
			seal: func(*Sealer, time.Time) (string, error) {
				return "cdb2:a.not-a-real-ciphertext", nil
			},
			class: failureSealedCredentialCorrupt,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			f := newFakeTokeninfo(t, respondWith(http.StatusInternalServerError, ""))
			cfg := allowlistOf("one@example.test")
			h := serveBehindAuthAt(t, cfg, f, clock.now)
			sealed, err := tt.seal(testSealer(t, cfg.SealingSecret), clock.now())
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			clock.advance(tt.advance)

			resp := h.get(t, "Bearer "+sealed)
			h.assertRejected(t, resp, http.StatusUnauthorized, tt.class)
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a sealed credential, want 0", got)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

// challengeBeforeTheAuthorizationServer is the WWW-Authenticate string this
// middleware sent before this objective, taken from
// `git show HEAD:internal/auth/middleware.go` and written out here whole rather
// than assembled from [realm], so that an edit to realm is something this test
// reports instead of something it follows.
const challengeBeforeTheAuthorizationServer = `Bearer realm="cerberus-db-mcp"`

// refusalBeforeTheAuthorizationServer is the auth_refusal value every 403 from this
// package carried before this objective, from the same source.
const refusalBeforeTheAuthorizationServer = "identity_allowlist"

// TestTheRefusalShapesAreTheOnesFromBeforeTheAuthorizationServer is acceptance
// criterion 10.
//
// This objective gave the process an authorization server of its own, and the two
// credential paths that were already here — a Google bearer token, and a sealed
// access credential — have to refuse exactly as they refused before it. The
// expected side of every row is a literal read out of HEAD; the actual side is what
// the source spells today. Writing both is the whole point: a constant compared
// with itself follows a rename wherever it goes, and what has to be shown here is
// that the bytes on the wire and in the log did not move. Every connected client's
// reauthorization decision is made on the challenge, and every operator's log filter
// is written on the class.
//
// It pins the classes that exist rather than the number of them. A class added
// later is a new refusal and not a changed one, and nothing in this objective
// touched middleware.go.
func TestTheRefusalShapesAreTheOnesFromBeforeTheAuthorizationServer(t *testing.T) {
	t.Run("the class each refusal is logged under, and the challenge it carries", func(t *testing.T) {
		for _, tt := range []struct {
			class      string
			wire       string
			challenged bool
		}{
			{failureAbsentHeader, "absent_header", true},
			{failureRepeatedHeader, "repeated_header", true},
			{failureMalformedHeader, "malformed_header", true},
			{failureTokenRejected, "token_rejected", true},
			{failureUnavailable, "validation_unavailable", false},
			{failureNotAllowlisted, "identity_not_allowlisted", false},
			{failureNoEmailInToken, "no_email_in_token", false},
			{failureEmailUnverified, "email_unverified", false},
			{failureNoTokenValidation, "no_validator", false},
			{failureNoSealedCredentialValidation, "no_sealer", false},
			{failureSealedCredentialExpired, "sealed_credential_expired", true},
			{failureSealedCredentialCorrupt, "sealed_credential_corrupt", true},
			{failureSealedCredentialWrongPurpose, "sealed_credential_wrong_purpose", true},
		} {
			t.Run(tt.wire, func(t *testing.T) {
				if tt.class != tt.wire {
					t.Errorf("a refusal of this kind is now logged as %q and was logged as %q; the class is what an operator filters on and what this server's own diagnosis is written against",
						tt.class, tt.wire)
				}
				if got := challengesTheCredential(tt.class); got != tt.challenged {
					t.Errorf("challengesTheCredential(%q) = %v, want %v: whether this class sends a client back to reauthorize is not something this objective may change",
						tt.wire, got, tt.challenged)
				}
				want := ""
				if tt.challenged {
					want = challengeBeforeTheAuthorizationServer
				}
				if got := challengeFor(t, tt.class); got != want {
					t.Errorf("challengeFor(%q) = %q, want %q", tt.wire, got, want)
				}
			})
		}
	})

	t.Run("what the Google bearer path answers", func(t *testing.T) {
		for _, tt := range []struct {
			name          string
			tokeninfo     func(http.ResponseWriter, *http.Request)
			authorization []string
			status        int
			class         string
			challenge     []string
			authRefusal   string
		}{
			{
				name:      "a request carrying no credential",
				tokeninfo: respondWith(http.StatusOK, acceptedBody("one@example.test")),
				status:    http.StatusUnauthorized, class: "absent_header",
				challenge: []string{challengeBeforeTheAuthorizationServer},
			},
			{
				name:          "a token Google refuses",
				tokeninfo:     respondWith(http.StatusBadRequest, `{"error":"invalid_token"}`),
				authorization: []string{"Bearer ya29.a-token"},
				status:        http.StatusUnauthorized, class: "token_rejected",
				challenge: []string{challengeBeforeTheAuthorizationServer},
			},
			{
				name:          "an endpoint that is throttling this deployment",
				tokeninfo:     respondWith(http.StatusTooManyRequests, `{"error":"rate_limited"}`),
				authorization: []string{"Bearer ya29.a-token"},
				status:        http.StatusUnauthorized, class: "validation_unavailable",
			},
			{
				name:          "an identity outside the allowlist",
				tokeninfo:     respondWith(http.StatusOK, acceptedBody("stranger@example.test")),
				authorization: []string{"Bearer ya29.a-token"},
				status:        http.StatusForbidden, class: "identity_not_allowlisted",
				authRefusal: refusalBeforeTheAuthorizationServer,
			},
			{
				name:          "an allowlisted address Google has not verified",
				tokeninfo:     respondWith(http.StatusOK, tokeninfoBody(testClientID, testClientID, "sub-1", "one@example.test", "3599", "false")),
				authorization: []string{"Bearer ya29.a-token"},
				status:        http.StatusForbidden, class: "email_unverified",
				authRefusal: refusalBeforeTheAuthorizationServer,
			},
			{
				name:          "a token Google returned no address with",
				tokeninfo:     respondWith(http.StatusOK, fmt.Sprintf(`{"aud":%q,"azp":%q,"sub":"sub-1","exp":3599,"email_verified":true}`, testClientID, testClientID)),
				authorization: []string{"Bearer ya29.a-token"},
				status:        http.StatusForbidden, class: "no_email_in_token",
				authRefusal: refusalBeforeTheAuthorizationServer,
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeTokeninfo(t, tt.tokeninfo)
				h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

				resp := h.get(t, tt.authorization...)
				h.assertRefusalShape(t, resp, tt.status, tt.class, tt.challenge, tt.authRefusal)
			})
		}
	})

	t.Run("what the sealed access path answers", func(t *testing.T) {
		for _, tt := range []struct {
			name        string
			seal        func(*Sealer, time.Time) (string, error)
			advance     time.Duration
			status      int
			class       string
			challenge   []string
			authRefusal string
		}{
			{
				name: "a sealed access credential that has expired",
				seal: func(s *Sealer, now time.Time) (string, error) {
					return s.SealAccess(AccessCredential{Subject: "sub-1", Email: "one@example.test", Verified: true, ExpiresAt: now.Add(time.Hour)})
				},
				advance: time.Hour,
				status:  http.StatusUnauthorized, class: "sealed_credential_expired",
				challenge: []string{challengeBeforeTheAuthorizationServer},
			},
			{
				name: "a refresh credential presented as access",
				seal: func(s *Sealer, _ time.Time) (string, error) {
					return s.SealRefresh(RefreshCredential{UpstreamSecret: "upstream-refresh-secret"})
				},
				status: http.StatusUnauthorized, class: "sealed_credential_wrong_purpose",
				challenge: []string{challengeBeforeTheAuthorizationServer},
			},
			{
				name: "a sealed identity outside the allowlist",
				seal: func(s *Sealer, now time.Time) (string, error) {
					return s.SealAccess(AccessCredential{Subject: "sub-1", Email: "stranger@example.test", Verified: true, ExpiresAt: now.Add(time.Hour)})
				},
				status: http.StatusForbidden, class: "identity_not_allowlisted",
				authRefusal: refusalBeforeTheAuthorizationServer,
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				clock := newClock()
				// Answering 500 to anything: a sealed credential is decided locally, so a
				// refusal that needed Google would show up here as the wrong class.
				f := newFakeTokeninfo(t, respondWith(http.StatusInternalServerError, ""))
				cfg := allowlistOf("one@example.test")
				h := serveBehindAuthAt(t, cfg, f, clock.now)
				sealed, err := tt.seal(testSealer(t, cfg.SealingSecret), clock.now())
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				clock.advance(tt.advance)

				resp := h.get(t, "Bearer "+sealed)
				h.assertRefusalShape(t, resp, tt.status, tt.class, tt.challenge, tt.authRefusal)
				if got := f.requests.Load(); got != 0 {
					t.Errorf("Tokeninfo saw %d requests for a sealed credential, want 0", got)
				}
			})
		}
	})
}

// TestABearerValueWithoutTheSealedMarkerStillUsesGoogleValidation is acceptance
// criterion 9's routing boundary. A token beginning with bare cdb is deliberately
// Google-shaped here: it used to be misclassified by the three-character marker.
func TestABearerValueWithoutTheSealedMarkerStillUsesGoogleValidation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		token string
	}{
		{"a bare cdb-prefixed Google-shaped token", "cdb-google-shaped-token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			resp := h.get(t, "Bearer "+tt.token)
			if resp.StatusCode != handlerReached {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d (%s), want the protected handler to have answered", resp.StatusCode, body)
			}
			if got := f.presented(); len(got) != 1 || got[0] != tt.token {
				t.Errorf("Tokeninfo received %q, want only %q", got, tt.token)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

// TestAMiddlewareWithNothingToValidateWithAdmitsNobody pins the direction the one
// construction mistake this type can still be made with fails in.
//
// [NewMiddleware] cannot produce it. What can is a future edit that builds the
// middleware and the validator separately and gets the order wrong, and the
// difference between the two directions is a server that refuses everybody and a
// server that refuses nobody while looking authenticated.
func TestAMiddlewareWithNothingToValidateWithAdmitsNobody(t *testing.T) {
	appLog := &bytes.Buffer{}
	var reached atomic.Int64
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) })
	server := httptest.NewServer(newMiddleware(allowlistOf("one@example.test"), zerolog.New(appLog), nil)(next))
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer ya29.a-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if reached.Load() != 0 {
		t.Error("the protected handler ran behind a middleware that could not validate anything")
	}
	if !strings.Contains(appLog.String(), failureNoTokenValidation) {
		t.Errorf("the rejection is not logged as %s: %s", failureNoTokenValidation, appLog)
	}
}

// TestAMiddlewareWithNothingToUnsealAdmitsNobody pins the same fail-closed
// direction for a missing local sealer. Unlike a corrupt credential, this is a
// construction mistake, so its 401 must not tell the caller to reauthorize.
func TestAMiddlewareWithNothingToUnsealAdmitsNobody(t *testing.T) {
	for _, tt := range []struct {
		name string
	}{
		{"a sealed credential"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			appLog := &bytes.Buffer{}
			var reached atomic.Int64
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) })
			cfg := allowlistOf("one@example.test")
			sealer := testSealer(t, cfg.SealingSecret)
			sealed, err := sealer.SealAccess(AccessCredential{Subject: "sub-1", Email: "one@example.test", Verified: true, ExpiresAt: testNow.Add(time.Hour)})
			if err != nil {
				t.Fatalf("SealAccess: %v", err)
			}
			guarded := newMiddlewareWithSealer(cfg, zerolog.New(appLog), nil, nil, time.Now)(next)
			req := httptest.NewRequest(http.MethodPost, "http://example.test", nil)
			req.Header.Set("Authorization", "Bearer "+sealed)
			resp := httptest.NewRecorder()
			guarded.ServeHTTP(resp, req)

			if resp.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.Code)
			}
			if got := resp.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want none for a construction mistake", got)
			}
			if reached.Load() != 0 {
				t.Error("the protected handler ran behind a middleware that could not unseal anything")
			}
			if !strings.Contains(appLog.String(), failureNoSealedCredentialValidation) {
				t.Errorf("the rejection is not logged as %s: %s", failureNoSealedCredentialValidation, appLog)
			}
			if got := req.Header.Values("Authorization"); len(got) != 0 {
				t.Errorf("the request still carries an Authorization header after the middleware answered: %q", got)
			}
		})
	}
}

// TestTheTokenNeverAppearsInTheApplicationLogInAnyForm is acceptance criterion 6's
// behavioural half. Its source half — the claim over every code path rather than
// over the ones this test takes — is TestTheRawTokenNeverReachesALogger in
// guards_test.go, and neither substitutes for the other.
func TestTheTokenNeverAppearsInTheApplicationLogInAnyForm(t *testing.T) {
	// Distinctive enough that any fragment of it in the log is unambiguous, and
	// shaped like a Google access token so that a redaction keyed on the prefix
	// would be exercised.
	const token = "ya29.a0AfB_QUARANTINE-9x7Kq2ZmVbNpLrTsWyXcDfGhJkMnPqRt-EVIDENCE"
	sum := sha256.Sum256([]byte(token))
	hashed := hex.EncodeToString(sum[:])

	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"a token Tokeninfo rejects", http.StatusBadRequest, `{"error":"invalid_token"}`},
		{"a token for another audience", http.StatusOK,
			tokeninfoBody("other.apps.googleusercontent.com", testClientID, "sub-1", "one@example.test", "3599", "true")},
		{"an identity that is not allowlisted", http.StatusOK, acceptedBody("stranger@example.test")},
		{"an endpoint that is throttling", http.StatusTooManyRequests, ``},
		{"an identity that is admitted", http.StatusOK, acceptedBody("one@example.test")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(tt.status, tt.body))
			h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

			_ = h.get(t, "Bearer "+token)

			logged := h.appLog.String()
			// Every substring of this length, not just the token whole: a truncated or
			// prefixed rendering is the way a credential actually escapes into a log.
			const fragment = 8
			for i := 0; i+fragment <= len(token); i++ {
				if piece := token[i : i+fragment]; strings.Contains(logged, piece) {
					t.Fatalf("the application log contains %q, a fragment of the presented token: %s", piece, logged)
				}
			}
			// The hash is permitted as a cache key and is still not logged: it is a
			// stable identifier for a credential, and correlating it across lines is
			// not something this log needs to support.
			if strings.Contains(logged, hashed) {
				t.Errorf("the application log contains the token's SHA-256: %s", logged)
			}
		})
	}
}

// TestEveryValidatorBoundSurfacesAsUnauthorizedRatherThanAHangOrAPanic is
// acceptance criterion 8 from the caller's side. Each of these is a way for
// Google's endpoint to misbehave, and the only acceptable answer to all of them is
// the same 401 a bad token gets — not a stalled request, and not a 500 from a
// panicking handler.
func TestEveryValidatorBoundSurfacesAsUnauthorizedRatherThanAHangOrAPanic(t *testing.T) {
	t.Run("an endpoint that redirects the request elsewhere", func(t *testing.T) {
		f := newFakeTokeninfo(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://tokeninfo.invalid/tokeninfo", http.StatusFound)
		})
		h := serveBehindAuth(t, allowlistOf("one@example.test"), f)
		h.assertRejected(t, h.get(t, "Bearer ya29.a-token"), http.StatusUnauthorized, failureUnavailable)
	})

	t.Run("an endpoint that answers past the size cap", func(t *testing.T) {
		padding := strings.Repeat("p", responseLimit+1)
		body := fmt.Sprintf(`{"aud":%q,"azp":%q,"sub":"sub-1","exp":3599,"email":"one@example.test","email_verified":true,"padding":%q}`,
			testClientID, testClientID, padding)
		f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
		h := serveBehindAuth(t, allowlistOf("one@example.test"), f)
		h.assertRejected(t, h.get(t, "Bearer ya29.a-token"), http.StatusUnauthorized, failureUnavailable)
	})

	t.Run("an endpoint that does not answer", func(t *testing.T) {
		release := make(chan struct{})
		f := newFakeTokeninfo(t, func(w http.ResponseWriter, _ *http.Request) {
			<-release
		})
		// After the server, so that it runs before the server's own Close: cleanups
		// run last-registered-first, and httptest.Server.Close waits for a handler
		// that is still blocked.
		t.Cleanup(func() { close(release) })
		h := serveBehindAuthWithin(t, allowlistOf("one@example.test"), f, 100*time.Millisecond)

		done := make(chan *http.Response, 1)
		go func() { done <- h.get(t, "Bearer ya29.a-token") }()
		select {
		case resp := <-done:
			h.assertRejected(t, resp, http.StatusUnauthorized, failureUnavailable)
		case <-time.After(10 * time.Second):
			t.Fatal("the request never came back; an endpoint that never answers must not hold an inbound request open")
		}
	})

	t.Run("more concurrent callers than there are validation slots", func(t *testing.T) {
		var once sync.Once
		release := make(chan struct{})
		releaseAll := func() { once.Do(func() { close(release) }) }
		f := newFakeTokeninfo(t, func(w http.ResponseWriter, _ *http.Request) {
			<-release
			_, _ = w.Write([]byte(acceptedBody("one@example.test")))
		})
		// Released on cleanup as well as at the end, so that a failure part-way
		// through fails the test instead of hanging httptest's own Close on a handler
		// that is still blocked — and registered after the server so that it runs
		// first, cleanups being last-registered-first.
		t.Cleanup(releaseAll)
		h := serveBehindAuth(t, allowlistOf("one@example.test"), f)

		// Every slot is filled and held, so the next caller has to be shed rather
		// than queued behind them. These callers do not use the harness's own
		// request helper, because it reports a transport failure with t.Fatalf and
		// that is not usable from a goroutine that is not the test's.
		var wg sync.WaitGroup
		for i := range maxConcurrentValidations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodPost, h.url, nil)
				if err != nil {
					return
				}
				req.Header.Set("Authorization", fmt.Sprintf("Bearer ya29.slot-token-%d", i))
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
		}
		waitUntil(t, func() bool { return f.inFlight.Load() == int64(maxConcurrentValidations) }, 10*time.Second,
			"all validation slots to be occupied")

		resp := h.get(t, "Bearer ya29.one-too-many")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401: a caller that cannot be validated now is refused, not queued", resp.StatusCode)
		}
		if got := h.reached.Load(); got != 0 {
			t.Errorf("the protected handler ran %d times, want 0", got)
		}
		releaseAll()
		wg.Wait()
	})
}

func waitUntil(t *testing.T, cond func() bool, within time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}
