package authflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

const (
	// The three sentinels. Each is a value that must never appear on a channel a
	// person or a third party reads, and each is distinctive enough that a leak
	// is a substring match rather than a judgement.
	testClientSecret  = "client-secret-must-never-render"
	testRefreshToken  = "refresh-token-must-never-render"
	testSealingSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	testClientID    = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"
	testRedirectURI = "https://client.example.test/callback"
	testClientState = "client-state"
	testAccessToken = "Google-access-token"

	// Where a redirect from the fake Google points. Nothing this process sends may
	// ever arrive here: the fake serves every host, so a request recorded against
	// this one is a request the HTTP client followed a 3xx to.
	redirectTrapHost = "redirect-trap.example.test"
	redirectTrapURL  = "https://" + redirectTrapHost + "/collect"
)

// sentGoogle is one request the fake received, kept as text: everything this
// process put on the wire to a third party, which is what the ADR about a sealed
// value never reaching one is graded against.
type sentGoogle struct {
	url  string
	body string
}

type fakeGoogle struct {
	mu          sync.Mutex
	requests    []sentGoogle
	identity    googleIdentity
	refresh     string
	accessToken string
	// The redirect fields are set before the fake is used and read-only after.
	// redirectFrom is the path that answers 3xx instead of a token or an identity.
	redirectFrom   string
	redirectStatus int
	redirectTo     string
}

func newFakeGoogle(t *testing.T, identity googleIdentity, refresh string) *fakeGoogle {
	t.Helper()
	return &fakeGoogle{identity: identity, refresh: refresh, accessToken: testAccessToken}
}

func (f *fakeGoogle) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeGoogle) snapshot() []sentGoogle {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentGoogle(nil), f.requests...)
}

func (f *fakeGoogle) RoundTrip(r *http.Request) (*http.Response, error) {
	var sent []byte
	if r.Body != nil {
		read, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		sent = read
	}
	f.mu.Lock()
	f.requests = append(f.requests, sentGoogle{url: r.URL.String(), body: string(sent)})
	f.mu.Unlock()
	if f.redirectStatus != 0 && r.URL.Path == f.redirectFrom {
		// The Location keeps the request's query, which is what makes the tokeninfo
		// case a leak worth refusing: the access token is in that query, and a
		// client that follows the redirect re-sends it to the target.
		location := f.redirectTo
		if r.URL.RawQuery != "" {
			location += "?" + r.URL.RawQuery
		}
		header := make(http.Header)
		header.Set("Location", location)
		return &http.Response{
			StatusCode: f.redirectStatus,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	}
	status := http.StatusOK
	var body string
	switch r.URL.Path {
	case "/token":
		body = `{"access_token":"` + f.accessToken + `","refresh_token":"` + f.refresh + `"}`
	case "/tokeninfo":
		encoded, err := json.Marshal(f.identity)
		if err != nil {
			return nil, err
		}
		body = string(encoded)
	default:
		status = http.StatusNotFound
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func testConfig() Config {
	return Config{
		ClientSecret:       auth.Secret(testClientSecret),
		PublicBaseURL:      "https://public.example.test/",
		ClientRedirectURIs: []string{testRedirectURI},
	}
}

func testAuthentication() auth.Config {
	return auth.Config{
		ClientID:      testClientID,
		AllowedEmails: []string{"one@example.test"},
		SealingSecret: auth.Secret(testSealingSecret),
	}
}

func testEndpoints() endpoints {
	return endpoints{
		authorizeURL: "https://google.example.test/authorize",
		tokenURL:     "https://google.example.test/token",
		tokeninfoURL: "https://google.example.test/tokeninfo",
	}
}

// testClient is the production client with the fake transport underneath it, and
// not a bare http.Client, so that every test here drives the redirect refusal the
// real one carries rather than a client only tests ever build.
func testClient(fake *fakeGoogle) *http.Client {
	client := newHTTPClient(exchangeTimeout)
	client.Transport = fake
	return client
}

// permissiveRedirectClient is the client the presence check could not tell from
// the production one: it has a CheckRedirect, and that CheckRedirect follows
// every redirect it is asked about.
func permissiveRedirectClient(fake *fakeGoogle) *http.Client {
	return &http.Client{
		Transport:     fake,
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
	}
}

func testHandlers(t *testing.T, fake *fakeGoogle, logWriter io.Writer) *Handlers {
	t.Helper()
	handlers, err := newHandlers(testConfig(), testAuthentication(), testEndpoints(), testClient(fake), zerolog.New(logWriter))
	if err != nil {
		t.Fatalf("newHandlers: %v", err)
	}
	return handlers
}

func authorizationRequest(t *testing.T, handlers *Handlers, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, AuthorizationPath+"?"+url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {testClientState},
		"code_challenge":        {"client-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	recorder := httptest.NewRecorder()
	handlers.AuthorizationHandler().ServeHTTP(recorder, request)
	return recorder
}

func callbackRequest(t *testing.T, handlers *Handlers, state string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, CallbackPath+"?"+url.Values{"code": {"Google-code"}, "state": {state}}.Encode(), nil)
	recorder := httptest.NewRecorder()
	handlers.CallbackHandler().ServeHTTP(recorder, request)
	return recorder
}

func stateFromAuthorization(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorization Location: %v", err)
	}
	return target.Query().Get("state")
}

func TestConfigurationRequiresAUsableCallbackAndClientRegistry(t *testing.T) {
	for _, tt := range []struct {
		name     string
		change   map[string]string
		want     error
		variable string
	}{
		{"missing client secret", map[string]string{"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET": ""}, ErrNoGoogleClientMaterial, "CERBERUS_AUTH_GOOGLE_CLIENT_SECRET"},
		{"client secret with whitespace", map[string]string{"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET": "not usable\n"}, ErrInvalidVariable, "CERBERUS_AUTH_GOOGLE_CLIENT_SECRET"},
		{"missing public base URL", map[string]string{"CERBERUS_AUTH_PUBLIC_BASE_URL": ""}, ErrNoPublicBaseURL, "CERBERUS_AUTH_PUBLIC_BASE_URL"},
		{"non HTTPS public base URL", map[string]string{"CERBERUS_AUTH_PUBLIC_BASE_URL": "http://public.example.test"}, ErrInvalidVariable, "CERBERUS_AUTH_PUBLIC_BASE_URL"},
		{"empty client registry", map[string]string{"CERBERUS_AUTH_CLIENT_REDIRECT_URIS": ""}, ErrNoClientRedirectURIs, "CERBERUS_AUTH_CLIENT_REDIRECT_URIS"},
		{"relative registered redirect", map[string]string{"CERBERUS_AUTH_CLIENT_REDIRECT_URIS": "/callback"}, ErrInvalidVariable, "CERBERUS_AUTH_CLIENT_REDIRECT_URIS"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			environ := map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET": testClientSecret,
				"CERBERUS_AUTH_PUBLIC_BASE_URL":      "https://public.example.test",
				"CERBERUS_AUTH_CLIENT_REDIRECT_URIS": testRedirectURI,
			}
			for name, value := range tt.change {
				environ[name] = value
			}
			config, err := LoadConfigFrom(environ)
			if !errors.Is(err, tt.want) || config != nil {
				t.Fatalf("LoadConfigFrom = (%+v, %v), want an error wrapping %v", config, err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.variable) {
				t.Errorf("the refusal does not name %s: %s", tt.variable, err)
			}
			for _, value := range environ {
				if value != "" && strings.Contains(err.Error(), value) {
					t.Errorf("the refusal renders a supplied value: %s", err)
				}
			}
		})
	}
}

func TestAuthorizationRefusesUnregisteredRedirectURIsBeforeGoogle(t *testing.T) {
	fake := newFakeGoogle(t, googleIdentity{Subject: "sub-1", Email: "one@example.test", Verified: true}, "refresh")
	handlers := testHandlers(t, fake, io.Discard)
	for _, tt := range []struct {
		name     string
		redirect string
		want     int
	}{
		{"the configured URI", testRedirectURI, http.StatusFound},
		{"a different host", "https://attacker.example.test/callback", http.StatusBadRequest},
		{"a different scheme", "http://client.example.test/callback", http.StatusBadRequest},
		{"an appended path", testRedirectURI + "/steal", http.StatusBadRequest},
		{"a userinfo prefix", "https://client.example.test@attacker.example.test/callback", http.StatusBadRequest},
		{"a trailing segment on an accepted prefix", "https://client.example.test/callback/next", http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := fake.requestCount()
			response := authorizationRequest(t, handlers, tt.redirect)
			if response.Code != tt.want {
				t.Errorf("status = %d, want %d", response.Code, tt.want)
			}
			if tt.want != http.StatusFound && response.Header().Get("Location") != "" {
				t.Error("a refused authorization request has a Location header")
			}
			if got := fake.requestCount(); got != before {
				t.Errorf("Google received %d requests for a refused redirect URI, want none", got-before)
			}
		})
	}
}

func TestAuthorizationSendsGoogleTheOfflineConsentPKCERequest(t *testing.T) {
	fake := newFakeGoogle(t, googleIdentity{}, "refresh")
	handlers := testHandlers(t, fake, io.Discard)
	response := authorizationRequest(t, handlers, testRedirectURI)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	values := target.Query()
	if target.Scheme != "https" || target.Host != "google.example.test" {
		t.Errorf("Location = %q, want the fake Google authorization endpoint", target)
	}
	if values.Get("access_type") != "offline" || values.Get("prompt") != "consent" {
		t.Errorf("Google authorization parameters = %q, want access_type=offline and prompt=consent", values)
	}
	if values.Get("scope") != googleScopes {
		t.Errorf("scope = %q, want %q", values.Get("scope"), googleScopes)
	}
	if values.Get("redirect_uri") != "https://public.example.test"+CallbackPath {
		t.Errorf("redirect_uri = %q, want this server's callback", values.Get("redirect_uri"))
	}
	if values.Get("code_challenge_method") != "S256" || values.Get("code_challenge") == "" {
		t.Errorf("Google PKCE = challenge %q, method %q, want an S256 challenge", values.Get("code_challenge"), values.Get("code_challenge_method"))
	}
	state := values.Get("state")
	if state == "" || !strings.HasPrefix(state, statePrefix) || strings.Contains(target.String(), testClientState) {
		t.Errorf("state = %q, want a sealed state that does not expose the client state", state)
	}
	decoded, err := handlers.flow.unsealState(state)
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	sum := sha256.Sum256([]byte(decoded.GoogleCodeVerifier))
	if got, want := values.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("code_challenge = %q, want S256 of the verifier held only in sealed state", got)
	}
}

func TestCallbackRefusesUnallowlistedAndUnverifiedIdentities(t *testing.T) {
	for _, tt := range []struct {
		name     string
		identity googleIdentity
	}{
		{"an identity outside the allowlist", googleIdentity{Subject: "sub-outside", Email: "outside@example.test", Verified: true}},
		{"an identity whose email is not verified", googleIdentity{Subject: "sub-unverified", Email: "one@example.test", Verified: false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeGoogle(t, tt.identity, "refresh")
			handlers := testHandlers(t, fake, io.Discard)
			authorization := authorizationRequest(t, handlers, testRedirectURI)
			response := callbackRequest(t, handlers, stateFromAuthorization(t, authorization))
			if response.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
			if response.Header().Get("Location") != "" {
				t.Error("forbidden callback redirects to the client")
			}
			if strings.Contains(response.Body.String(), "cdb1:") {
				t.Error("forbidden callback body resembles a sealed credential")
			}
		})
	}
}

// completedFlow drives an authorization and its callback all the way through
// against the fake, and returns what a leak would have to show up in.
type completedFlow struct {
	handlers    *Handlers
	fake        *fakeGoogle
	toGoogle    string
	log         string
	body        string
	location    string
	sealedCode  string
	clientState string
}

// thirdParty is everything this process put in front of Google: the browser
// redirect it sends to Google's authorization endpoint, and every request it
// makes to Google itself. Each is included decoded as well as raw, because a
// value inside a query string is percent-encoded and a leak that only a
// substring search would find has to survive the encoding.
func thirdParty(googleAuthorization string, requests []sentGoogle) string {
	var out strings.Builder
	writeRawAndDecoded(&out, googleAuthorization)
	for _, request := range requests {
		writeRawAndDecoded(&out, request.url)
		writeRawAndDecoded(&out, request.body)
	}
	return out.String()
}

func writeRawAndDecoded(out *strings.Builder, raw string) {
	out.WriteString(raw)
	out.WriteString("\n")
	if decoded, err := url.QueryUnescape(raw); err == nil {
		out.WriteString(decoded)
		out.WriteString("\n")
	}
}

func completeFlow(t *testing.T) completedFlow {
	t.Helper()
	fake := newFakeGoogle(t, googleIdentity{Subject: "sub-1", Email: "one@example.test", Verified: true}, testRefreshToken)
	var capturedLog bytes.Buffer
	handlers := testHandlers(t, fake, &capturedLog)
	authorization := authorizationRequest(t, handlers, testRedirectURI)
	response := callbackRequest(t, handlers, stateFromAuthorization(t, authorization))
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	location := response.Header().Get("Location")
	target, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	sealed := target.Query().Get("code")
	if sealed == "" {
		t.Fatal("the client redirect carries no authorization code")
	}
	return completedFlow{
		handlers:    handlers,
		fake:        fake,
		toGoogle:    thirdParty(authorization.Header().Get("Location"), fake.snapshot()),
		log:         capturedLog.String(),
		body:        response.Body.String(),
		location:    location,
		sealedCode:  sealed,
		clientState: target.Query().Get("state"),
	}
}

// TestTheClientRedirectReturnsTheClientsOwnState is here because nothing else in
// this package can see the state come back, and the client that would notice is
// real Google's other side of the flow: every OAuth client rejects a callback
// whose state does not match the one it sent, so dropping it turns green here
// into a failure the operator meets in a browser with nothing naming the cause.
func TestTheClientRedirectReturnsTheClientsOwnState(t *testing.T) {
	flow := completeFlow(t)
	if flow.clientState != testClientState {
		t.Errorf("state on the client redirect = %q, want %q, the state the authorization request sent", flow.clientState, testClientState)
	}
}

func TestWholeFlowRendersNoneOfTheThreeValuesItMustNot(t *testing.T) {
	flow := completeFlow(t)
	if !strings.Contains(flow.log, "an authorization code was issued") {
		t.Fatalf("the flow did not write its safe completion log line, so the assertions below are over an empty log: %q", flow.log)
	}
	for _, tt := range []struct {
		name     string
		value    string
		channels map[string]string
	}{
		{
			// Google's refresh token: nothing this server writes may carry it,
			// and the client is given a sealed code instead of the token itself.
			name:  "the Google refresh token",
			value: testRefreshToken,
			channels: map[string]string{
				"the captured log":        flow.log,
				"the response body":       flow.body,
				"the Location header":     flow.location,
				"what was sent to Google": flow.toGoogle,
			},
		},
		{
			// This deployment's Google client secret. It legitimately travels in
			// the token endpoint's request body, so that channel is not asserted
			// on here; everywhere a client or an operator reads is.
			name:  "this deployment's Google client secret",
			value: testClientSecret,
			channels: map[string]string{
				"the captured log":    flow.log,
				"the response body":   flow.body,
				"the Location header": flow.location,
			},
		},
		{
			// The sealed authorization code is a replayable credential carrying
			// the sealed refresh token for its whole lifetime. It belongs in the
			// Location, and in the body http.Redirect writes out of it, and
			// nowhere else — a log a person or a log shipper reads least of all.
			name:  "the sealed authorization code",
			value: flow.sealedCode,
			channels: map[string]string{
				"the captured log": flow.log,
			},
		},
		{
			// ADR 01M069V70NEKXXPSQ3HDTAVPS3: nothing carrying this server's own
			// credential marker goes to a third party. This is the assertion the
			// reasoning at [statePrefix] is graded by.
			name:  "this server's sealed-credential marker",
			value: "cdb1:",
			channels: map[string]string{
				"the captured log":        flow.log,
				"what was sent to Google": flow.toGoogle,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for name, rendered := range tt.channels {
				if rendered == "" {
					t.Fatalf("%s is empty, so asserting %s is absent from it proves nothing", name, tt.name)
				}
				if strings.Contains(rendered, tt.value) {
					t.Errorf("%s appears in %s", tt.name, name)
				}
			}
		})
	}
}

// TestCallbackReportsBothLengths is acceptance criterion 4's
// local half: the figures the real run against Google is graded on, and the two
// open questions about whether a sealed Google refresh token fits in a redirect
// URL's query string, come out of these two fields.
func TestCallbackReportsBothLengths(t *testing.T) {
	flow := completeFlow(t)
	var reported map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(flow.log)), &reported); err != nil {
		t.Fatalf("the completion log line is not one JSON object: %v in %q", err, flow.log)
	}
	for _, tt := range []struct {
		field string
		want  int
	}{
		{"google_refresh_token_bytes", len(testRefreshToken)},
		{"authorization_code_bytes", len(flow.sealedCode)},
	} {
		got, ok := reported[tt.field].(float64)
		if !ok {
			t.Errorf("the completion log line carries no numeric %s: %v", tt.field, reported)
			continue
		}
		if int(got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.field, int(got), tt.want)
		}
	}
}

func TestTheAuthorizationCodeCarriesTheRefreshTokenAndTheClientPKCE(t *testing.T) {
	flow := completeFlow(t)
	credential, err := flow.handlers.flow.sealer.UnsealAuthorizationCode(flow.sealedCode)
	if err != nil {
		t.Fatalf("unseal authorization code: %v", err)
	}
	if !reflect.DeepEqual(credential, auth.AuthorizationCodeCredential{
		UpstreamSecret:      testRefreshToken,
		Subject:             "sub-1",
		Email:               "one@example.test",
		Verified:            true,
		CodeChallenge:       "client-challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           credential.ExpiresAt,
	}) {
		t.Errorf("authorization code credential = %#v, want the Google identity and client PKCE values", credential)
	}
}

// TestTheClientRefusesARedirectThatWouldForwardACredential is the only place this
// package can observe [newHTTPClient]'s CheckRedirect, and both rows are a real
// way a credential leaves: the tokeninfo request carries Google's access token in
// its URL, so a 302 whose Location keeps the query hands it to the target, and
// the token request carries this deployment's client secret in its body, which
// net/http re-sends on a 307 or a 308.
func TestTheClientRefusesARedirectThatWouldForwardACredential(t *testing.T) {
	for _, tt := range []struct {
		name string
		from string
		// status is the redirect the fake answers with, and credential is what
		// following it would have delivered to [redirectTrapURL].
		status     int
		credential string
	}{
		{"a 302 from the tokeninfo endpoint, whose URL carries the access token", "/tokeninfo", http.StatusFound, testAccessToken},
		{"a 307 from the token endpoint, which re-sends the request body", "/token", http.StatusTemporaryRedirect, testClientSecret},
		{"a 308 from the token endpoint, which re-sends the request body", "/token", http.StatusPermanentRedirect, testClientSecret},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeGoogle(t, googleIdentity{Subject: "sub-1", Email: "one@example.test", Verified: true}, testRefreshToken)
			fake.redirectFrom, fake.redirectStatus, fake.redirectTo = tt.from, tt.status, redirectTrapURL
			handlers := testHandlers(t, fake, io.Discard)
			authorization := authorizationRequest(t, handlers, testRedirectURI)
			response := callbackRequest(t, handlers, stateFromAuthorization(t, authorization))

			if response.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want %d: a 3xx from Google ends the exchange rather than being followed", response.Code, http.StatusBadGateway)
			}
			if response.Header().Get("Location") != "" {
				t.Error("a callback whose exchange was refused redirects the client anyway")
			}
			var delivered strings.Builder
			followed := 0
			for _, request := range fake.snapshot() {
				if !strings.Contains(request.url, redirectTrapHost) {
					continue
				}
				followed++
				writeRawAndDecoded(&delivered, request.url)
				writeRawAndDecoded(&delivered, request.body)
			}
			if followed != 0 {
				t.Errorf("the client followed %d redirect(s) to %s", followed, redirectTrapHost)
			}
			if strings.Contains(delivered.String(), tt.credential) {
				t.Errorf("the redirect target was delivered the credential the %d was pointed at", tt.status)
			}
			if fake.requestCount() == 0 {
				t.Fatal("the fake received no request at all, so nothing above is an assertion about a redirect")
			}
		})
	}
}

// TestTheFlowRefusesToBuildWithoutADependencyItNames covers the refusals an
// operator reads at startup: each names the one dependency that is missing, and
// the redirect-following client is refused here so that the defence above cannot
// be lost by handing in a client built somewhere else.
func TestTheFlowRefusesToBuildWithoutADependencyItNames(t *testing.T) {
	fake := newFakeGoogle(t, googleIdentity{}, testRefreshToken)
	for _, tt := range []struct {
		name   string
		change func(*auth.Config)
		client *http.Client
		want   error
	}{
		{"no Google OAuth client ID", func(c *auth.Config) { c.ClientID = "" }, testClient(fake), errNoClientID},
		{"an empty allowlist", func(c *auth.Config) { c.AllowedEmails = nil }, testClient(fake), errNoAllowlist},
		{"no HTTP client", nil, nil, errNoHTTPClient},
		// The two redirect rows are two different clients and not one written
		// twice. A client with no CheckRedirect at all follows redirects because
		// net/http's default does; a client whose CheckRedirect returns nil
		// follows them because it said so. The second was accepted for as long as
		// this refusal was a nil check, and the flow then handed Google's access
		// token to the host a 302 named — so the row exists to keep the refusal a
		// question about what the client does rather than about what it has.
		{"an HTTP client with no redirect check at all", nil, &http.Client{Transport: fake}, errRedirectingHTTPClient},
		{"an HTTP client whose redirect check permits every hop", nil, permissiveRedirectClient(fake), errRedirectingHTTPClient},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authentication := testAuthentication()
			if tt.change != nil {
				tt.change(&authentication)
			}
			handlers, err := newHandlers(testConfig(), authentication, testEndpoints(), tt.client, zerolog.New(io.Discard))
			if !errors.Is(err, tt.want) || handlers != nil {
				t.Fatalf("newHandlers returned handlers=%t and %v, want no handlers and an error wrapping %v", handlers != nil, err, tt.want)
			}
		})
	}
}

// TestTheRedirectCheckIsAskedWithArgumentsARealOneCanInspect is the other side of
// the row above: asking a CheckRedirect what it would do means calling it, and a
// call is only a fair question if the arguments are the ones net/http passes.
//
// Every row is a refusal a real deployment could plausibly have written, and each
// reads a different part of what it was handed — the hop's URL, the chain behind
// it, the response that caused it, the headers on it. A probe that left any of
// them empty would refuse a client that refuses every redirect, or panic inside
// it; each row's own observation is asserted so that a panic swallowed by the
// probe's recover shows up here as nothing having been read.
func TestTheRedirectCheckIsAskedWithArgumentsARealOneCanInspect(t *testing.T) {
	fake := newFakeGoogle(t, googleIdentity{}, testRefreshToken)
	for _, tt := range []struct {
		name string
		// observe returns what this CheckRedirect read before refusing, which must
		// come back non-empty.
		observe func(*http.Request, []*http.Request) string
	}{
		{"one that decides on the hop's target", func(r *http.Request, _ []*http.Request) string {
			return r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
		}},
		{"one that decides on the request line", func(r *http.Request, _ []*http.Request) string {
			return r.Method + " " + r.Host + " " + r.Proto
		}},
		{"one that counts the chain it was reached through", func(_ *http.Request, via []*http.Request) string {
			if len(via) == 0 {
				return ""
			}
			return via[0].URL.String()
		}},
		{"one that reads the response that caused the hop", func(r *http.Request, _ []*http.Request) string {
			if r.Response == nil {
				return ""
			}
			return r.Response.Status + r.Response.Header.Get("Location")
		}},
		{"one that writes a header onto the hop, which a nil map would panic on", func(r *http.Request, _ []*http.Request) string {
			r.Header.Set("X-Probe", "written")
			return r.Header.Get("X-Probe")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var seen string
			client := &http.Client{
				Transport: fake,
				CheckRedirect: func(r *http.Request, via []*http.Request) error {
					seen = tt.observe(r, via)
					return errors.New("redirects are refused")
				},
			}
			handlers, err := newHandlers(testConfig(), testAuthentication(), testEndpoints(), client, zerolog.New(io.Discard))
			if err != nil || handlers == nil {
				t.Fatalf("newHandlers returned handlers=%t and %v, want handlers and no error: a client that refuses every redirect is the one this flow is meant to run on", handlers != nil, err)
			}
			if seen == "" {
				t.Errorf("the redirect check read nothing; it was either never asked or asked with arguments too empty to decide on")
			}
		})
	}
}
