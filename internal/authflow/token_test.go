package authflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// Everything here runs against the fake Google flow_test.go already builds. The
// token endpoint's two grants are the last half of the flow those tests drive, and
// a second harness for them would be a second set of assumptions about what Google
// answers — which is the thing under test at a renewal.

// testCodeVerifier is the client's own PKCE secret. It is long and distinctive so
// that a leak of it into a log or a Google request is a substring match.
const testCodeVerifier = "client-code-verifier-must-never-render-and-is-long-enough-to-be-real"

// clientChallenge is the S256 challenge for a verifier, computed here rather than
// through the package's own pkceChallenge: a test that derives its expectation the
// same way the code does cannot notice the code changing, and this one is about the
// check the code makes.
func clientChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizedClient is one client that has been through /authorize and the callback
// and is holding an authorization code it has not spent.
type authorizedClient struct {
	handlers *Handlers
	fake     *fakeGoogle
	log      *bytes.Buffer
	code     string
}

func authorize(t *testing.T, fake *fakeGoogle) authorizedClient {
	t.Helper()
	captured := &bytes.Buffer{}
	handlers := testHandlers(t, fake, captured)
	return authorizeThrough(t, handlers, fake, captured)
}

// authorizeThrough is [authorize] over handlers the caller built, which the
// restart test needs: it has to mint against one instance and present against
// another.
func authorizeThrough(t *testing.T, handlers *Handlers, fake *fakeGoogle, captured *bytes.Buffer) authorizedClient {
	t.Helper()
	authorization := authorizationRequestFor(t, handlers, testRedirectURI, clientChallenge(testCodeVerifier))
	if authorization.Code != http.StatusFound {
		t.Fatalf("authorization status = %d, want %d", authorization.Code, http.StatusFound)
	}
	callback := callbackRequest(t, handlers, stateFromAuthorization(t, authorization))
	if callback.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d: %s", callback.Code, http.StatusFound, callback.Body)
	}
	target, err := url.Parse(callback.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	code := target.Query().Get("code")
	if code == "" {
		t.Fatal("the client redirect carries no authorization code")
	}
	return authorizedClient{handlers: handlers, fake: fake, log: captured, code: code}
}

func consentingIdentity() googleIdentity {
	return googleIdentity{Subject: "sub-1", Email: "one@example.test", Verified: true}
}

// post drives one request at the token endpoint, through the handler the routes
// mount rather than through a method a test picked.
func post(t *testing.T, handlers *Handlers, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	mounted(t, handlers, TokenPath).ServeHTTP(recorder, request)
	return recorder
}

// mounted is the handler this package says it serves at a path. Reaching the
// endpoints through [Handlers.Routes] rather than through their constructors is
// what makes these tests fail if a route stops being mounted.
func mounted(t *testing.T, handlers *Handlers, pattern string) http.Handler {
	t.Helper()
	for _, route := range handlers.Routes() {
		if route.Pattern == pattern {
			return route.Handler
		}
	}
	t.Fatalf("this package mounts no handler at %s; its routes are %v", pattern, patterns(handlers))
	return nil
}

func patterns(handlers *Handlers) []string {
	var out []string
	for _, route := range handlers.Routes() {
		out = append(out, route.Pattern)
	}
	return out
}

func codeGrant(code string) url.Values {
	return url.Values{
		"grant_type":    {grantAuthorizationCode},
		"code":          {code},
		"code_verifier": {testCodeVerifier},
		"redirect_uri":  {testRedirectURI},
	}
}

// issuedPair is a decoded token endpoint success response.
type issuedPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func decodePair(t *testing.T, response *httptest.ResponseRecorder) issuedPair {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body)
	}
	var pair issuedPair
	if err := json.Unmarshal(response.Body.Bytes(), &pair); err != nil {
		t.Fatalf("the token response is not JSON: %v in %s", err, response.Body)
	}
	return pair
}

// TestTheAuthorizationCodeGrantIssuesTheCredentialPair is acceptance criterion 1,
// end to end from /authorize through the callback to /token against the fake
// Google, with both returned values opened afterwards.
func TestTheAuthorizationCodeGrantIssuesTheCredentialPair(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	client := authorize(t, fake)

	response := post(t, client.handlers, codeGrant(client.code))
	pair := decodePair(t, response)

	if pair.TokenType != bearerTokenType {
		t.Errorf("token_type = %q, want %q", pair.TokenType, bearerTokenType)
	}
	if pair.ExpiresIn != int(time.Hour/time.Second) {
		t.Errorf("expires_in = %d, want %d", pair.ExpiresIn, int(time.Hour/time.Second))
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: this body is a credential pair", got)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	sealer := client.handlers.flow.sealer
	access, err := sealer.UnsealAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("the access_token does not unseal as an access credential: %v", err)
	}
	if access.Subject != "sub-1" || access.Email != "one@example.test" || !access.Verified {
		t.Errorf("access credential = %#v, want the identity that consented", access)
	}
	if remaining := time.Until(access.ExpiresAt); remaining <= 55*time.Minute || remaining > time.Hour {
		t.Errorf("the access credential expires in %s, want about an hour", remaining)
	}
	renewal, err := sealer.UnsealRefresh(pair.RefreshToken)
	if err != nil {
		t.Fatalf("the refresh_token does not unseal as a refresh credential: %v", err)
	}
	if renewal.UpstreamSecret != testRefreshToken {
		t.Error("the refresh credential does not carry the Google refresh token the callback was given")
	}
}

// TestTheAuthorizationCodeGrantRefusesInOAuthsOwnShape is acceptance criterion 2:
// one row per way a code can fail to be exchangeable, each answered 400 with
// invalid_grant and issuing nothing.
//
// Every row builds its value with this package's real sealer, so what is being
// checked is the endpoint's decision and not a string a test made up.
func TestTheAuthorizationCodeGrantRefusesInOAuthsOwnShape(t *testing.T) {
	for _, tt := range []struct {
		name string
		// present returns the form to post, given a client holding a fresh,
		// unspent authorization code.
		present func(*testing.T, authorizedClient) url.Values
	}{
		{
			name: "a code_verifier that does not hash to the sealed challenge",
			present: func(_ *testing.T, client authorizedClient) url.Values {
				form := codeGrant(client.code)
				form.Set("code_verifier", testCodeVerifier+"-not-the-one")
				return form
			},
		},
		{
			name: "a code past its five-minute expiry",
			present: func(t *testing.T, client authorizedClient) url.Values {
				sealed, err := client.handlers.flow.sealer.SealAuthorizationCode(auth.AuthorizationCodeCredential{
					UpstreamSecret:      testRefreshToken,
					Subject:             "sub-1",
					Email:               "one@example.test",
					Verified:            true,
					CodeChallenge:       clientChallenge(testCodeVerifier),
					CodeChallengeMethod: challengeMethod,
					ExpiresAt:           time.Now().Add(-time.Second),
				})
				if err != nil {
					t.Fatalf("SealAuthorizationCode: %v", err)
				}
				return codeGrant(sealed)
			},
		},
		{
			name: "a value that is not a sealed credential at all",
			present: func(_ *testing.T, _ authorizedClient) url.Values {
				return codeGrant("not-a-sealed-credential")
			},
		},
		{
			name: "an access credential presented as a code",
			present: func(t *testing.T, client authorizedClient) url.Values {
				sealed, err := client.handlers.flow.sealer.SealAccess(auth.AccessCredential{
					Subject: "sub-1", Email: "one@example.test", Verified: true,
					ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatalf("SealAccess: %v", err)
				}
				return codeGrant(sealed)
			},
		},
		{
			name: "a refresh credential presented as a code",
			present: func(t *testing.T, client authorizedClient) url.Values {
				sealed, err := client.handlers.flow.sealer.SealRefresh(auth.RefreshCredential{UpstreamSecret: testRefreshToken})
				if err != nil {
					t.Fatalf("SealRefresh: %v", err)
				}
				return codeGrant(sealed)
			},
		},
		{
			name: "a redirect URI this deployment would not redirect to",
			present: func(_ *testing.T, client authorizedClient) url.Values {
				form := codeGrant(client.code)
				form.Set("redirect_uri", "https://attacker.example.test/callback")
				return form
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
			client := authorize(t, fake)

			response := post(t, client.handlers, tt.present(t, client))

			assertOAuthRefusal(t, response, http.StatusBadRequest, "invalid_grant")
			assertNoCredentialInBody(t, response)
		})
	}
}

// TestTheTokenEndpointRefusesARequestThatIsNotOne covers the two refusals that are
// about the request rather than about a grant. They are separate codes because a
// client's repair differs: one has to send the parameter it left out, the other has
// to ask for a grant this server implements.
func TestTheTokenEndpointRefusesARequestThatIsNotOne(t *testing.T) {
	for _, tt := range []struct {
		name       string
		form       url.Values
		status     int
		oauthError string
	}{
		{"no grant_type at all", url.Values{}, http.StatusBadRequest, "unsupported_grant_type"},
		{"a grant this endpoint does not implement", url.Values{"grant_type": {"client_credentials"}}, http.StatusBadRequest, "unsupported_grant_type"},
		{"an authorization code grant with no code", url.Values{"grant_type": {grantAuthorizationCode}, "code_verifier": {testCodeVerifier}, "redirect_uri": {testRedirectURI}}, http.StatusBadRequest, "invalid_request"},
		{"an authorization code grant with no verifier", url.Values{"grant_type": {grantAuthorizationCode}, "code": {"anything"}, "redirect_uri": {testRedirectURI}}, http.StatusBadRequest, "invalid_request"},
		{"a refresh grant with no refresh token", url.Values{"grant_type": {grantRefreshToken}}, http.StatusBadRequest, "invalid_request"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
			handlers := testHandlers(t, fake, io.Discard)
			before := fake.requestCount()

			response := post(t, handlers, tt.form)

			assertOAuthRefusal(t, response, tt.status, tt.oauthError)
			if got := fake.requestCount(); got != before {
				t.Errorf("Google received %d requests for a request that is not a token request, want none", got-before)
			}
		})
	}
}

func TestTheTokenEndpointAnswersOnlyPOST(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)
	request := httptest.NewRequest(http.MethodGet, TokenPath+"?"+codeGrant("a-code").Encode(), nil)
	recorder := httptest.NewRecorder()
	mounted(t, handlers, TokenPath).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d: a grant presented in a URL is one in a proxy log and a browser history",
			recorder.Code, http.StatusMethodNotAllowed)
	}
}

// TestTheRefreshGrantSpendsTheGoogleGrantAndRechecksTheIdentity is acceptance
// criterion 3: the accepted path, the path where Google refuses the grant, and the
// path where the identity has left the allowlist.
func TestTheRefreshGrantSpendsTheGoogleGrantAndRechecksTheIdentity(t *testing.T) {
	t.Run("the accepted path renews without a browser", func(t *testing.T) {
		fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
		client := authorize(t, fake)
		pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))
		spentBefore := fake.refreshGrantsSpent()

		renewed := decodePair(t, post(t, client.handlers, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		}))

		if got := fake.refreshGrantsSpent() - spentBefore; got != 1 {
			t.Errorf("the renewal spent the Google refresh token %d times, want exactly 1: a renewal that does not ask Google cannot notice a revoked grant", got)
		}
		access, err := client.handlers.flow.sealer.UnsealAccess(renewed.AccessToken)
		if err != nil {
			t.Fatalf("the renewed access_token does not unseal: %v", err)
		}
		if access.Email != "one@example.test" || access.Subject != "sub-1" || !access.Verified {
			t.Errorf("renewed access credential = %#v, want the identity Tokeninfo vouched for", access)
		}
		if renewed.RefreshToken != pair.RefreshToken {
			t.Error("the renewal rotated the refresh credential; the same one is presented at every renewal")
		}
		if renewed.AccessToken == pair.AccessToken {
			t.Error("the renewal returned the same access credential, so nothing was renewed")
		}
	})

	t.Run("a Google grant Google refuses ends the session", func(t *testing.T) {
		fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
		client := authorize(t, fake)
		pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))

		// Set after the pair is minted: this is the operator revoking the grant in
		// their Google account between one renewal and the next.
		fake.tokenStatus, fake.tokenBody = http.StatusBadRequest, `{"error":"invalid_grant"}`

		response := post(t, client.handlers, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		})

		assertOAuthRefusal(t, response, http.StatusBadRequest, "invalid_grant")
		assertNoCredentialInBody(t, response)
	})

	t.Run("an identity no longer in the allowlist is refused 403", func(t *testing.T) {
		fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
		client := authorize(t, fake)
		pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))

		// The same deployment with the address taken out of
		// CERBERUS_AUTH_ALLOWED_EMAILS: the same sealing secret, so the credential
		// still opens, and an allowlist that no longer holds the identity behind it.
		authentication := testAuthentication()
		authentication.AllowedEmails = []string{"somebody-else@example.test"}
		var afterward bytes.Buffer
		handlers, err := newHandlers(testConfig(), authentication, testResourcePath, testEndpoints(), testClient(fake), zerologTo(&afterward))
		if err != nil {
			t.Fatalf("newHandlers: %v", err)
		}

		response := post(t, handlers, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		})

		assertOAuthRefusal(t, response, http.StatusForbidden, "access_denied")
		assertNoCredentialInBody(t, response)
		record := lastLogLine(t, afterward.String())
		if record["auth_refusal"] != "renewal_identity_allowlist" {
			t.Errorf("auth_refusal = %v, want renewal_identity_allowlist: two other things at this listener answer 403 and this field is what tells them apart", record["auth_refusal"])
		}
	})

	t.Run("a Google that is unwell does not end the session", func(t *testing.T) {
		fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
		client := authorize(t, fake)
		pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))

		fake.tokenStatus, fake.tokenBody = http.StatusInternalServerError, ""

		response := post(t, client.handlers, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		})

		// Not invalid_grant. A client reading invalid_grant discards its refresh
		// credential and goes back to a browser, which is the wrong answer to
		// Google having a bad minute.
		assertOAuthRefusal(t, response, http.StatusServiceUnavailable, "temporarily_unavailable")
	})

	t.Run("a Google that rotates the refresh token re-seals it", func(t *testing.T) {
		fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
		client := authorize(t, fake)
		pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))
		fake.rotatedRefresh = "the-rotated-google-refresh-token"

		renewed := decodePair(t, post(t, client.handlers, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		}))

		if renewed.RefreshToken == pair.RefreshToken {
			t.Fatal("Google issued a new refresh token and the client was handed back the old sealed one, which is now dead")
		}
		opened, err := client.handlers.flow.sealer.UnsealRefresh(renewed.RefreshToken)
		if err != nil {
			t.Fatalf("the re-sealed refresh credential does not unseal: %v", err)
		}
		if opened.UpstreamSecret != "the-rotated-google-refresh-token" {
			t.Error("the re-sealed refresh credential does not carry the refresh token Google issued")
		}
	})
}

// TestARefreshCredentialCarryingASealedValueIsNeverForwardedToGoogle is ADR
// 01M069V70NEKXXPSQ3HDTAVPS3 at the one place this objective could break it: the
// refresh grant is the only path that takes something out of a sealed credential
// and posts it to a third party.
func TestARefreshCredentialCarryingASealedValueIsNeverForwardedToGoogle(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)
	marked, err := handlers.flow.sealer.SealAccess(auth.AccessCredential{
		Subject: "sub-1", Email: "one@example.test", Verified: true, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SealAccess: %v", err)
	}
	// A refresh credential whose upstream secret is one of this server's own
	// values. Nothing seals one like this today; the point is that if anything ever
	// does, it is refused here rather than posted to Google.
	sealed, err := handlers.flow.sealer.SealRefresh(auth.RefreshCredential{UpstreamSecret: marked})
	if err != nil {
		t.Fatalf("SealRefresh: %v", err)
	}
	before := fake.requestCount()

	response := post(t, handlers, url.Values{"grant_type": {grantRefreshToken}, "refresh_token": {sealed}})

	assertOAuthRefusal(t, response, http.StatusBadRequest, "invalid_grant")
	if got := fake.requestCount(); got != before {
		t.Errorf("Google received %d requests, want none: a value carrying this server's own credential marker may not be sent to a third party", got-before)
	}
	for _, request := range fake.snapshot() {
		if strings.Contains(request.url+request.body, "cdb1:") {
			t.Error("a value carrying this server's sealed-credential marker was sent to Google")
		}
	}
}

// TestNothingTheTokenEndpointWritesCarriesACredential is criterion 7's behavioural
// half: the source guards say the file that logs cannot reach a credential, and
// this says what actually came out.
func TestNothingTheTokenEndpointWritesCarriesACredential(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	client := authorize(t, fake)
	response := post(t, client.handlers, codeGrant(client.code))
	pair := decodePair(t, response)

	record := lastLogLine(t, client.log.String())
	if record["grant"] != grantAuthorizationCode {
		t.Errorf("the issuance log line names grant %v, want %q", record["grant"], grantAuthorizationCode)
	}
	for field, want := range map[string]int{
		"access_credential_bytes":  len(pair.AccessToken),
		"refresh_credential_bytes": len(pair.RefreshToken),
	} {
		got, ok := record[field].(float64)
		if !ok {
			t.Errorf("the issuance log line carries no numeric %s: %v", field, record)
			continue
		}
		if int(got) != want {
			t.Errorf("%s = %d, want %d", field, int(got), want)
		}
	}

	logged := client.log.String()
	for _, tt := range []struct {
		name  string
		value string
	}{
		{"the sealed access credential", pair.AccessToken},
		{"the sealed refresh credential", pair.RefreshToken},
		{"the Google refresh token", testRefreshToken},
		{"this deployment's Google client secret", testClientSecret},
		{"the client's PKCE verifier", testCodeVerifier},
	} {
		if strings.Contains(logged, tt.value) {
			t.Errorf("%s appears in the application log", tt.name)
		}
	}
	// The verifier is the client's proof and is presented to this server alone;
	// forwarding it to Google would be handing a third party the one value that
	// makes a stolen authorization code useless.
	for _, request := range fake.snapshot() {
		if strings.Contains(request.url+request.body, testCodeVerifier) {
			t.Error("the client's own PKCE verifier was sent to Google")
		}
	}
}

// TestARestartIssuesNoLogout is acceptance criterion 8. Both credentials are
// minted against one set of handlers and presented to a second built from the same
// configuration, which is what a redeploy of this process is: nothing is stored, so
// the only thing that has to survive is the sealing secret.
func TestARestartIssuesNoLogout(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	before := authorize(t, fake)
	pair := decodePair(t, post(t, before.handlers, codeGrant(before.code)))

	after := testHandlers(t, fake, io.Discard)

	t.Run("the refresh credential still renews", func(t *testing.T) {
		renewed := decodePair(t, post(t, after, url.Values{
			"grant_type":    {grantRefreshToken},
			"refresh_token": {pair.RefreshToken},
		}))
		if renewed.AccessToken == "" {
			t.Fatal("the restarted process issued no access credential")
		}
	})

	t.Run("the access credential still opens", func(t *testing.T) {
		// A sealer built the way internal/auth's middleware builds one, from the same
		// configured secret and nothing else.
		sealer, err := auth.NewSealer(auth.Secret(testSealingSecret))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		access, err := sealer.UnsealAccess(pair.AccessToken)
		if err != nil {
			t.Fatalf("a credential minted before the restart does not open after it: %v", err)
		}
		if access.Email != "one@example.test" {
			t.Errorf("access credential email = %q, want the identity that consented", access.Email)
		}
	})

	t.Run("an authorization code minted before the restart is still spendable", func(t *testing.T) {
		client := authorizeThrough(t, before.handlers, fake, &bytes.Buffer{})
		if pair := decodePair(t, post(t, after, codeGrant(client.code))); pair.AccessToken == "" {
			t.Error("the restarted process would not spend a code the previous one issued")
		}
	})
}

// TestTheDiscoveryDocumentsDescribeThisServer is acceptance criterion 5, field by
// field over all three paths.
func TestTheDiscoveryDocumentsDescribeThisServer(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)

	t.Run("the authorization server document", func(t *testing.T) {
		document := getDocument(t, handlers, AuthorizationServerMetadataPath)
		for field, want := range map[string]any{
			"issuer":                                testPublicBaseURL,
			"authorization_endpoint":                testPublicBaseURL + AuthorizationPath,
			"token_endpoint":                        testPublicBaseURL + TokenPath,
			"response_types_supported":              []any{"code"},
			"grant_types_supported":                 []any{grantAuthorizationCode, grantRefreshToken},
			"code_challenge_methods_supported":      []any{challengeMethod},
			"token_endpoint_auth_methods_supported": []any{"none"},
		} {
			if got := document[field]; !equalJSON(got, want) {
				t.Errorf("%s = %#v, want %#v", field, got, want)
			}
		}
		scopes, _ := document["scopes_supported"].([]any)
		if !containsAny(scopes, offlineAccessScope) {
			t.Errorf("scopes_supported = %v, want it to contain %q: that string is what makes a Claude client ask for a renewable session, and it is why this whole endpoint exists",
				scopes, offlineAccessScope)
		}
		// A jwks_uri this server cannot serve would send a discovering client to
		// fetch a document that is not there.
		if _, present := document["jwks_uri"]; present {
			t.Errorf("the document carries jwks_uri = %v; this server publishes no JWK set and its credentials are sealed opaque values", document["jwks_uri"])
		}
	})

	for _, pattern := range []string{auth.ProtectedResourceMetadataPath, auth.ProtectedResourceMetadataPath + testResourcePath} {
		t.Run("the protected resource document at "+pattern, func(t *testing.T) {
			document := getDocument(t, handlers, pattern)
			if got, want := document["resource"], testPublicBaseURL+testResourcePath; got != want {
				t.Errorf("resource = %v, want %q, the public base URL joined with the configured MCP path", got, want)
			}
			if got, want := document["authorization_servers"], []any{testPublicBaseURL}; !equalJSON(got, want) {
				t.Errorf("authorization_servers = %#v, want %#v", got, want)
			}
		})
	}

	t.Run("a document says nothing a client could authenticate with", func(t *testing.T) {
		for _, pattern := range patterns(handlers) {
			if !strings.HasPrefix(pattern, "/.well-known/") {
				continue
			}
			body := documentBody(t, handlers, pattern)
			for _, value := range []string{testClientSecret, testSealingSecret, testRefreshToken} {
				if strings.Contains(body, value) {
					t.Errorf("the document at %s carries a value that must never be served: %s", pattern, body)
				}
			}
		}
	})
}

// TestTheDocumentsAreServedToABrowserAndOnlyRead covers what a browser-based
// client needs before it will read either document, and the method rule both
// follow.
func TestTheDocumentsAreServedToABrowserAndOnlyRead(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)
	for _, pattern := range []string{AuthorizationServerMetadataPath, auth.ProtectedResourceMetadataPath} {
		t.Run(pattern, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mounted(t, handlers, pattern).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, pattern, nil))
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want *: a document a browser cannot read is a discovery that stops there", got)
			}

			refused := httptest.NewRecorder()
			mounted(t, handlers, pattern).ServeHTTP(refused, httptest.NewRequest(http.MethodPost, pattern, nil))
			if refused.Code != http.StatusMethodNotAllowed {
				t.Errorf("POST status = %d, want %d", refused.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestTheHandlersRefuseToBuildWithoutTheResourcePath(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers, err := newHandlers(testConfig(), testAuthentication(), "", testEndpoints(), testClient(fake), zerologTo(io.Discard))
	if handlers != nil || err == nil {
		t.Fatalf("newHandlers returned handlers=%t and %v, want no handlers and a refusal", handlers != nil, err)
	}
}

func getDocument(t *testing.T, handlers *Handlers, pattern string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(documentBody(t, handlers, pattern)), &document); err != nil {
		t.Fatalf("the document at %s is not JSON: %v", pattern, err)
	}
	return document
}

func documentBody(t *testing.T, handlers *Handlers, pattern string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	mounted(t, handlers, pattern).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, pattern, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want %d", pattern, recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type at %s = %q, want application/json", pattern, got)
	}
	return recorder.Body.String()
}

func assertOAuthRefusal(t *testing.T, response *httptest.ResponseRecorder, status int, oauthError string) {
	t.Helper()
	if response.Code != status {
		t.Errorf("status = %d, want %d: %s", response.Code, status, response.Body)
	}
	var refusal map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("the refusal is not JSON: %v in %q. A client reads the error code to decide whether to start over or to retry", err, response.Body)
	}
	if refusal["error"] != oauthError {
		t.Errorf("error = %v, want %q", refusal["error"], oauthError)
	}
}

// assertNoCredentialInBody is the "issues nothing" half of every refusal row.
func assertNoCredentialInBody(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	body := response.Body.String()
	for _, marker := range []string{"cdb1:", "access_token", "refresh_token"} {
		if strings.Contains(body, marker) {
			t.Errorf("a refused request was answered with %q in its body: %s", marker, body)
		}
	}
}

func lastLogLine(t *testing.T, logged string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logged), "\n")
	last := lines[len(lines)-1]
	var record map[string]any
	if err := json.Unmarshal([]byte(last), &record); err != nil {
		t.Fatalf("the last application log line is not JSON: %v in %q", err, last)
	}
	return record
}

func equalJSON(got, want any) bool {
	encodedGot, err := json.Marshal(got)
	if err != nil {
		return false
	}
	encodedWant, err := json.Marshal(want)
	if err != nil {
		return false
	}
	return string(encodedGot) == string(encodedWant)
}

func containsAny(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
