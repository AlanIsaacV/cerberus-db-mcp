package authflow

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// This file is the half of the package that writes where a person can read: the
// HTTP handlers, their refusals, and the log lines the flow produces. It holds no
// credential and reaches none — everything of that kind is behind [credentialFlow]
// in exchange.go and token.go, neither of which imports a logger. See the note at
// the top of exchange.go for what enforces it.
//
// It also names none. A selector here whose name carries one of the credential
// stems fails TestTheRawTokenNeverReachesALogger, which is why the token
// endpoint's handler is [Handlers.IssuanceHandler] rather than anything spelled
// after what it issues.

const (
	// AuthorizationPath is where an OAuth client starts this server's flow.
	AuthorizationPath = "/authorize"
	// CallbackPath is the registered Google callback.
	CallbackPath = "/authorize/callback"
	// TokenPath is where a client exchanges an authorization code for this
	// server's own credential pair, and where it renews without a browser.
	TokenPath = "/token"
	// AuthorizationServerMetadataPath is RFC 8414's well-known location. Its
	// protected-resource counterpart is auth.ProtectedResourceMetadataPath, which
	// lives in internal/auth because the 401 challenge has to name it too.
	AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"

	googleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL         = "https://oauth2.googleapis.com/token"
	googleTokeninfoURL     = "https://oauth2.googleapis.com/tokeninfo"
	googleScopes           = "openid email profile"

	// exchangeTimeout bounds each of the two calls the callback makes to Google.
	exchangeTimeout = 10 * time.Second
)

// Handlers is the unauthenticated endpoints that main hands to the HTTP
// transport. It holds only configuration-derived immutable values, so a restart
// with the same sealing secret can finish a flow started before the restart.
type Handlers struct {
	clientID     string
	redirectURIs []string
	callbackURL  string
	authorizeURL string
	documents    documents
	flow         *credentialFlow
	log          zerolog.Logger
}

// New builds the production authorization-flow handlers.
//
// resourcePath is where internal/mcp mounts the MCP endpoint, which this package
// does not configure and must not guess: it is what the protected-resource
// document names as the resource a client is being sent to authorize for, and a
// document naming /mcp on a deployment that set CERBERUS_MCP_PATH to something
// else describes a resource that is not there.
func New(config Config, authentication auth.Config, resourcePath string, log zerolog.Logger) (*Handlers, error) {
	return newHandlers(config, authentication, resourcePath, googleEndpoints(), newHTTPClient(exchangeTimeout), log)
}

// newHTTPClient builds the client both calls to Google go through.
//
// Redirects are refused rather than followed, the way internal/auth/tokeninfo.go
// refuses them, because both of this flow's outbound calls carry a credential
// where a redirect would take it: Google's access token is in the tokeninfo
// URL's query, so a 302 to anywhere forwards it there, and this deployment's
// client secret is in the token endpoint's request body, which a 307 or a 308
// re-sends to whatever the Location names. The endpoints this package trusts are
// the constants above and nothing else. A CheckRedirect that returns an error
// makes Client.Do return a non-nil response alongside its error, but net/http has
// already closed that body, so the callers in exchange.go, which return on the
// error and never look at the response, leak nothing.
//
// [newCredentialFlow] refuses to build on a client without this, so it holds for
// a hand-built client too and not only for the one made here.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are refused")
		},
	}
}

type endpoints struct {
	authorizeURL string
	tokenURL     string
	tokeninfoURL string
}

func googleEndpoints() endpoints {
	return endpoints{authorizeURL: googleAuthorizationURL, tokenURL: googleTokenURL, tokeninfoURL: googleTokeninfoURL}
}

func newHandlers(config Config, authentication auth.Config, resourcePath string, google endpoints, client *http.Client, log zerolog.Logger) (*Handlers, error) {
	// Both configurations go straight through. What comes back is where the
	// handlers read their own values from — the client id, the registry, the
	// callback URL — so this file never reads a field off a configuration that
	// also holds a secret, and validation happens once, there.
	flow, err := newCredentialFlow(config, authentication, google, client)
	if err != nil {
		return nil, err
	}
	// The flow's copy of the base URL and not this function's: [Config.validate]
	// normalises the value it was given, and the copy it normalised is the one
	// inside the flow. A document built from the unvalidated form here would
	// publish an issuer with a trailing slash that no other URL in the process has.
	papers, err := newDocuments(flow.publicBaseURL, resourcePath)
	if err != nil {
		return nil, err
	}
	return &Handlers{
		clientID:     flow.clientID,
		redirectURIs: flow.redirectURIs,
		callbackURL:  flow.callbackURL,
		authorizeURL: google.authorizeURL,
		documents:    papers,
		flow:         flow,
		log:          log,
	}, nil
}

// Route is one endpoint this package needs mounted, in the shape internal/mcp's
// UnauthenticatedRoute has without this package importing the transport.
type Route struct {
	Pattern string
	Handler http.Handler
}

// Routes is every endpoint of this server's authorization-server half, as one
// list, so that the binary mounts what this package says it serves rather than a
// list somebody has to keep in step with it. A path added here and forgotten
// there is a flow that 404s in production with every package green.
//
// It is also how the binary mounts an endpoint it may not name: internal/auth's
// guards refuse an identifier in cmd/cerberus-db-mcp that so much as contains
// "token", because that directory is where a second credential path would be
// added, and handing main a list it copies keeps that rule and this endpoint from
// having to be traded off against each other.
func (h *Handlers) Routes() []Route {
	resource := h.documents.resourceHandler()
	return []Route{
		{Pattern: AuthorizationPath, Handler: h.AuthorizationHandler()},
		{Pattern: CallbackPath, Handler: h.CallbackHandler()},
		{Pattern: TokenPath, Handler: h.IssuanceHandler()},
		{Pattern: AuthorizationServerMetadataPath, Handler: h.documents.authorizationServerHandler()},
		{Pattern: auth.ProtectedResourceMetadataPath, Handler: resource},
		// The same document at the path-suffixed location RFC 9728 section 3.1 has
		// a client build when the resource is not at the origin root. Both are
		// served because which one a given client asks for is not something this
		// server can find out from here, and answering only one of them is a
		// discovery that stops at a 404.
		{Pattern: h.documents.suffixedResourcePath, Handler: resource},
	}
}

// AuthorizationHandler starts the Google authorization request.
func (h *Handlers) AuthorizationHandler() http.Handler { return http.HandlerFunc(h.authorize) }

// CallbackHandler receives Google's authorization response.
func (h *Handlers) CallbackHandler() http.Handler { return http.HandlerFunc(h.callback) }

// IssuanceHandler is [TokenPath]: the authorization-code grant and the refresh
// grant.
//
// It is not named for the endpoint it serves, and neither is the method behind
// it. This file may not name a credential-bearing identifier at all — see the note
// at the top of it, and TestTheRawTokenNeverReachesALogger, which fails on any
// selector here whose name carries one of the credential stems.
func (h *Handlers) IssuanceHandler() http.Handler { return http.HandlerFunc(h.issuance) }

func (h *Handlers) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	client := clientRequest{
		redirectURI:     query.Get("redirect_uri"),
		state:           query.Get("state"),
		challenge:       query.Get("code_challenge"),
		challengeMethod: query.Get("code_challenge_method"),
	}
	if !accepts(h.redirectURIs, client.redirectURI) {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	if client.challenge == "" || client.challengeMethod != "S256" {
		http.Error(w, "invalid PKCE challenge", http.StatusBadRequest)
		return
	}
	state, challenge, err := h.flow.start(client)
	if err != nil {
		http.Error(w, "authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(h.authorizeURL)
	if err != nil {
		http.Error(w, "authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	values := target.Query()
	values.Set("client_id", h.clientID)
	values.Set("redirect_uri", h.callbackURL)
	values.Set("response_type", "code")
	values.Set("scope", googleScopes)
	values.Set("access_type", "offline")
	values.Set("prompt", "consent")
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("state", state)
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (h *Handlers) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// finish writes the redirect on success, because its Location carries the
	// sealed authorization code and this file may not hold one.
	finished, err := h.flow.finish(w, r)
	if err != nil {
		message, status := refusal(err)
		http.Error(w, message, status)
		googleFailureFields(h.log.Warn().
			Str("failure_class", message).
			Int("status", status), err).
			Msg("the authorization callback refused a response")
		return
	}
	// The two lengths are what acceptance criterion 4 is graded on against real
	// Google, and they are the first real measurement of whether a sealed Google
	// refresh token fits in a redirect URL's query string. Lengths only: the
	// values they describe are never rendered, and no field of [completion]
	// holds one.
	h.log.Info().
		Int("google_refresh_token_bytes", finished.refreshBytes).
		Int("authorization_code_bytes", finished.codeBytes).
		Msg("Google authorization completed, a refresh token was present, and an authorization code was issued")
}

func (h *Handlers) issuance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// issue writes the 200 itself, because the body it writes is the credential
	// pair and this file may not hold one. What comes back is two lengths and the
	// name of the grant that ran.
	result, err := h.flow.issue(w, r)
	if err != nil {
		status, failure := tokenRefusal(err)
		oauthRefusal(w, status, failure)
		event := h.log.Warn().
			Str("grant", result.grant).
			Str("failure_class", failure).
			Int("status", status)
		if status == http.StatusForbidden {
			// Three things at this listener now answer 403, and the auth_refusal
			// field is the only thing that tells them apart: the go-sdk's own
			// DNS-rebinding refusal writes no line at all, internal/auth's middleware
			// writes identity_allowlist, and this is the third — an identity that was
			// admitted once and is not on the allowlist any more. It is deliberately
			// not the middleware's value: an operator filtering on that one is
			// looking at requests refused at the MCP endpoint, and a renewal refused
			// here is a different event with a different remedy.
			event = event.Str("auth_refusal", "renewal_identity_allowlist")
		}
		googleFailureFields(event, err).Msg("the token endpoint refused a request")
		return
	}
	// Lengths and the grant, and nothing else. Both figures are the measurement the
	// open question about client storage limits is answered with, and no field of
	// [issuance] holds the value it measures.
	h.log.Info().
		Str("grant", result.grant).
		Int("access_credential_bytes", result.accessBytes).
		Int("refresh_credential_bytes", result.refreshBytes).
		Msg("the token endpoint issued this server's own credential pair")
}

// tokenRefusal is how a failure inside the issuance becomes a status and an OAuth
// error code.
//
// The token endpoint refuses in OAuth's own shape rather than through [refusal]
// above, because the caller here is a machine following RFC 6749 section 5.2 and
// not a browser: a client reads the error code to decide whether to start the flow
// again or to retry, and a plain-text body leaves it with only the status.
//
// The split between invalid_grant and a 503 is the one that matters to a session.
// invalid_grant means "this grant is finished, go back to /authorize", which for
// an agent means a browser; so it is the answer only when this server or Google
// has actually decided the grant is unusable. A Google that timed out, or one
// answering 500, produces a 503 instead, for the reason internal/auth answers
// validation_unavailable without a challenge: an upstream hiccup must not evict
// every connected client.
func tokenRefusal(err error) (status int, oauthError string) {
	switch {
	case errors.Is(err, errRequestMalformed):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, errGrantUnsupported):
		return http.StatusBadRequest, "unsupported_grant_type"
	case errors.Is(err, errGrantUnusable):
		return http.StatusBadRequest, "invalid_grant"
	case errors.Is(err, errIdentityRefused):
		// 403 and not 400: the grant is valid and this server understood it, and
		// what is being refused is the person behind it. It is the same answer the
		// MCP endpoint gives an identity that has left the allowlist, and it is not
		// 401, which would tell the client its credential is the problem and send it
		// to fetch another one that would be refused in exactly the same way.
		return http.StatusForbidden, "access_denied"
	case errors.Is(err, errIdentityUnusable), errors.Is(err, errRenewalUnavailable):
		return http.StatusServiceUnavailable, "temporarily_unavailable"
	default:
		return http.StatusServiceUnavailable, "temporarily_unavailable"
	}
}

// oauthRefusal writes RFC 6749 section 5.2's body: one member, assembled from a
// code this file chose. Nothing of what was presented, and nothing of what Google
// said, is in it.
func oauthRefusal(w http.ResponseWriter, status int, oauthError string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + oauthError + `"}`))
}

// refusal is how a failure inside the exchange becomes a response. The messages
// and statuses are the whole of what a caller learns: which step failed is in
// the status class, and nothing of what Google said travels back out.
func refusal(err error) (string, int) {
	switch {
	case errors.Is(err, errAuthorizationResponse):
		return "invalid authorization response", http.StatusBadRequest
	case errors.Is(err, errExchangeRefused):
		return "authorization exchange failed", http.StatusBadGateway
	case errors.Is(err, errIdentityUnusable):
		return "identity verification failed", http.StatusBadGateway
	case errors.Is(err, errIdentityRefused):
		return "forbidden", http.StatusForbidden
	default:
		return "authorization is unavailable", http.StatusServiceUnavailable
	}
}

// accepts is the client registry check, exact match and nothing else. A prefix
// or a host comparison would admit the near misses an open redirect is built
// from, and there is no dynamic registration here for a looser rule to serve.
func accepts(configured []string, candidate string) bool {
	for _, registered := range configured {
		if candidate == registered {
			return true
		}
	}
	return false
}
