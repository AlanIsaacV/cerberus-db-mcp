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
// two HTTP handlers, their refusals, and the one log line the flow produces. It
// holds no credential and reaches none — everything of that kind is behind
// [credentialFlow] in exchange.go, which imports no logger. See the note at the
// top of that file for what enforces it.

const (
	// AuthorizationPath is where an OAuth client starts this server's flow.
	AuthorizationPath = "/authorize"
	// CallbackPath is the registered Google callback.
	CallbackPath = "/authorize/callback"

	googleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL         = "https://oauth2.googleapis.com/token"
	googleTokeninfoURL     = "https://oauth2.googleapis.com/tokeninfo"
	googleScopes           = "openid email profile"

	// exchangeTimeout bounds each of the two calls the callback makes to Google.
	exchangeTimeout = 10 * time.Second
)

// Handlers is the two unauthenticated endpoints that main hands to the HTTP
// transport. It holds only configuration-derived immutable values, so a restart
// with the same sealing secret can finish a flow started before the restart.
type Handlers struct {
	clientID     string
	redirectURIs []string
	callbackURL  string
	authorizeURL string
	flow         *credentialFlow
	log          zerolog.Logger
}

// New builds the production authorization-flow handlers.
func New(config Config, authentication auth.Config, log zerolog.Logger) (*Handlers, error) {
	return newHandlers(config, authentication, googleEndpoints(), newHTTPClient(exchangeTimeout), log)
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

func newHandlers(config Config, authentication auth.Config, google endpoints, client *http.Client, log zerolog.Logger) (*Handlers, error) {
	// Both configurations go straight through. What comes back is where the
	// handlers read their own values from — the client id, the registry, the
	// callback URL — so this file never reads a field off a configuration that
	// also holds a secret, and validation happens once, there.
	flow, err := newCredentialFlow(config, authentication, google, client)
	if err != nil {
		return nil, err
	}
	return &Handlers{
		clientID:     flow.clientID,
		redirectURIs: flow.redirectURIs,
		callbackURL:  flow.callbackURL,
		authorizeURL: google.authorizeURL,
		flow:         flow,
		log:          log,
	}, nil
}

// AuthorizationHandler starts the Google authorization request.
func (h *Handlers) AuthorizationHandler() http.Handler { return http.HandlerFunc(h.authorize) }

// CallbackHandler receives Google's authorization response.
func (h *Handlers) CallbackHandler() http.Handler { return http.HandlerFunc(h.callback) }

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
