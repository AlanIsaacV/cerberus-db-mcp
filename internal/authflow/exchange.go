package authflow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// This file holds every value in this package that must never be rendered —
// this deployment's Google client secret, Google's refresh token, and the
// authorization code sealed from them — and it imports no logger and no
// formatter, exactly as internal/auth/tokeninfo.go and internal/auth/sealing.go
// do. That is what makes "the flow logs no credential" a claim about the shape
// of the source rather than about which variable names somebody chose:
// [Handlers], which has the logger, holds none of these values and can reach
// none of them, and TestTheRawTokenNeverReachesALogger enumerates both halves
// and fails if a new file in this package joins neither.
//
// The seam is the whole of the callback: [credentialFlow.finish] writes the
// redirect itself, because the redirect's Location carries the sealed
// authorization code, and handing that string back to the handler would put a
// credential in the file that can write one.

const (
	// statePrefix is why the state is a second sealing format here rather than a
	// fourth auth.Sealer purpose. ADR 01M069V70NEKXXPSQ3HDTAVPS3 binds a value
	// carrying this server's own `cdb1:` marker never to be sent to a third
	// party, and the state is the one value of this server's that Google is
	// handed — a sealed credential's wire form would carry that marker straight
	// to Google. The prefix is also the AEAD's additional data below, so a state
	// cannot be opened as anything but a state.
	statePrefix  = "cdbstate1:"
	stateKeyInfo = "cerberus-db-mcp authorization state"
	codeLifetime = 5 * time.Minute
)

// The ways the callback can fail. The handlers turn each into a status and a
// message; none of them carries what Google said, what was presented, or what
// this package holds.
var (
	errAuthorizationResponse = errors.New("authflow: Google's authorization response cannot be used")
	errExchangeRefused       = errors.New("authflow: the Google token exchange did not complete")
	errIdentityUnusable      = errors.New("authflow: Google would not vouch for this identity")
	errIdentityRefused       = errors.New("authflow: this identity may not use this server")
	errFlowUnavailable       = errors.New("authflow: this authorization cannot be completed")

	// The ways construction can fail. Each names one dependency, because the
	// operator who reads it at startup has to know which one to supply — the same
	// reason internal/auth/config.go names a variable per sentinel rather than
	// reporting that something was missing.
	errNoClientID            = errors.New("authflow: no Google OAuth client ID was configured")
	errNoAllowlist           = errors.New("authflow: no identity allowlist was configured")
	errNoHTTPClient          = errors.New("authflow: no HTTP client was supplied for the calls to Google")
	errRedirectingHTTPClient = errors.New("authflow: the HTTP client for the calls to Google would follow a redirect")

	// errStateMalformed is every way the state parameter fails to open. It is one
	// sentinel and not four because nothing reads which: [credentialFlow.finish]
	// turns any of them into the same refusal, and telling a caller which step of
	// the unsealing failed would describe the format to whoever is probing it.
	errStateMalformed = errors.New("authflow: authorization state is malformed")
)

// credentialFlow is the half of this package that touches credentials: it
// exchanges Google's authorization code, asks who the resulting access token
// belongs to, and seals the answer into this server's own authorization code.
//
// It is unexported and reachable only through [Handlers], which builds one and
// never reads a field of it that holds anything.
type credentialFlow struct {
	clientID     string
	clientSecret auth.Secret
	callbackURL  string
	redirectURIs []string
	allowed      map[string]bool
	sealer       *auth.Sealer
	stateAEAD    cipher.AEAD
	httpClient   *http.Client
	tokenURL     string
	tokeninfoURL string
}

func newCredentialFlow(config Config, authentication auth.Config, google endpoints, client *http.Client) (*credentialFlow, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	sealer, err := auth.NewSealer(authentication.SealingSecret)
	if err != nil {
		return nil, err
	}
	// The state key is derived from the same master secret rather than
	// configured on its own, so that a restart mid-flow can still open a state
	// it sealed, and it is derived under its own label so that the key sealing
	// state cannot open a credential.
	stateKey, err := hkdf.Key(sha256.New, []byte(string(authentication.SealingSecret)), nil, stateKeyInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(stateKey)
	if err != nil {
		return nil, err
	}
	stateAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(authentication.AllowedEmails))
	for _, address := range authentication.Allowlist() {
		allowed[address] = true
	}
	if authentication.ClientID == "" {
		return nil, errNoClientID
	}
	if len(allowed) == 0 {
		return nil, errNoAllowlist
	}
	if client == nil {
		return nil, errNoHTTPClient
	}
	// A client that follows redirects would carry the access token in the
	// tokeninfo URL, and on a 307 or a 308 this deployment's client secret in the
	// token request's body, to wherever a Location points. See [newHTTPClient].
	if !refusesEveryRedirect(client) {
		return nil, errRedirectingHTTPClient
	}
	return &credentialFlow{
		clientID:     authentication.ClientID,
		clientSecret: config.ClientSecret,
		callbackURL:  config.PublicBaseURL + CallbackPath,
		redirectURIs: config.ClientRedirectURIs,
		allowed:      allowed,
		sealer:       sealer,
		stateAEAD:    stateAEAD,
		httpClient:   client,
		tokenURL:     google.tokenURL,
		tokeninfoURL: google.tokeninfoURL,
	}, nil
}

// redirectProbeHost is where the hop [refusesEveryRedirect] asks about points.
// RFC 2606 reserves .invalid, so the name resolves nowhere even if a
// CheckRedirect under test decides to do something with it.
const redirectProbeHost = "redirect-probe.invalid"

// refusesEveryRedirect asks the client's CheckRedirect what it would do about a
// redirect, rather than whether it has one at all.
//
// The difference is the whole of what errRedirectingHTTPClient claims. A
// CheckRedirect that is non-nil and returns nil permits every hop, so a check
// for presence admitted exactly the client the sentinel is named after: this
// was verified by handing [newHandlers] such a client and watching the flow
// forward Google's access token, which travels in the tokeninfo URL's query, to
// the host a 302 named. Presence proves nothing; a refusal does, and a refusal
// is the only thing that can be observed by calling.
//
// The arguments are the pair net/http passes — the request that would be made
// to the redirect target, and the chain that led to it — and they are filled in
// as completely as a real hop is, because a legitimate CheckRedirect inspects
// them: reading the target's host to decide, counting the chain, reading the
// response that caused the hop, or writing a header onto the new request, which
// panics outright on a nil header map. A probe that panicked on a client that
// refuses every redirect would be a startup failure this check invented. The
// recover is the backstop for one that reads further than this constructs: a
// CheckRedirect that panics never returns nil, so it never permits the hop
// either, and refusal is the correct reading of it here.
func refusesEveryRedirect(client *http.Client) (refuses bool) {
	if client.CheckRedirect == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			refuses = true
		}
	}()
	origin := probeHop("/", nil)
	return client.CheckRedirect(probeHop("/redirected", origin), []*http.Request{origin}) != nil
}

// probeHop builds one request of the shape net/http hands to a CheckRedirect.
// When from is non-nil this is the request that would follow the redirect, and
// from is what answered the 302 that named it.
func probeHop(path string, from *http.Request) *http.Request {
	hop := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Scheme: "https", Host: redirectProbeHost, Path: path},
		Host:       redirectProbeHost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	if from != nil {
		hop.Response = &http.Response{
			Status:     http.StatusText(http.StatusFound),
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    from,
		}
	}
	return hop
}

// clientRequest is what the authorization endpoint accepted from the client,
// after the checks the handlers make.
type clientRequest struct {
	redirectURI     string
	state           string
	challenge       string
	challengeMethod string
}

// start seals everything the callback will need into the state parameter, and
// returns it with the S256 challenge for this server's own PKCE verifier. The
// verifier itself never leaves this file: the only copy that outlives the
// request is inside the sealed state, which is why a restart does not break a
// flow in progress and no map has to remember one.
func (f *credentialFlow) start(client clientRequest) (state, challenge string, err error) {
	verifier, err := randomValue(32)
	if err != nil {
		return "", "", err
	}
	sealed, err := f.sealState(callbackState{
		ClientRedirectURI:     client.redirectURI,
		ClientState:           client.state,
		ClientCodeChallenge:   client.challenge,
		ClientChallengeMethod: client.challengeMethod,
		GoogleCodeVerifier:    verifier,
	})
	if err != nil {
		return "", "", err
	}
	return sealed, pkceChallenge(verifier), nil
}

// completion is the whole of what the handlers learn from a finished exchange:
// two lengths in bytes.
//
// Neither field is named for the value it measures. The file that logs may not
// name a credential-bearing field at all — that is the check that closes the
// leak a name-based scan cannot see — and a length is the one thing about a
// credential that is safe to write down.
type completion struct {
	refreshBytes int
	codeBytes    int
}

// finish completes the callback: it exchanges Google's authorization code,
// checks the identity against the allowlist, seals this server's own
// authorization code, and redirects the client to it.
//
// It writes the redirect itself rather than returning the target, because the
// target carries the sealed code — see the note at the top of this file.
func (f *credentialFlow) finish(w http.ResponseWriter, r *http.Request) (completion, error) {
	query := r.URL.Query()
	googleCode := query.Get("code")
	// ADR 01KZTJ7XXFMFRY632WJ55KX8RJ: the inbound credential is deleted from the
	// request at this package's boundary, so nothing downstream of here can read
	// it back off the request it arrived on.
	query.Del("code")
	r.URL.RawQuery = query.Encode()
	state, err := f.unsealState(query.Get("state"))
	if err != nil || !f.validState(state) || googleCode == "" {
		return completion{}, errAuthorizationResponse
	}
	token, err := f.exchange(r.Context(), googleCode, state.GoogleCodeVerifier)
	if err != nil {
		return completion{}, errExchangeRefused
	}
	identity, err := f.identity(r.Context(), token.AccessToken)
	if err != nil {
		return completion{}, errIdentityUnusable
	}
	if !identity.Verified || identity.Email == "" || !f.allowed[strings.ToLower(strings.TrimSpace(identity.Email))] {
		return completion{}, errIdentityRefused
	}
	sealedCredential, err := f.sealer.SealAuthorizationCode(auth.AuthorizationCodeCredential{
		UpstreamSecret:      token.RefreshToken,
		Subject:             identity.Subject,
		Email:               identity.Email,
		Verified:            identity.Verified,
		CodeChallenge:       state.ClientCodeChallenge,
		CodeChallengeMethod: state.ClientChallengeMethod,
		ExpiresAt:           time.Now().Add(codeLifetime),
	})
	if err != nil {
		return completion{}, errFlowUnavailable
	}
	target, err := url.Parse(state.ClientRedirectURI)
	if err != nil {
		return completion{}, errFlowUnavailable
	}
	values := target.Query()
	values.Set("code", sealedCredential)
	values.Set("state", state.ClientState)
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
	return completion{refreshBytes: len(token.RefreshToken), codeBytes: len(sealedCredential)}, nil
}

// validState re-checks at the callback what the authorization endpoint checked
// before sealing, including the client's redirect URI against the registry: the
// registry can have shrunk between the two legs, and this is the last point
// before an authorization code is minted for a URI nobody would register today.
func (f *credentialFlow) validState(state callbackState) bool {
	return state.GoogleCodeVerifier != "" &&
		state.ClientCodeChallenge != "" &&
		state.ClientChallengeMethod == "S256" &&
		accepts(f.redirectURIs, state.ClientRedirectURI)
}

// callbackState is everything the callback needs to finish, sealed into the
// state parameter Google echoes back so that nothing has to be remembered
// between the two requests.
//
// Sealing binds it to this deployment's sealing secret and, through
// [statePrefix] as additional data, to being a state. What it does not bind is
// time: no field here carries an expiry, so a state this server sealed stays
// openable and usable at the callback for as long as the sealing secret lives.
// Google's authorization code is single-use and short-lived, which is what
// bounds the window in practice. The lifetime this state should have, like
// codeLifetime's, is left for the /token child to decide with more information;
// a field that looked like it answered the question was removed rather than left
// to be trusted.
type callbackState struct {
	ClientRedirectURI     string `json:"client_redirect_uri"`
	ClientState           string `json:"client_state"`
	ClientCodeChallenge   string `json:"client_code_challenge"`
	ClientChallengeMethod string `json:"client_challenge_method"`
	GoogleCodeVerifier    string `json:"google_code_verifier"`
}

func (f *credentialFlow) sealState(state callbackState) (string, error) {
	plain, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, f.stateAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := f.stateAEAD.Seal(nil, nonce, plain, []byte(statePrefix))
	return statePrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func (f *credentialFlow) unsealState(value string) (callbackState, error) {
	if !strings.HasPrefix(value, statePrefix) {
		return callbackState{}, errStateMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, statePrefix))
	if err != nil || len(raw) < f.stateAEAD.NonceSize() {
		return callbackState{}, errStateMalformed
	}
	plain, err := f.stateAEAD.Open(nil, raw[:f.stateAEAD.NonceSize()], raw[f.stateAEAD.NonceSize():], []byte(statePrefix))
	if err != nil {
		return callbackState{}, errStateMalformed
	}
	var state callbackState
	if err := json.Unmarshal(plain, &state); err != nil {
		return callbackState{}, errStateMalformed
	}
	return state, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (f *credentialFlow) exchange(ctx context.Context, code, verifier string) (tokenResponse, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {f.clientID},
		"client_secret": {string(f.clientSecret)},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {f.callbackURL},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := f.httpClient.Do(request)
	if err != nil {
		return tokenResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return tokenResponse{}, errors.New("Google token exchange was refused")
	}
	var token tokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil || token.AccessToken == "" || token.RefreshToken == "" {
		return tokenResponse{}, errors.New("Google token exchange response was unusable")
	}
	return token, nil
}

type googleIdentity struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

func (f *credentialFlow) identity(ctx context.Context, accessToken string) (googleIdentity, error) {
	target, err := url.Parse(f.tokeninfoURL)
	if err != nil {
		return googleIdentity{}, err
	}
	values := target.Query()
	values.Set("access_token", accessToken)
	target.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return googleIdentity{}, err
	}
	response, err := f.httpClient.Do(request)
	if err != nil {
		return googleIdentity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return googleIdentity{}, errors.New("Google identity response was refused")
	}
	var identity googleIdentity
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&identity); err != nil || identity.Subject == "" {
		return googleIdentity{}, errors.New("Google identity response was unusable")
	}
	return identity, nil
}

func randomValue(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
