package authflow

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// This file is the credential half of the token endpoint, and it is subject to
// the rule the note at the top of exchange.go states: it holds the values that
// must never be rendered — the sealed authorization code a client presents, the
// Google refresh token inside a sealed refresh credential, and both credentials
// this server mints — so it imports no logger and no formatter. [Handlers.issuance]
// in flow.go is the half that writes, and it never sees any of them.
//
// The seam is the same one the callback uses: [credentialFlow.issue] writes the
// 200 itself, because the body it writes is a credential pair, and handing those
// strings back to the handler would put them in the file that can log.

const (
	// accessLifetime is how long a credential this server issues stays usable.
	//
	// It is a constant and not a variable an operator can set. An hour is what
	// Google gives an access token, so this changes nothing an agent has to cope
	// with that it did not already cope with; and the whole point of this endpoint
	// is that the hour is now invisible, because the client renews at [TokenPath]
	// without a browser. A configurable lifetime would only be a way to make the
	// window between a Google revocation and this server noticing it longer, and
	// that window is this deployment's entire revocation story — see
	// [credentialFlow.issueFromRenewal].
	accessLifetime = time.Hour

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	// grantUnsupported is chosen here rather than copied out of an unauthenticated
	// request, because issuance logs the grant class and a client-controlled value
	// would make that log a channel for arbitrary input.
	grantUnsupported = "unsupported"

	// challengeMethod is the only PKCE method this server issues a code under and
	// the only one it will verify one against. The authorization endpoint refuses
	// anything else, so a code whose sealed method is not this one cannot have been
	// minted by a version of this server that is still running — and "plain" as a
	// fallback would make the verifier check a comparison of a value the client
	// already put in a URL.
	challengeMethod = "S256"

	bearerTokenType = "Bearer"
)

// The ways the token endpoint can refuse. Each maps to one OAuth error code and
// one status in [tokenRefusal]; none of them carries what was presented, what
// Google said, or what this package holds.
var (
	// errRequestMalformed is a request that is not a token request at all: no
	// parseable form, or a grant with a parameter missing that the grant is
	// defined in terms of.
	errRequestMalformed = errors.New("authflow: the token request cannot be read")
	// errGrantUnsupported is a grant_type this endpoint does not implement. It is
	// distinct from errGrantUnusable because the client's repair is different: one
	// is "ask for something else", the other is "start over at /authorize".
	errGrantUnsupported = errors.New("authflow: this token endpoint does not implement that grant")
	// errGrantUnusable is every way a presented grant fails to be exchangeable —
	// an unopenable or expired code, a verifier that does not hash to the sealed
	// challenge, a sealed value of the wrong purpose, a Google grant Google itself
	// refuses. It is one sentinel and not six for [errStateMalformed]'s reason:
	// nothing reads which, and telling a caller which check failed describes the
	// format to whoever is probing it.
	errGrantUnusable = errors.New("authflow: the presented grant cannot be exchanged")
	// errIssuanceUnavailable is this process failing to seal or encode what it had
	// already decided to issue. It is not a statement about the request.
	errIssuanceUnavailable = errors.New("authflow: this server could not issue a credential")
)

// tokenRequest is everything [TokenPath] accepted, lifted off the request in one
// place and deleted from it there.
//
// ADR 01KZTJ7XXFMFRY632WJ55KX8RJ: an inbound credential is removed from the
// request at the boundary of the package that validates it. Two of these fields
// are credentials — the authorization code and the sealed refresh credential —
// and after [parseTokenRequest] neither is on the *http.Request any more, so a
// handler, a middleware or a logger that got hold of the request later would find
// an empty form rather than a replayable grant.
type tokenRequest struct {
	grant       string
	code        string
	verifier    string
	redirectURI string
	// renewal is the sealed refresh credential a client presents at the refresh
	// grant. It is deliberately not named for what it holds, because what it holds
	// is exactly what this file exists to keep out of everything else.
	renewal string
}

func parseTokenRequest(r *http.Request) (tokenRequest, error) {
	if err := r.ParseForm(); err != nil {
		return tokenRequest{}, errRequestMalformed
	}
	request := tokenRequest{
		grant:       r.PostForm.Get("grant_type"),
		code:        r.PostForm.Get("code"),
		verifier:    r.PostForm.Get("code_verifier"),
		redirectURI: r.PostForm.Get("redirect_uri"),
		renewal:     r.PostForm.Get("refresh_token"),
	}
	// ParseForm merges the body into r.Form as well as filling r.PostForm, so both
	// have to be emptied of the three values that are credentials.
	for _, name := range []string{"code", "code_verifier", "refresh_token"} {
		r.PostForm.Del(name)
		r.Form.Del(name)
	}
	return request, nil
}

// issuance is the whole of what the handler learns from a completed exchange:
// which grant ran, and two lengths in bytes.
//
// As with [completion], no field is named for the value it measures. The file
// that logs may not name a credential-bearing field, and a length is the one
// thing about a credential that is safe to write down — the open question about
// whether a sealed Google refresh token fits in a client's storage is answered
// with these numbers and nothing else.
type issuance struct {
	grant        string
	accessBytes  int
	refreshBytes int
}

// issue is the token endpoint. It writes the 200 itself — see the note at the top
// of this file — and returns only what may be written to a log.
func (f *credentialFlow) issue(w http.ResponseWriter, r *http.Request) (issuance, error) {
	request, err := parseTokenRequest(r)
	if err != nil {
		return issuance{}, err
	}
	switch request.grant {
	case grantAuthorizationCode:
		return f.issueFromCode(w, request)
	case grantRefreshToken:
		return f.issueFromRenewal(r.Context(), w, request)
	default:
		return issuance{grant: grantUnsupported}, errGrantUnsupported
	}
}

// issueFromCode exchanges an authorization code this server minted for the
// credential pair the client will live on.
//
// There is no replay check here and there cannot be one: this process is
// stateless by design — nothing is stored, and a restart invalidates no session —
// so it has nowhere to record that a code has been spent. What bounds a stolen
// code instead is the five minutes the callback sealed into it and the PKCE
// binding below: the code alone is not enough, because whoever presents it must
// also produce the verifier whose S256 hash the client sent to /authorize, and
// that verifier never travelled anywhere this code did. Building the register a
// replay check would need is the one thing that would make this server stateful,
// which is a trade the parent objective already refused.
func (f *credentialFlow) issueFromCode(w http.ResponseWriter, request tokenRequest) (issuance, error) {
	if request.code == "" || request.verifier == "" || request.redirectURI == "" {
		return issuance{grant: request.grant}, errRequestMalformed
	}
	// The registry, exact match, as at both earlier legs of the flow. The sealed
	// code carries the client's PKCE challenge but not its redirect URI, so this is
	// a check that the URI is one this deployment would redirect to at all rather
	// than that it is the one this particular code was issued for. The narrower
	// check is the verifier below, which no other client can produce.
	if !accepts(f.redirectURIs, request.redirectURI) {
		return issuance{grant: request.grant}, errGrantUnusable
	}
	credential, err := f.sealer.UnsealAuthorizationCode(request.code)
	if err != nil {
		// Everything lands here: a value that is not sealed at all, one sealed for
		// another purpose — an access credential presented as a code — one sealed by
		// a deployment with a different secret, and one whose bytes were edited.
		return issuance{grant: request.grant}, errGrantUnusable
	}
	if !credential.ExpiresAt.After(f.now()) {
		return issuance{grant: request.grant}, errGrantUnusable
	}
	if credential.CodeChallengeMethod != challengeMethod || !verifierMatches(request.verifier, credential.CodeChallenge) {
		return issuance{grant: request.grant}, errGrantUnusable
	}
	// The allowlist again, five minutes after the callback asked it. It is nearly
	// always the same answer, and the case where it is not is the one worth having:
	// an operator who has just removed an address should not have a session start
	// because a browser was already open.
	if !credential.Verified || !f.allows(credential.Email) {
		return issuance{grant: request.grant}, errIdentityRefused
	}
	renewal, err := f.sealer.SealRefresh(auth.RefreshCredential{UpstreamSecret: credential.UpstreamSecret})
	if err != nil {
		return issuance{grant: request.grant}, errIssuanceUnavailable
	}
	return f.mint(w, request.grant, auth.AccessCredential{
		Subject:  credential.Subject,
		Email:    credential.Email,
		Verified: credential.Verified,
	}, renewal)
}

// issueFromRenewal spends the Google refresh token inside a sealed refresh
// credential and issues a fresh access credential against what Google says now.
//
// Every renewal contacts Google, and that is the whole revocation story of this
// server. The alternative — carrying the identity inside the sealed refresh and
// re-issuing offline — would make a stolen refresh credential immortal and would
// leave this process with no way at all to notice that the operator revoked the
// grant in their Google account, because it would never ask. So: spend the
// upstream token, ask Tokeninfo who it belongs to now, and check that answer
// against the allowlist as it stands now. Revoking the Google grant, or removing
// an address from CERBERUS_AUTH_ALLOWED_EMAILS, ends the session at its next
// renewal rather than at the end of the sealing key's life.
func (f *credentialFlow) issueFromRenewal(ctx context.Context, w http.ResponseWriter, request tokenRequest) (issuance, error) {
	if request.renewal == "" {
		return issuance{grant: request.grant}, errRequestMalformed
	}
	credential, err := f.sealer.UnsealRefresh(request.renewal)
	if err != nil {
		return issuance{grant: request.grant}, errGrantUnusable
	}
	// ADR 01M069V70NEKXXPSQ3HDTAVPS3: a value carrying this server's own credential
	// marker is never sent to a third party, whatever version it claims. What is
	// about to be posted to Google's token endpoint is whatever the callback sealed
	// in here, and the only thing that belongs there is Google's own refresh token —
	// so a value that looks like one of ours is refused here rather than forwarded.
	// Nothing in this process seals a credential inside a credential today; this is
	// what keeps that from becoming a leak if something ever does.
	if credential.UpstreamSecret == "" || auth.IsSealedCredential(credential.UpstreamSecret) {
		return issuance{grant: request.grant}, errGrantUnusable
	}
	renewed, err := f.renew(ctx, credential.UpstreamSecret)
	if err != nil {
		return issuance{grant: request.grant}, err
	}
	identity, err := f.identity(ctx, renewed.AccessToken)
	if err != nil {
		return issuance{grant: request.grant}, errors.Join(errIdentityUnusable, err)
	}
	if !bool(identity.Verified) || !f.allows(identity.Email) {
		return issuance{grant: request.grant}, errIdentityRefused
	}
	// The presented credential is handed straight back, unrotated, because a
	// stateless server cannot enforce rotation anyway: with nothing recording that
	// the old one was spent, both would keep working, and the client would carry
	// the cost of storing a new value for no gain. The exception is a Google that
	// rotated underneath us — the upstream token would be dead and the session
	// would end on the next renewal — so a changed one is re-sealed.
	renewal := request.renewal
	if renewed.RefreshToken != "" && renewed.RefreshToken != credential.UpstreamSecret {
		renewal, err = f.sealer.SealRefresh(auth.RefreshCredential{UpstreamSecret: renewed.RefreshToken})
		if err != nil {
			return issuance{grant: request.grant}, errIssuanceUnavailable
		}
	}
	return f.mint(w, request.grant, auth.AccessCredential{
		Subject:  identity.Subject,
		Email:    identity.Email,
		Verified: bool(identity.Verified),
	}, renewal)
}

// issued is the token endpoint's success response, in RFC 6749 section 5.1's
// shape. The refresh credential is always included, including on a renewal that
// did not rotate it, because a client that stored a response without one would
// have to be able to tell "keep the old one" from "you have none" — and the
// specification's own answer to that is to send it.
type issued struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// mint seals the access credential, writes the response, and returns the two
// lengths the handler may log.
//
// The expiry is written into the sealed credential rather than only announced in
// expires_in: the announcement is advice to a client, and the sealed value is what
// internal/auth's middleware actually refuses on, so a client that ignores the
// number gets an hour anyway.
func (f *credentialFlow) mint(w http.ResponseWriter, grant string, identity auth.AccessCredential, renewal string) (issuance, error) {
	identity.ExpiresAt = f.now().Add(accessLifetime)
	access, err := f.sealer.SealAccess(identity)
	if err != nil {
		return issuance{grant: grant}, errIssuanceUnavailable
	}
	body, err := json.Marshal(issued{
		AccessToken:  access,
		TokenType:    bearerTokenType,
		ExpiresIn:    int(accessLifetime / time.Second),
		RefreshToken: renewal,
	})
	if err != nil {
		return issuance{grant: grant}, errIssuanceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 section 5.1 requires both: the body is a credential pair, and a
	// cache between this process and the client holding one would hand it to the
	// next caller.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return issuance{grant: grant, accessBytes: len(access), refreshBytes: len(renewal)}, nil
}

// verifierMatches is PKCE's whole check: the S256 hash of what the client kept
// against the challenge the client published when it started the flow.
//
// The comparison is constant time. The challenge is not a secret — it travelled
// in a URL — but the verifier is, and a comparison that returns early tells
// whoever is guessing how many leading bytes of their guess were right.
func verifierMatches(verifier, challenge string) bool {
	return subtle.ConstantTimeCompare([]byte(pkceChallenge(verifier)), []byte(challenge)) == 1
}
