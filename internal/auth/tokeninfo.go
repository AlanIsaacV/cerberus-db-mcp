package auth

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file is the only one in the repository that holds a raw bearer token, and
// it imports neither a logger nor fmt. That is enforced rather than remembered:
// TestTheRawTokenNeverReachesALogger reads this file's imports and its calls, so
// "the token is never logged" is a claim about a file that has nothing to log
// with, and not a claim about which branches a test happened to take.

// The validator's bounds. Every one of them is ported from inbox-kernel's
// deployed implementation (internal/mcp/google_oauth.go:17-24) rather than
// re-derived, because these numbers have been serving a real Google client for
// long enough to have been wrong if they were, and a fresh set derived for "one
// or two tokens" would be a guess with less evidence behind it.
const (
	// tokeninfoURL is the one endpoint this package talks to, and it is a constant
	// because a configurable validation endpoint is a variable that turns
	// authentication off. TestTheOnlyEndpointNamedInTheSourceIsGooglesOverHTTPS
	// pins it, over HTTPS: the token travels in this URL's query, so a scheme
	// somebody could downgrade would put the credential on the wire in clear.
	//
	// This is the OIDC-era endpoint, whose response fields are aud, azp, sub,
	// scope, exp, email and email_verified — not the older
	// www.googleapis.com/oauth2/v2/tokeninfo, whose fields are audience,
	// issued_to, expires_in, user_id, email and verified_email.
	tokeninfoURL = "https://oauth2.googleapis.com/tokeninfo"

	// validationTimeout bounds one Tokeninfo request end to end. It is the whole
	// client timeout and not a dial timeout: what this protects against is Google
	// answering slowly, which would otherwise hold an inbound request open for as
	// long as it liked.
	validationTimeout = 3 * time.Second

	// responseLimit is the most of Google's answer this will read. A response
	// larger than this is abandoned rather than parsed, because the only body that
	// can arrive here is a small JSON object and anything else is either not
	// Google or not something to spend memory on.
	responseLimit = 64 << 10

	// cacheCapacity and cacheMaxTTL bound the positive-result cache.
	//
	// The TTL is what makes the volume against Google roughly one request per token
	// per five minutes, which matters because Google's own documentation says
	// tokeninfo-style validation may be throttled. It also creates a revocation
	// tail: for up to five minutes after a grant is revoked, a token this process
	// already accepted keeps working. That is accepted deliberately — five minutes
	// of a revoked grant against a read-only, gated, audited surface is a smaller
	// risk than an authentication path that stops working when Google rate-limits
	// it — and it is documented in .env.example so an operator revoking access
	// knows what to expect.
	cacheCapacity = 128
	cacheMaxTTL   = 5 * time.Minute

	// maxConcurrentValidations is admission control, not a fan-out bound. net/http
	// has already parallelised the inbound requests; this is how many of them may
	// be waiting on Google at once, and the rest are refused immediately rather
	// than queued. Refusing is the point: a queue would convert a slow Tokeninfo
	// into unbounded inbound latency, which is exactly what the caller's own
	// deadline cannot see.
	maxConcurrentValidations = 8
)

// The two ways a token can fail to become an identity. Neither carries the token,
// the response, or anything Google said: both exist to be compared with
// errors.Is by the middleware, which turns them into a failure class and a 401.
var (
	// errTokenRejected means Google's answer was usable and says this token is
	// not: a 4xx, a wrong audience, an expiry that has passed or that cannot be
	// read.
	errTokenRejected = errors.New("token rejected")
	// errValidationUnavailable means this validator could not get a usable answer:
	// the request failed, the response was too large or unparseable, Google
	// throttled it, or every concurrency slot was busy. It is still a 401 to the
	// caller — a request this process cannot authenticate does not reach a tool,
	// whatever the reason — and the class in the log is what tells an operator
	// which of the two happened.
	errValidationUnavailable = errors.New("token validation unavailable")
)

// claims is what one accepted Tokeninfo response says about a caller. It is this
// package's own shape and not the wire's: the fields the middleware needs, after
// the audience and expiry checks that decide whether there is anything here at
// all.
type claims struct {
	subject       string
	email         string
	emailVerified bool
}

// tokeninfoResponse is the part of Google's answer this validator reads.
//
// The two lax field types are not defensiveness for its own sake. Google's
// Tokeninfo endpoint has historically rendered its numbers and booleans as JSON
// strings ("3599", "true") while its reference documents them as a number and a
// boolean, and a strict decode of the other spelling fails the whole response —
// which would be a 401 for every request, from a server whose configuration and
// whose token are both correct. Accepting either spelling costs two small types
// and cannot accept anything a strict decode would have refused.
type tokeninfoResponse struct {
	Aud           string         `json:"aud"`
	Azp           string         `json:"azp"`
	Sub           string         `json:"sub"`
	Exp           stringOrNumber `json:"exp"`
	Email         string         `json:"email"`
	EmailVerified stringOrBool   `json:"email_verified"`
}

// stringOrNumber is an integer that may arrive as a JSON number or as a decimal
// JSON string. Absent, null and unreadable are all "not present", which every
// caller here treats as a refusal.
type stringOrNumber struct {
	value   int64
	present bool
}

// UnmarshalJSON never reports an error, and that is deliberate. An `exp` this
// code cannot read is a statement about the token — it has no expiry this
// validator will accept — and belongs in the claims check, where it becomes
// errTokenRejected. Returning an error here would make it errValidationUnavailable
// instead, which reads in the log as "Google is having a bad day" for a response
// Google delivered perfectly well.
func (n *stringOrNumber) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	value, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return nil
	}
	n.value, n.present = value, true
	return nil
}

// stringOrBool is a boolean that may arrive as a JSON boolean or as the JSON
// string "true" or "false". Anything else — absent, null, 1, "TRUE" — is false,
// which is what makes "email_verified must be true, not merely present" a
// property of the decoder rather than of a check somebody has to remember.
type stringOrBool bool

func (b *stringOrBool) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	*b = stringOrBool(text == "true")
	return nil
}

// The two readings of `exp`, and the band between them that is neither.
//
// Google's OIDC reference describes `exp` on this endpoint as "the expiry time of
// the token, as number of seconds left until expiry", which is what `expires_in`
// means on the older endpoint and is not what `exp` means anywhere else in OAuth
// or OIDC, where it is an absolute epoch second. Both readings had to be handled,
// because reading it wrong in the permissive direction accepts expired tokens.
//
// What makes that possible without guessing is that the two readings do not
// overlap for any live token. A Google access token has a lifetime of about an
// hour, so seconds-remaining is a small number; an absolute epoch second is
// around 1.7e9. So a value is interpreted only when exactly one reading of it can
// describe a token Google just answered 200 for, and a value in neither range —
// or in the gap between them — is a refusal rather than a coin flip.
const (
	// remainingSecondsCeiling is the largest value that will be read as
	// seconds-remaining: one day, which is more than an order of magnitude above
	// any access-token lifetime Google issues.
	remainingSecondsCeiling = int64(24 * 60 * 60)
	// absoluteEpochFloor is 2020-01-01T00:00:00Z. Below it, an absolute-epoch
	// reading describes a token that expired years ago, which cannot be what
	// accompanies a 200 from Google; above it, a seconds-remaining reading
	// describes a token valid for fifty years, which no access token is.
	absoluteEpochFloor = int64(1577836800)
)

// remainingLifetime turns the `exp` field into how long this token has left, or
// reports that it has no reading this validator will accept.
//
// It is total and it fails closed: a missing field, a non-positive value, a value
// in the gap between the two readings, and an absolute instant that has passed
// all return false. Nothing about the response can produce a lifetime this
// function did not derive from a value it could interpret exactly one way.
func remainingLifetime(exp stringOrNumber, now time.Time) (time.Duration, bool) {
	if !exp.present {
		return 0, false
	}
	switch {
	case exp.value >= absoluteEpochFloor:
		remaining := time.Unix(exp.value, 0).Sub(now)
		if remaining <= 0 {
			return 0, false
		}
		return remaining, true
	case exp.value > 0 && exp.value <= remainingSecondsCeiling:
		return time.Duration(exp.value) * time.Second, true
	default:
		return 0, false
	}
}

// cacheEntry is one accepted token: the claims it resolved to, and when this
// process stops believing them.
type cacheEntry struct {
	key       string
	claims    claims
	expiresAt time.Time
}

// validator turns a bearer token into claims by asking Google, within bounds,
// and remembers only the answers that were yes.
//
// It is unexported because the seam this package offers is one middleware. A
// caller who could build a validator could point it at a different endpoint, and
// there is no deployment that wants to.
type validator struct {
	client   *http.Client
	clientID string
	baseURL  string
	// now is injected so the cache's TTL and the absolute-expiry reading can be
	// tested without sleeping through them.
	now     func() time.Time
	slots   chan struct{}
	mu      sync.Mutex
	cache   *list.List
	entries map[string]*list.Element
}

// newHTTPClient builds the client every Tokeninfo request goes through.
//
// Redirects are refused rather than followed because the token is in the request
// URL: a 302 to anywhere would forward the credential there, and the one endpoint
// this package trusts is the constant above. A CheckRedirect that returns an error
// makes Client.Do return a non-nil response alongside its error, but net/http has
// already closed that body, so the error path below does not leak it.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are refused")
		},
	}
}

func newValidator(clientID, baseURL string, client *http.Client, now func() time.Time) *validator {
	return &validator{
		client:   client,
		clientID: clientID,
		baseURL:  baseURL,
		now:      now,
		slots:    make(chan struct{}, maxConcurrentValidations),
		cache:    list.New(),
		entries:  make(map[string]*list.Element),
	}
}

// validate resolves a bearer token to the claims Google vouches for.
//
// It answers exactly two questions: is this token one Google issued to this
// deployment's OAuth client, and has it not expired. Whether the identity behind
// it may use this server is the allowlist's question, deliberately asked
// afterwards and separately — see [newMiddleware].
func (v *validator) validate(ctx context.Context, token string) (claims, error) {
	// Unreachable through [NewMiddleware], which refuses an empty client ID at
	// construction. It is here because without it a hand-built validator would
	// compare Google's `aud` against "" and reject everything — or, if a response
	// ever carried an empty audience, accept it.
	if v.clientID == "" {
		return claims{}, errTokenRejected
	}

	// The hash is the cache key and the only representation of the token that
	// outlives this call. It is not logged either: see the note at the top of this
	// file.
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	if cached, ok := v.cached(key); ok {
		return cached, nil
	}

	select {
	case v.slots <- struct{}{}:
		defer func() { <-v.slots }()
	default:
		return claims{}, errValidationUnavailable
	}
	// Checked again now that this call holds a slot: the request it was queued
	// behind may have been for this same token and may have just cached it.
	if cached, ok := v.cached(key); ok {
		return cached, nil
	}

	endpoint, err := url.Parse(v.baseURL)
	if err != nil {
		return claims{}, errValidationUnavailable
	}
	query := endpoint.Query()
	query.Set("access_token", token)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return claims{}, errValidationUnavailable
	}
	resp, err := v.client.Do(req)
	if err != nil {
		// Everything this can be — a refused redirect, the timeout, a DNS failure,
		// the caller's own cancelled context — is discarded rather than wrapped.
		// The URL is in it, and the token is in the URL.
		return claims{}, errValidationUnavailable
	}
	defer resp.Body.Close()
	// Drained up to the cap before closing, so the connection can be reused, and
	// bounded so that draining is not its own way of reading an unbounded body.
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, responseLimit)) }()

	switch {
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		// Throttling and timeouts are Google's capacity, not a verdict on the token.
		return claims{}, errValidationUnavailable
	case resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError:
		// This is what an invalid or expired token gets: 400 with
		// {"error":"invalid_token"}. The body is not read, because the verdict is
		// already in the status and Google's words are not this process's to repeat.
		return claims{}, errTokenRejected
	case resp.StatusCode != http.StatusOK:
		return claims{}, errValidationUnavailable
	}

	// One byte past the cap, so that a body exactly at the limit is read whole and
	// one over it is detectable rather than silently truncated into valid JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil || len(body) > responseLimit {
		return claims{}, errValidationUnavailable
	}
	var info tokeninfoResponse
	if json.Unmarshal(body, &info) != nil {
		return claims{}, errValidationUnavailable
	}

	// aud and azp both, because they answer different questions: aud is who the
	// token is for and azp is who asked for it, and the MCP authorization spec's
	// audience rule is what makes a token minted for another application useless
	// here. An empty subject is refused too — an identity with no stable id is not
	// an identity, and it is what every audit line downstream is keyed on.
	if info.Aud != v.clientID || info.Azp != v.clientID || info.Sub == "" {
		return claims{}, errTokenRejected
	}
	remaining, ok := remainingLifetime(info.Exp, v.now())
	if !ok {
		return claims{}, errTokenRejected
	}

	accepted := claims{subject: info.Sub, email: info.Email, emailVerified: bool(info.EmailVerified)}
	// The cache never outlives the token: a token with two minutes left is
	// remembered for two minutes, not for five.
	v.store(key, accepted, v.now().Add(min(remaining, cacheMaxTTL)))
	return accepted, nil
}

// cached returns a remembered positive result, evicting it if it has aged out.
//
// Only positive results are here, and that is the asymmetry acceptance criterion 9
// is about: an accepted token costs one Tokeninfo request per TTL, and a rejected
// one is asked about again every time it is presented, so a caller cannot make a
// refusal cheap by repeating it and a token that starts working starts working
// immediately.
func (v *validator) cached(key string) (claims, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	element, ok := v.entries[key]
	if !ok {
		return claims{}, false
	}
	entry := element.Value.(cacheEntry)
	if !v.now().Before(entry.expiresAt) {
		v.cache.Remove(element)
		delete(v.entries, key)
		return claims{}, false
	}
	v.cache.MoveToFront(element)
	return entry.claims, true
}

func (v *validator) store(key string, accepted claims, expiresAt time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if element, ok := v.entries[key]; ok {
		element.Value = cacheEntry{key: key, claims: accepted, expiresAt: expiresAt}
		v.cache.MoveToFront(element)
		return
	}
	v.entries[key] = v.cache.PushFront(cacheEntry{key: key, claims: accepted, expiresAt: expiresAt})
	if v.cache.Len() > cacheCapacity {
		oldest := v.cache.Back()
		delete(v.entries, oldest.Value.(cacheEntry).key)
		v.cache.Remove(oldest)
	}
}
