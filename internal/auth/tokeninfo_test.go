package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// No test in this package calls t.Parallel. The configuration tests use t.Setenv,
// which panics under it, and a suite where some tests may run in parallel and
// others may not is a suite where the rule has to be rechecked on every new test.
// internal/mcp and internal/db carry the same rule for the same reason.

// testClientID is the audience every fake response below is issued to. It has the
// shape of a real Google client ID because that is what an operator will paste in,
// and nothing in this package parses it.
const testClientID = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"

// testNow is the instant the fake clock starts at: 2027-01-15, comfortably above
// absoluteEpochFloor, so an absolute expiry in the past and one in the future are
// both expressible.
var testNow = time.Unix(1_800_000_000, 0).UTC()

// clock is a hand-wound time source, so the cache's TTL and the absolute-expiry
// reading can be tested at five minutes and at an hour without a test that takes
// five minutes or an hour.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock { return &clock{at: testNow} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// fakeTokeninfo is an httptest server standing in for Google's endpoint.
//
// It is a real HTTP server on a real socket rather than a stubbed
// http.RoundTripper, because half of what this file tests is what net/http does
// on the way there and back: a redirect refused by the client's own policy, a
// response abandoned mid-body, a request abandoned at its deadline. A fake
// transport would let those tests pass without any of that code running.
type fakeTokeninfo struct {
	url string
	// requests counts every request that arrived, which is how the cache's
	// behaviour is observed: the cache is not visible from outside, but its whole
	// purpose is requests that do not happen.
	requests atomic.Int64
	inFlight atomic.Int64
	// peakInFlight is the most requests this server ever had open at one moment,
	// which is the only place the concurrency bound is observable.
	peakInFlight atomic.Int64
	// tokens records every distinct token presented, so a test can assert which
	// token a request was about.
	mu     sync.Mutex
	tokens []string
}

func newFakeTokeninfo(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *fakeTokeninfo {
	t.Helper()
	f := &fakeTokeninfo{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		open := f.inFlight.Add(1)
		for {
			peak := f.peakInFlight.Load()
			if open <= peak || f.peakInFlight.CompareAndSwap(peak, open) {
				break
			}
		}
		defer f.inFlight.Add(-1)
		f.mu.Lock()
		f.tokens = append(f.tokens, r.URL.Query().Get("access_token"))
		f.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	f.url = server.URL
	return f
}

func (f *fakeTokeninfo) presented() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokens...)
}

// respondWith is the ordinary fake: one status and one body for every token.
func respondWith(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// tokeninfoBody renders a Tokeninfo response with the numeric and boolean fields
// written verbatim, so that a test can present "3599" and 3599, or "true" and
// true, and tell what the decoder did with each.
func tokeninfoBody(aud, azp, sub, email, exp, emailVerified string) string {
	return fmt.Sprintf(
		`{"aud":%q,"azp":%q,"sub":%q,"scope":"openid email profile","exp":%s,"email":%q,"email_verified":%s}`,
		aud, azp, sub, exp, email, emailVerified)
}

// acceptedBody is a response this validator should accept: the configured
// audience, a subject, a verified address, and an hour left in the spelling
// Google's own reference describes.
func acceptedBody(email string) string {
	return tokeninfoBody(testClientID, testClientID, "108134201943512340987", email, "3599", "true")
}

func validatorAgainst(t *testing.T, f *fakeTokeninfo, c *clock) *validator {
	t.Helper()
	return newValidator(testClientID, f.url, newHTTPClient(2*time.Second), c.now)
}

func TestATokenGoogleDoesNotVouchForNeverBecomesAnIdentity(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"the 400 an invalid or expired token gets", http.StatusBadRequest, `{"error":"invalid_token","error_description":"Invalid Value"}`, errTokenRejected},
		{"a 401", http.StatusUnauthorized, `{"error":"invalid_token"}`, errTokenRejected},
		{"a 403", http.StatusForbidden, `{"error":"forbidden"}`, errTokenRejected},
		// Throttling is Google's capacity and not a verdict on the token, which is
		// why it is a different class in the log even though it is the same 401 to
		// the caller.
		{"the 429 Google throttles with", http.StatusTooManyRequests, `{"error":"rate_limited"}`, errValidationUnavailable},
		{"a 408", http.StatusRequestTimeout, ``, errValidationUnavailable},
		{"a 500", http.StatusInternalServerError, ``, errValidationUnavailable},
		{"a 302 answered as a body rather than a redirect", http.StatusFound, ``, errValidationUnavailable},

		{"an audience that is some other application", http.StatusOK,
			tokeninfoBody("999.apps.googleusercontent.com", testClientID, "sub-1", "a@example.com", "3599", "true"), errTokenRejected},
		{"an authorized party that is some other application", http.StatusOK,
			tokeninfoBody(testClientID, "999.apps.googleusercontent.com", "sub-1", "a@example.com", "3599", "true"), errTokenRejected},
		{"an audience that is absent", http.StatusOK,
			tokeninfoBody("", testClientID, "sub-1", "a@example.com", "3599", "true"), errTokenRejected},
		{"an authorized party that is absent", http.StatusOK,
			tokeninfoBody(testClientID, "", "sub-1", "a@example.com", "3599", "true"), errTokenRejected},
		{"no subject to identify the caller by", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "", "a@example.com", "3599", "true"), errTokenRejected},

		{"an expiry field that is absent altogether", http.StatusOK,
			fmt.Sprintf(`{"aud":%q,"azp":%q,"sub":"sub-1","email":"a@example.com","email_verified":true}`, testClientID, testClientID), errTokenRejected},
		{"an expiry of null", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", "null", "true"), errTokenRejected},
		{"an expiry of zero", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", "0", "true"), errTokenRejected},
		{"a negative expiry", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", "-30", "true"), errTokenRejected},
		{"an expiry that is text", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", `"soon"`, "true"), errTokenRejected},
		{"an absolute expiry that has passed", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", strconv.FormatInt(testNow.Unix()-1, 10), "true"), errTokenRejected},
		{"an absolute expiry that is exactly now", http.StatusOK,
			tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", strconv.FormatInt(testNow.Unix(), 10), "true"), errTokenRejected},

		{"a body that is not JSON at all", http.StatusOK, `<html>proxy sign-in page</html>`, errValidationUnavailable},
		{"a body that is an empty JSON document", http.StatusOK, `{}`, errTokenRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(tt.status, tt.body))
			v := validatorAgainst(t, f, newClock())

			got, err := v.validate(context.Background(), "ya29.a-token")
			if !errors.Is(err, tt.want) {
				t.Fatalf("validate = (%+v, %v), want an error wrapping %v", got, err, tt.want)
			}
			if got != (claims{}) {
				t.Errorf("validate returned %+v alongside its error; a refusal must yield no claims", got)
			}
			// A refusal is never remembered, so the next presentation of the same
			// token is asked about again. This is the other half of acceptance
			// criterion 9 and it is asserted on every refusing shape rather than on
			// one of them.
			if _, err := v.validate(context.Background(), "ya29.a-token"); !errors.Is(err, tt.want) {
				t.Fatalf("the second validate = %v, want the same refusal", err)
			}
			if f.requests.Load() != 2 {
				t.Errorf("Tokeninfo saw %d requests for two presentations of a refused token, want 2", f.requests.Load())
			}
		})
	}
}

// TestBothReadingsOfTheExpiryFieldAreAcceptedAndAnythingBetweenThemIsRefused is
// the one open question this package could not settle without a real token.
//
// Google's OIDC reference calls `exp` "the expiry time of the token, as number of
// seconds left until expiry"; `exp` everywhere else in OAuth and OIDC is an
// absolute epoch second. Reading it wrong in the permissive direction accepts
// expired tokens, so neither reading is assumed: a value is interpreted only when
// exactly one reading of it could describe a live token, and a value that could be
// either — or neither — is a refusal.
func TestBothReadingsOfTheExpiryFieldAreAcceptedAndAnythingBetweenThemIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name     string
		exp      string
		accepted bool
	}{
		{"an hour of seconds remaining, as Google's reference describes it", "3599", true},
		{"one second remaining", "1", true},
		{"a whole day remaining, at the top of that reading", strconv.FormatInt(remainingSecondsCeiling, 10), true},
		{"an absolute epoch second an hour from now", strconv.FormatInt(testNow.Unix()+3600, 10), true},
		{"an absolute epoch second one second from now", strconv.FormatInt(testNow.Unix()+1, 10), true},
		// Neither reading describes a token Google would have answered 200 for: a
		// day and a half of remaining seconds is longer than any access token
		// Google issues, and as an absolute instant it is January 1970.
		{"a value in the gap between the two readings", strconv.FormatInt(remainingSecondsCeiling+1, 10), false},
		{"a value just below the epoch floor", strconv.FormatInt(absoluteEpochFloor-1, 10), false},
		{"an absolute epoch second in the past", strconv.FormatInt(testNow.Unix()-3600, 10), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", tt.exp, "true")
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
			v := validatorAgainst(t, f, newClock())

			got, err := v.validate(context.Background(), "ya29.a-token")
			switch {
			case tt.accepted && err != nil:
				t.Fatalf("validate with exp=%s = %v, want the token accepted", tt.exp, err)
			case !tt.accepted && !errors.Is(err, errTokenRejected):
				t.Fatalf("validate with exp=%s = (%+v, %v), want errTokenRejected: an expiry with two readings must not be guessed at", tt.exp, got, err)
			}
		})
	}
}

// TestTheNumbersAndBooleansGoogleSpellsAsStringsAreUnderstood matters because the
// alternative failure is silent and total: a strict decode of email_verified:"true"
// fails the whole response, and every request in the deployment is answered 401
// with a correct configuration and a valid token.
func TestTheNumbersAndBooleansGoogleSpellsAsStringsAreUnderstood(t *testing.T) {
	for _, tt := range []struct {
		name          string
		exp           string
		emailVerified string
		wantVerified  bool
	}{
		{"the spellings the reference documents", "3599", "true", true},
		{"the spellings the endpoint has historically returned", `"3599"`, `"true"`, true},
		{"an absolute epoch as a string", strconv.FormatInt(testNow.Unix()+600, 10), `"true"`, true},
		{"an unverified address as a boolean", "3599", "false", false},
		{"an unverified address as a string", "3599", `"false"`, false},
		{"an email_verified this decoder does not recognise", "3599", `"TRUE"`, false},
		{"an email_verified of 1", "3599", "1", false},
		{"no email_verified at all", "3599", "null", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", tt.exp, tt.emailVerified)
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
			v := validatorAgainst(t, f, newClock())

			got, err := v.validate(context.Background(), "ya29.a-token")
			if err != nil {
				t.Fatalf("validate = %v, want the token accepted whichever spelling its fields arrived in", err)
			}
			if got.emailVerified != tt.wantVerified {
				t.Errorf("emailVerified = %v, want %v", got.emailVerified, tt.wantVerified)
			}
			if got.subject != "sub-1" || got.email != "a@example.com" {
				t.Errorf("claims = %+v, want the subject and email from the response", got)
			}
		})
	}
}

// TestValidationDoesNotDecideWhetherAnEmailIsAcceptable pins the split the
// middleware depends on: an unverified address is a valid token, reported as such,
// and refused afterwards with a different status. Folding it in here would make it
// a 401.
func TestValidationDoesNotDecideWhetherAnEmailIsAcceptable(t *testing.T) {
	body := tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", "3599", "false")
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
	v := validatorAgainst(t, f, newClock())

	got, err := v.validate(context.Background(), "ya29.a-token")
	if err != nil {
		t.Fatalf("validate = %v, want an unverified address to be a valid token", err)
	}
	if got.emailVerified {
		t.Error("emailVerified = true for a response that said false")
	}
}

func TestTheValidatorRefusesToFollowARedirectRatherThanForwardingTheToken(t *testing.T) {
	var elsewhere atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte(acceptedBody("a@example.com")))
	}))
	t.Cleanup(target.Close)

	f := newFakeTokeninfo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/tokeninfo", http.StatusFound)
	})
	v := validatorAgainst(t, f, newClock())

	if _, err := v.validate(context.Background(), "ya29.a-token"); !errors.Is(err, errValidationUnavailable) {
		t.Fatalf("validate = %v, want errValidationUnavailable for a redirected request", err)
	}
	// The point is not only the error. The token is in the request's query string,
	// so a followed redirect would have handed the credential to whoever sent the
	// Location header.
	if elsewhere.Load() != 0 {
		t.Errorf("the redirect target was reached %d times; the token must never leave the configured endpoint", elsewhere.Load())
	}
}

func TestAResponseLargerThanTheCapIsAbandonedRatherThanRead(t *testing.T) {
	// Valid JSON that would be accepted if it were read, so that this test fails if
	// the cap stops being applied rather than passing for a parse error.
	padding := strings.Repeat("p", responseLimit+1)
	body := fmt.Sprintf(`{"aud":%q,"azp":%q,"sub":"sub-1","exp":3599,"email":"a@example.com","email_verified":true,"padding":%q}`,
		testClientID, testClientID, padding)
	if len(body) <= responseLimit {
		t.Fatalf("the test body is %d bytes, which does not exceed the %d byte cap", len(body), responseLimit)
	}
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
	v := validatorAgainst(t, f, newClock())

	if _, err := v.validate(context.Background(), "ya29.a-token"); !errors.Is(err, errValidationUnavailable) {
		t.Fatalf("validate = %v, want errValidationUnavailable for an oversized response", err)
	}
}

func TestARequestThatOutlastsItsTimeoutIsAbandonedRatherThanWaitedOut(t *testing.T) {
	release := make(chan struct{})
	f := newFakeTokeninfo(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(acceptedBody("a@example.com")))
	})
	// Registered after the server, so it runs before the server's own Close:
	// cleanups run last-registered-first, and httptest.Server.Close waits for its
	// handlers, so a release that ran second would deadlock the suite instead of
	// ending the test.
	t.Cleanup(func() { close(release) })
	v := newValidator(testClientID, f.url, newHTTPClient(100*time.Millisecond), newClock().now)

	done := make(chan error, 1)
	go func() {
		_, err := v.validate(context.Background(), "ya29.a-token")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errValidationUnavailable) {
			t.Fatalf("validate = %v, want errValidationUnavailable when the endpoint does not answer", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("validate did not return; a Tokeninfo endpoint that never answers must not hold a request open")
	}
}

// TestNoMoreThanTheBoundedNumberOfTokeninfoRequestsAreEverInFlight asserts the
// bound from the far side: what the endpoint observed, not what this code
// intended.
func TestNoMoreThanTheBoundedNumberOfTokeninfoRequestsAreEverInFlight(t *testing.T) {
	// Held open until as many requests as the bound allows have arrived, so that
	// they genuinely overlap. Without this the bound is untested: eight sequential
	// requests never exceed eight in flight either. The extra pause after the gate
	// opens keeps every slot occupied a while longer, so a caller that was going to
	// be shed is shed rather than finding a slot somebody had already returned.
	var gate sync.Once
	release := make(chan struct{})
	var arrived atomic.Int64
	f := newFakeTokeninfo(t, func(w http.ResponseWriter, _ *http.Request) {
		if arrived.Add(1) >= int64(maxConcurrentValidations) {
			gate.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(acceptedBody("a@example.com")))
	})
	v := validatorAgainst(t, f, newClock())

	const callers = 64
	// Every caller waits here, so that they reach for a slot at the same moment
	// rather than in the order the goroutines happened to be scheduled.
	start := make(chan struct{})
	var accepted, shed atomic.Int64
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// A distinct token per caller, so the cache cannot answer for any of them
			// and every one of these calls has to reach for a slot.
			_, err := v.validate(context.Background(), fmt.Sprintf("ya29.token-%d", i))
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, errValidationUnavailable):
				shed.Add(1)
			default:
				t.Errorf("validate = %v, want either an identity or errValidationUnavailable", err)
			}
		}()
	}
	close(start)
	waitFor(t, &wg, 20*time.Second)

	if peak := f.peakInFlight.Load(); peak > int64(maxConcurrentValidations) {
		t.Errorf("Tokeninfo saw %d requests in flight at once, want no more than %d", peak, maxConcurrentValidations)
	}
	if peak := f.peakInFlight.Load(); peak < 2 {
		t.Errorf("Tokeninfo never saw two requests at once (peak %d), so this test asserts nothing about the bound", peak)
	}
	if accepted.Load()+shed.Load() != callers {
		t.Errorf("%d accepted plus %d shed, want %d callers accounted for", accepted.Load(), shed.Load(), callers)
	}
	if shed.Load() == 0 {
		t.Error("no caller was shed, so the admission control this test is about never engaged")
	}
}

// TestAnAcceptedTokenIsNotAskedAboutAgainWithinItsCacheTTL is acceptance
// criterion 9's positive half, counted at the endpoint because the cache has no
// other observable behaviour.
func TestAnAcceptedTokenIsNotAskedAboutAgainWithinItsCacheTTL(t *testing.T) {
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("a@example.com")))
	c := newClock()
	v := validatorAgainst(t, f, c)

	first, err := v.validate(context.Background(), "ya29.a-token")
	if err != nil {
		t.Fatalf("the first validate = %v", err)
	}
	c.advance(cacheMaxTTL - time.Second)
	for range 5 {
		again, err := v.validate(context.Background(), "ya29.a-token")
		if err != nil {
			t.Fatalf("a repeat validate within the TTL = %v", err)
		}
		if again != first {
			t.Errorf("a cached validate returned %+v, want the claims the first one did: %+v", again, first)
		}
	}
	if f.requests.Load() != 1 {
		t.Errorf("Tokeninfo saw %d requests for six presentations inside the TTL, want 1", f.requests.Load())
	}

	c.advance(2 * time.Second)
	if _, err := v.validate(context.Background(), "ya29.a-token"); err != nil {
		t.Fatalf("validate after the TTL = %v", err)
	}
	if f.requests.Load() != 2 {
		t.Errorf("Tokeninfo saw %d requests after the TTL expired, want 2", f.requests.Load())
	}
}

// TestTheCacheNeverOutlivesTheTokenItRemembers is why the TTL is a minimum of two
// numbers rather than a constant: a token with two minutes left, cached for five,
// would be accepted for three minutes after it stopped being valid.
func TestTheCacheNeverOutlivesTheTokenItRemembers(t *testing.T) {
	body := tokeninfoBody(testClientID, testClientID, "sub-1", "a@example.com", "120", "true")
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, body))
	c := newClock()
	v := validatorAgainst(t, f, c)

	if _, err := v.validate(context.Background(), "ya29.a-token"); err != nil {
		t.Fatalf("the first validate = %v", err)
	}
	c.advance(119 * time.Second)
	if _, err := v.validate(context.Background(), "ya29.a-token"); err != nil {
		t.Fatalf("validate inside the token's own lifetime = %v", err)
	}
	if f.requests.Load() != 1 {
		t.Errorf("Tokeninfo saw %d requests inside the token's lifetime, want 1", f.requests.Load())
	}
	c.advance(2 * time.Second)
	if _, err := v.validate(context.Background(), "ya29.a-token"); err != nil {
		t.Fatalf("validate after the token's own expiry = %v", err)
	}
	if f.requests.Load() != 2 {
		t.Errorf("Tokeninfo saw %d requests once the token's own lifetime had passed, want 2: the cache must not outlive the token", f.requests.Load())
	}
}

// TestTheCacheIsBoundedAndForgetsItsOldestEntry pins the 128-entry bound. A cache
// with no bound is a memory leak keyed on something a caller chooses.
func TestTheCacheIsBoundedAndForgetsItsOldestEntry(t *testing.T) {
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("a@example.com")))
	v := validatorAgainst(t, f, newClock())

	first := "ya29.token-0"
	for i := range cacheCapacity + 1 {
		if _, err := v.validate(context.Background(), fmt.Sprintf("ya29.token-%d", i)); err != nil {
			t.Fatalf("validate of token %d = %v", i, err)
		}
	}
	before := f.requests.Load()
	if _, err := v.validate(context.Background(), first); err != nil {
		t.Fatalf("validate of the evicted token = %v", err)
	}
	if f.requests.Load() != before+1 {
		t.Errorf("the oldest of %d tokens was still cached; the bound is %d entries", cacheCapacity+1, cacheCapacity)
	}
	presented := f.presented()
	if len(presented) == 0 || presented[len(presented)-1] != first {
		t.Errorf("the last token the endpoint was asked about is not the evicted one; it saw %d requests", len(presented))
	}
}

// TestTheProductionValidatorTalksOnlyToGoogleOverHTTPSWithinItsBounds checks the
// constructed object rather than the constants, so that a bound loosened by
// editing the constructor fails here too.
func TestTheProductionValidatorTalksOnlyToGoogleOverHTTPSWithinItsBounds(t *testing.T) {
	middleware, err := NewMiddleware(Config{ClientID: testClientID, AllowedEmails: []string{"a@example.com"}, SealingSecret: testSealingSecret}, discardLogger())
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	if middleware == nil {
		t.Fatal("NewMiddleware returned no middleware")
	}

	if !strings.HasPrefix(tokeninfoURL, "https://oauth2.googleapis.com/") {
		t.Errorf("tokeninfoURL = %q, want Google's endpoint over HTTPS: the token travels in this URL's query", tokeninfoURL)
	}
	client := newHTTPClient(validationTimeout)
	if client.Timeout != 3*time.Second {
		t.Errorf("the Tokeninfo client timeout is %v, want 3s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("the Tokeninfo client follows redirects, which would forward the token in the request URL")
	}
	if err := client.CheckRedirect(nil, nil); err == nil {
		t.Error("CheckRedirect permitted a redirect")
	}
	if responseLimit != 64<<10 || cacheCapacity != 128 || cacheMaxTTL != 5*time.Minute || maxConcurrentValidations != 8 {
		t.Errorf("the ported bounds have changed: limit=%d capacity=%d ttl=%v slots=%d",
			responseLimit, cacheCapacity, cacheMaxTTL, maxConcurrentValidations)
	}
}

// waitFor fails the test rather than hanging it when a group of callers does not
// finish. Every bound in this file is a bound on time as well as on count, and a
// test that hangs reports nothing.
func waitFor(t *testing.T, wg *sync.WaitGroup, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("callers did not finish within %v", within)
	}
}
