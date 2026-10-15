package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testGatewayAudience = "cerberus-db"

var (
	testGatewaySigningKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	otherGatewaySigningKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
)

func encodedGatewayPublicKey(signingKey ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))
}

func gatewayTrusting(addresses ...string) Config {
	cfg := allowlistOf(addresses...)
	cfg.GatewayPublicKey = encodedGatewayPublicKey(testGatewaySigningKey)
	cfg.GatewayAudience = testGatewayAudience
	return cfg
}

type assertionParts struct {
	header map[string]any
	claims map[string]any
}

func validAssertionParts(now time.Time) assertionParts {
	return assertionParts{
		header: map[string]any{
			"alg": "EdDSA",
			"typ": "cerberus-gw-assertion+jwt",
			"kid": gatewayKeyID(testGatewaySigningKey.Public().(ed25519.PublicKey)),
		},
		claims: map[string]any{
			"iss":    "cerberus-gw",
			"aud":    testGatewayAudience,
			"sub":    "gateway-subject-1",
			"email":  "Gateway.Person@example.test",
			"groups": []string{"engineering"},
			"perms":  []string{"db.read"},
			"iat":    now.Unix(),
			"exp":    now.Add(2 * time.Minute).Unix(),
		},
	}
}

func segmentOf(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %v: %v", value, err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func signedAssertion(t *testing.T, signingKey ed25519.PrivateKey, parts assertionParts) string {
	t.Helper()
	signingInput := segmentOf(t, parts.header) + "." + segmentOf(t, parts.claims)
	signature := ed25519.Sign(signingKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func unsignedJWS(header string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"108134201943512340987"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

func TestAGatewayAssertionReachesTheHandlerAsItsSubjectAndEmail(t *testing.T) {
	clock := newClock()
	f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
	h := serveBehindAuthAt(t, gatewayTrusting("one@example.test"), f, clock.now)
	assertionToken := signedAssertion(t, testGatewaySigningKey, validAssertionParts(clock.now()))

	resp := h.get(t, "Bearer "+assertionToken)
	if resp.StatusCode != handlerReached {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (%s), want the protected handler to have answered", resp.StatusCode, body)
	}
	id, ok := h.observedIdentity()
	if !ok {
		t.Fatal("the handler found no identity on its context")
	}
	want := Identity{Subject: "gateway-subject-1", Email: "Gateway.Person@example.test"}
	if id != want {
		t.Errorf("Identity = %#v, want %#v; the email is not on the allowlist, and an assertion is not checked against it", id, want)
	}
	if got := f.requests.Load(); got != 0 {
		t.Errorf("Tokeninfo saw %d requests for a gateway assertion, want 0", got)
	}
	h.assertAuthorizationGone(t)
}

func TestAGatewayAssertionThatCannotAuthenticateIsRefusedWithoutAskingGoogle(t *testing.T) {
	ownKeyID := gatewayKeyID(testGatewaySigningKey.Public().(ed25519.PublicKey))
	for _, tt := range []struct {
		name    string
		mint    func(t *testing.T, now time.Time) string
		advance time.Duration
		class   string
	}{
		{
			name: "an assertion for another audience",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.claims["aud"] = "cerberus-cache"
				return signedAssertion(t, testGatewaySigningKey, parts)
			},
			class: failureAssertionWrongAudience,
		},
		{
			name: "an audience carried as an array",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.claims["aud"] = []string{testGatewayAudience}
				return signedAssertion(t, testGatewaySigningKey, parts)
			},
			class: failureAssertionRejected,
		},
		{
			name: "an assertion at its expiry instant",
			mint: func(t *testing.T, now time.Time) string {
				return signedAssertion(t, testGatewaySigningKey, validAssertionParts(now))
			},
			advance: 2 * time.Minute,
			class:   failureAssertionExpired,
		},
		{
			name: "an assertion signed by another key under the trusted key's id",
			mint: func(t *testing.T, now time.Time) string {
				return signedAssertion(t, otherGatewaySigningKey, validAssertionParts(now))
			},
			class: failureAssertionRejected,
		},
		{
			name: "an assertion signed by another key under that key's own id",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.header["kid"] = gatewayKeyID(otherGatewaySigningKey.Public().(ed25519.PublicKey))
				return signedAssertion(t, otherGatewaySigningKey, parts)
			},
			class: failureAssertionRejected,
		},
		{
			name: "a signature altered in one byte",
			mint: func(t *testing.T, now time.Time) string {
				segments := strings.Split(signedAssertion(t, testGatewaySigningKey, validAssertionParts(now)), ".")
				raw, err := base64.RawURLEncoding.DecodeString(segments[2])
				if err != nil {
					t.Fatalf("decode signature: %v", err)
				}
				raw[0] ^= 0xff
				segments[2] = base64.RawURLEncoding.EncodeToString(raw)
				return strings.Join(segments, ".")
			},
			class: failureAssertionRejected,
		},
		{
			name: "a wrong alg",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.header["alg"] = "none"
				return signedAssertion(t, testGatewaySigningKey, parts)
			},
			class: failureAssertionRejected,
		},
		{
			name: "a typ of the gateway's family that is not the assertion's",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.header["typ"] = "cerberus-gw-assertion+jwt;v=2"
				return signedAssertion(t, testGatewaySigningKey, parts)
			},
			class: failureAssertionRejected,
		},
		{
			name: "two segments",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				return segmentOf(t, parts.header) + "." + segmentOf(t, parts.claims)
			},
			class: failureAssertionRejected,
		},
		{
			name: "a payload that is not base64url",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				signingInput := segmentOf(t, parts.header) + ".!!not*base64!!"
				return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testGatewaySigningKey, []byte(signingInput)))
			},
			class: failureAssertionRejected,
		},
		{
			name: "a signature that is not base64url",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				return segmentOf(t, parts.header) + "." + segmentOf(t, parts.claims) + ".!!not*base64!!"
			},
			class: failureAssertionRejected,
		},
		{
			name: "a payload that is not JSON",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				signingInput := segmentOf(t, parts.header) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"cerberus-gw",`))
				return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testGatewaySigningKey, []byte(signingInput)))
			},
			class: failureAssertionRejected,
		},
		{
			name: "a header whose alg is not a string",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"cerberus-gw-assertion+jwt","alg":1,"kid":"` + ownKeyID + `"}`))
				signingInput := header + "." + segmentOf(t, parts.claims)
				return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testGatewaySigningKey, []byte(signingInput)))
			},
			class: failureAssertionRejected,
		},
		{
			name: "a header that is not JSON",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"cerberus-gw-assertion+jwt","alg":"EdDSA",`))
				signingInput := header + "." + segmentOf(t, parts.claims)
				return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testGatewaySigningKey, []byte(signingInput)))
			},
			class: failureAssertionRejected,
		},
		{
			name: "a header whose typ is not a string",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":["cerberus-gw-assertion+jwt"],"alg":"EdDSA","kid":"` + ownKeyID + `"}`))
				signingInput := header + "." + segmentOf(t, parts.claims)
				return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testGatewaySigningKey, []byte(signingInput)))
			},
			class: failureAssertionRejected,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
			h := serveBehindAuthAt(t, gatewayTrusting("one@example.test"), f, clock.now)
			assertionToken := tt.mint(t, clock.now())
			clock.advance(tt.advance)

			resp := h.get(t, "Bearer "+assertionToken)
			h.assertRejected(t, resp, http.StatusUnauthorized, tt.class)
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a gateway assertion, want 0", got)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

func TestAGatewayAssertionIsRefusedAndKeptFromGoogleWhenNoGatewayIsTrusted(t *testing.T) {
	for _, tt := range []struct {
		name string
		mint func(t *testing.T, now time.Time) string
	}{
		{
			name: "a valid assertion",
			mint: func(t *testing.T, now time.Time) string {
				return signedAssertion(t, testGatewaySigningKey, validAssertionParts(now))
			},
		},
		{
			name: "an assertion for another audience",
			mint: func(t *testing.T, now time.Time) string {
				parts := validAssertionParts(now)
				parts.claims["aud"] = "cerberus-cache"
				return signedAssertion(t, testGatewaySigningKey, parts)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
			h := serveBehindAuthAt(t, allowlistOf("one@example.test"), f, clock.now)

			resp := h.get(t, "Bearer "+tt.mint(t, clock.now()))
			h.assertRejected(t, resp, http.StatusUnauthorized, failureNoAssertionVerification)
			if got := f.requests.Load(); got != 0 {
				t.Errorf("Tokeninfo saw %d requests for a gateway assertion, want 0", got)
			}
			h.assertAuthorizationGone(t)
		})
	}
}

func TestTrustingAGatewayLeavesSealedCredentialsAndGoogleTokensAdmittedAsBefore(t *testing.T) {
	clock := newClock()
	cfg := gatewayTrusting("one@example.test")
	sealedCredential, err := testSealer(t, cfg.SealingSecret).SealAccess(AccessCredential{
		Subject: "sealed-subject", Email: "one@example.test", Verified: true, ExpiresAt: clock.now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SealAccess: %v", err)
	}
	for _, tt := range []struct {
		name        string
		bearer      string
		want        Identity
		googleAsked int64
	}{
		{"a sealed credential", sealedCredential, Identity{Subject: "sealed-subject", Email: "one@example.test"}, 0},
		{"a Google access token", "ya29.a-google-access-token", Identity{Subject: "108134201943512340987", Email: "one@example.test"}, 1},
		{"a Google access token of three segments", "ya29.c.c0-a-service-account-token", Identity{Subject: "108134201943512340987", Email: "one@example.test"}, 1},
		{"a JWT whose typ is not ours", unsignedJWS(`{"alg":"RS256","typ":"JWT"}`), Identity{Subject: "108134201943512340987", Email: "one@example.test"}, 1},
		{"a JWT with no typ", unsignedJWS(`{"alg":"RS256"}`), Identity{Subject: "108134201943512340987", Email: "one@example.test"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeTokeninfo(t, respondWith(http.StatusOK, acceptedBody("one@example.test")))
			h := serveBehindAuthAt(t, cfg, f, clock.now)

			resp := h.get(t, "Bearer "+tt.bearer)
			if resp.StatusCode != handlerReached {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d (%s), want the protected handler to have answered", resp.StatusCode, body)
			}
			if id, _ := h.observedIdentity(); id != tt.want {
				t.Errorf("Identity = %#v, want %#v", id, tt.want)
			}
			if got := f.requests.Load(); got != tt.googleAsked {
				t.Errorf("Tokeninfo saw %d requests, want %d", got, tt.googleAsked)
			}
		})
	}
}

func TestGatewayTrustIsConfiguredByBothVariablesOrNeither(t *testing.T) {
	base := map[string]string{
		"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
		"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
		"CERBERUS_AUTH_SEALING_SECRET":   testSealingSecret,
	}
	with := func(extra map[string]string) map[string]string {
		environ := make(map[string]string, len(base)+len(extra))
		for name, value := range base {
			environ[name] = value
		}
		for name, value := range extra {
			environ[name] = value
		}
		return environ
	}
	publicKeyValue := encodedGatewayPublicKey(testGatewaySigningKey)

	for _, tt := range []struct {
		name    string
		environ map[string]string
		want    error
		names   string
	}{
		{"neither variable", with(nil), nil, ""},
		{"both variables", with(map[string]string{
			"CERBERUS_AUTH_GATEWAY_PUBLIC_KEY": publicKeyValue,
			"CERBERUS_AUTH_GATEWAY_AUDIENCE":   testGatewayAudience,
		}), nil, ""},
		{"the public key alone", with(map[string]string{
			"CERBERUS_AUTH_GATEWAY_PUBLIC_KEY": publicKeyValue,
		}), ErrIncompleteGatewayTrust, "CERBERUS_AUTH_GATEWAY_AUDIENCE"},
		{"the audience alone", with(map[string]string{
			"CERBERUS_AUTH_GATEWAY_AUDIENCE": testGatewayAudience,
		}), ErrIncompleteGatewayTrust, "CERBERUS_AUTH_GATEWAY_PUBLIC_KEY"},
		{"a public key that is not base64", with(map[string]string{
			"CERBERUS_AUTH_GATEWAY_PUBLIC_KEY": "not base64!",
			"CERBERUS_AUTH_GATEWAY_AUDIENCE":   testGatewayAudience,
		}), ErrInvalidVariable, "CERBERUS_AUTH_GATEWAY_PUBLIC_KEY"},
		{"a public key of the wrong length", with(map[string]string{
			"CERBERUS_AUTH_GATEWAY_PUBLIC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
			"CERBERUS_AUTH_GATEWAY_AUDIENCE":   testGatewayAudience,
		}), ErrInvalidVariable, "CERBERUS_AUTH_GATEWAY_PUBLIC_KEY"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadConfigFrom(tt.environ)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("LoadConfigFrom: %v", err)
				}
				if cfg.GatewayPublicKey != tt.environ["CERBERUS_AUTH_GATEWAY_PUBLIC_KEY"] || cfg.GatewayAudience != tt.environ["CERBERUS_AUTH_GATEWAY_AUDIENCE"] {
					t.Errorf("LoadConfigFrom = %+v, want the gateway variables as they were set", cfg)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("LoadConfigFrom = (%+v, %v), want an error wrapping %v", cfg, err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.names) {
				t.Errorf("the error does not name %s: %s", tt.names, err)
			}
			for name, value := range tt.environ {
				if strings.Contains(err.Error(), value) {
					t.Errorf("the error quotes the value of %s: %s", name, err)
				}
			}
			var built Config
			built.ClientID, built.AllowedEmails, built.SealingSecret = testClientID, []string{"one@example.test"}, testSealingSecret
			built.GatewayPublicKey, built.GatewayAudience = tt.environ["CERBERUS_AUTH_GATEWAY_PUBLIC_KEY"], tt.environ["CERBERUS_AUTH_GATEWAY_AUDIENCE"]
			middleware, err := NewMiddleware(built, noPublicBaseURL, discardLogger())
			if !errors.Is(err, tt.want) || middleware != nil {
				t.Errorf("NewMiddleware = (%v, %v), want no middleware and an error wrapping %v", middleware != nil, err, tt.want)
			}
		})
	}
}
