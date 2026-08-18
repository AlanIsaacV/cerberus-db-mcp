package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testSealer(t *testing.T, secret Secret) *Sealer {
	t.Helper()
	s, err := NewSealer(secret)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestASealerIsRedactedByEveryOrdinaryRendering(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	for _, tt := range []struct {
		name string
		got  func() string
	}{
		{"%v", func() string { return fmt.Sprintf("%v", sealer) }},
		{"%+v", func() string { return fmt.Sprintf("%+v", sealer) }},
		{"%#v", func() string { return fmt.Sprintf("%#v", sealer) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(); got != redactedSecret && got != `"`+redactedSecret+`"` {
				t.Errorf("%s rendered %q, want a redaction", tt.name, got)
			}
			if got := tt.got(); strings.Contains(got, testSealingSecret) {
				t.Errorf("%s rendered the sealing secret", tt.name)
			}
		})
	}
}

func TestSealingRoundTripsAllCredentialPurposes(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	access := AccessCredential{
		Subject:   "108134201943512340987",
		Email:     "caller@example.test",
		Verified:  true,
		ExpiresAt: testNow.Add(time.Hour),
	}
	refresh := RefreshCredential{UpstreamSecret: "upstream-refresh-secret"}
	authorizationCode := AuthorizationCodeCredential{
		UpstreamSecret:      "upstream-refresh-secret",
		Subject:             "108134201943512340987",
		Email:               "caller@example.test",
		Verified:            true,
		CodeChallenge:       "client-code-challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           testNow.Add(5 * time.Minute),
	}

	for _, tt := range []struct {
		name string
		seal func() (string, error)
		open func(string) (any, error)
		want any
	}{
		{
			name: "access",
			seal: func() (string, error) { return sealer.SealAccess(access) },
			open: func(value string) (any, error) { return sealer.UnsealAccess(value) },
			want: access,
		},
		{
			name: "refresh",
			seal: func() (string, error) { return sealer.SealRefresh(refresh) },
			open: func(value string) (any, error) { return sealer.UnsealRefresh(value) },
			want: refresh,
		},
		{
			name: "authorization code",
			seal: func() (string, error) { return sealer.SealAuthorizationCode(authorizationCode) },
			open: func(value string) (any, error) { return sealer.UnsealAuthorizationCode(value) },
			want: authorizationCode,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sealed, err := tt.seal()
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if !IsSealedCredential(sealed) {
				t.Errorf("sealed value %q has no credential marker", sealed)
			}
			got, err := tt.open(sealed)
			if err != nil {
				t.Fatalf("unseal: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unsealed payload = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSealedCredentialHasAFreshRandomNonce(t *testing.T) {
	for _, tt := range []struct {
		name    string
		payload AccessCredential
	}{
		{"access credential", AccessCredential{Subject: "sub", Email: "caller@example.test", Verified: true, ExpiresAt: testNow.Add(time.Hour)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sealer := testSealer(t, testSealingSecret)
			first, err := sealer.SealAccess(tt.payload)
			if err != nil {
				t.Fatalf("first SealAccess: %v", err)
			}
			second, err := sealer.SealAccess(tt.payload)
			if err != nil {
				t.Fatalf("second SealAccess: %v", err)
			}
			if first == second {
				t.Error("two seals of the same payload were equal, want independently random nonces")
			}
		})
	}
}

func TestUnsealingRefusesMalformedAndCorruptCredentials(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	sealed, err := sealer.SealAccess(AccessCredential{Subject: "sub", Email: "caller@example.test", Verified: true, ExpiresAt: testNow.Add(time.Hour)})
	if err != nil {
		t.Fatalf("SealAccess: %v", err)
	}
	parts := strings.Split(sealed, ".")
	if len(parts) != 2 {
		t.Fatalf("split test credential: got %d parts, want marker/purpose and body", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode test credential: %v", err)
	}
	flippedNonce := append([]byte(nil), raw...)
	flippedNonce[0] ^= 1
	flippedCiphertext := append([]byte(nil), raw...)
	flippedCiphertext[len(flippedCiphertext)-1] ^= 1

	for _, tt := range []struct {
		name  string
		value string
		want  error
	}{
		{"an empty value", "", ErrEmptySealedCredential},
		{"a value with no prefix", "some-google-shaped-value", ErrSealedCredentialMissingPrefix},
		{"an unknown version prefix", "cdb2:a." + parts[1], ErrUnknownSealedCredentialVersion},
		{"a non-base64 body", "cdb1:a.***", ErrMalformedSealedCredential},
		{"a truncated body", "cdb1:a." + base64.RawURLEncoding.EncodeToString(raw[:11]), ErrTruncatedSealedCredential},
		{"a flipped nonce", "cdb1:a." + base64.RawURLEncoding.EncodeToString(flippedNonce), ErrCorruptSealedCredential},
		{"a flipped ciphertext", "cdb1:a." + base64.RawURLEncoding.EncodeToString(flippedCiphertext), ErrCorruptSealedCredential},
		{"valid base64 that is not a credential", "cdb1:a." + base64.RawURLEncoding.EncodeToString(make([]byte, len(raw))), ErrCorruptSealedCredential},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sealer.UnsealAccess(tt.value)
			if !errors.Is(err, tt.want) {
				t.Fatalf("UnsealAccess = (%+v, %v), want an error wrapping %v", got, err, tt.want)
			}
			if got != (AccessCredential{}) {
				t.Errorf("UnsealAccess returned %+v alongside its error", got)
			}
		})
	}
}

func TestSealedCredentialMarkerDoesNotCatchABareCDBGoogleToken(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  bool
	}{
		{"a current access credential marker", "cdb1:a.anything", true},
		{"a current refresh credential marker", "cdb1:r.anything", true},
		{"a current authorization code credential marker", "cdb1:c.anything", true},
		{"a future version in the credential family", "cdb2:a.anything", true},
		{"a numeric multi-digit version in the credential family", "cdb12:a.anything", true},
		{"a bare cdb prefix", "cdb-google-shaped-token", false},
		{"no version", "cdb:a.anything", false},
		{"a non-numeric version", "cdbnext:a.anything", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSealedCredential(tt.value); got != tt.want {
				t.Errorf("IsSealedCredential(%q) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestCredentialsCannotCrossPurposes(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	access, err := sealer.SealAccess(AccessCredential{Subject: "sub", Email: "caller@example.test", Verified: true, ExpiresAt: testNow.Add(time.Hour)})
	if err != nil {
		t.Fatalf("SealAccess: %v", err)
	}
	refresh, err := sealer.SealRefresh(RefreshCredential{UpstreamSecret: "upstream-refresh-secret"})
	if err != nil {
		t.Fatalf("SealRefresh: %v", err)
	}
	authorizationCode, err := sealer.SealAuthorizationCode(AuthorizationCodeCredential{
		UpstreamSecret:      "upstream-refresh-secret",
		Subject:             "sub",
		Email:               "caller@example.test",
		Verified:            true,
		CodeChallenge:       "client-code-challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           testNow.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SealAuthorizationCode: %v", err)
	}
	for _, tt := range []struct {
		name string
		open func() error
		want error
	}{
		{"access cannot become refresh", func() error { _, err := sealer.UnsealRefresh(access); return err }, ErrSealedCredentialWrongPurpose},
		{"refresh cannot become access", func() error { _, err := sealer.UnsealAccess(refresh); return err }, ErrSealedCredentialWrongPurpose},
		{"authorization code cannot become access", func() error { _, err := sealer.UnsealAccess(authorizationCode); return err }, ErrSealedCredentialWrongPurpose},
		{"authorization code cannot become refresh", func() error { _, err := sealer.UnsealRefresh(authorizationCode); return err }, ErrSealedCredentialWrongPurpose},
		{"access cannot become an authorization code", func() error { _, err := sealer.UnsealAuthorizationCode(access); return err }, ErrSealedCredentialWrongPurpose},
		{"refresh cannot become an authorization code", func() error { _, err := sealer.UnsealAuthorizationCode(refresh); return err }, ErrSealedCredentialWrongPurpose},
		{"a refresh ciphertext relabelled as access", func() error {
			relabelled := strings.Replace(refresh, "cdb1:r.", "cdb1:a.", 1)
			_, err := sealer.UnsealAccess(relabelled)
			return err
		}, ErrCorruptSealedCredential},
		{"an authorization code ciphertext relabelled as access", func() error {
			relabelled := strings.Replace(authorizationCode, "cdb1:c.", "cdb1:a.", 1)
			_, err := sealer.UnsealAccess(relabelled)
			return err
		}, ErrCorruptSealedCredential},
		{"an access ciphertext relabelled as an authorization code", func() error {
			relabelled := strings.Replace(access, "cdb1:a.", "cdb1:c.", 1)
			_, err := sealer.UnsealAuthorizationCode(relabelled)
			return err
		}, ErrCorruptSealedCredential},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.open()
			if !errors.Is(err, tt.want) {
				t.Errorf("cross-purpose unseal = %v, want an error wrapping %v", err, tt.want)
			}
		})
	}
}

func TestCredentialWirePrefixIsAuthenticated(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	sealed, err := sealer.seal(AccessPurpose, []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, _, encoded, err := parseCredential(sealed)
	if err != nil {
		t.Fatalf("parse sealed credential: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode sealed credential: %v", err)
	}

	for _, tt := range []struct {
		name    string
		purpose Purpose
	}{
		{"a different purpose tag", RefreshPurpose},
	} {
		t.Run(tt.name, func(t *testing.T) {
			otherPrefix, err := prefixFor(tt.purpose)
			if err != nil {
				t.Fatalf("prefixFor: %v", err)
			}
			got, err := sealer.open(AccessPurpose, otherPrefix, raw)
			if !errors.Is(err, ErrCorruptSealedCredential) {
				t.Fatalf("open with relabelled prefix = (%q, %v), want an error wrapping %v", got, err, ErrCorruptSealedCredential)
			}
		})
	}
}

// TestEachPurposeDerivesItsOwnKey is the assertion that the purposes are
// separated by their HKDF label and not only by the tag they travel beside.
//
// Every other cross-purpose case in this file varies the wire tag and the derived
// key together, so the AEAD's additional data refuses the value first and the key
// is never reached. That gap was measured rather than supposed: giving
// AuthorizationCodePurpose the access purpose's label in [labelFor] left every test
// in internal/auth and internal/authflow green. These cases hold the additional
// data at the prefix the value was actually sealed under and vary only the key, so
// a collision in [labelFor] is the one thing they can fail on.
func TestEachPurposeDerivesItsOwnKey(t *testing.T) {
	sealer := testSealer(t, testSealingSecret)
	for _, tt := range []struct {
		name           string
		sealed, opened Purpose
	}{
		{"an authorization code under the access key", AuthorizationCodePurpose, AccessPurpose},
		{"an authorization code under the refresh key", AuthorizationCodePurpose, RefreshPurpose},
		{"an access credential under the authorization code key", AccessPurpose, AuthorizationCodePurpose},
		{"a refresh credential under the authorization code key", RefreshPurpose, AuthorizationCodePurpose},
		{"an access credential under the refresh key", AccessPurpose, RefreshPurpose},
		{"a refresh credential under the access key", RefreshPurpose, AccessPurpose},
	} {
		t.Run(tt.name, func(t *testing.T) {
			value, err := sealer.seal(tt.sealed, []byte("payload"))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			prefix, _, encoded, err := parseCredential(value)
			if err != nil {
				t.Fatalf("parse sealed credential: %v", err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("decode sealed credential: %v", err)
			}
			got, err := sealer.open(tt.opened, prefix, raw)
			if !errors.Is(err, ErrCorruptSealedCredential) {
				t.Fatalf("opening a %s credential under the %s key = (%q, %v), want an error wrapping %v; the two purposes are deriving the same key",
					tt.sealed, tt.opened, got, err, ErrCorruptSealedCredential)
			}
		})
	}
}

func TestCredentialsCannotCrossMasterSecrets(t *testing.T) {
	for _, tt := range []struct {
		name         string
		issuer, open Secret
	}{
		{"a different master secret", testSealingSecret, Secret("//////////////////////////////////////////8=")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issuer := testSealer(t, tt.issuer)
			other := testSealer(t, tt.open)
			sealed, err := issuer.SealAccess(AccessCredential{Subject: "sub", Email: "caller@example.test", Verified: true, ExpiresAt: testNow.Add(time.Hour)})
			if err != nil {
				t.Fatalf("SealAccess: %v", err)
			}
			got, err := other.UnsealAccess(sealed)
			if !errors.Is(err, ErrCorruptSealedCredential) {
				t.Fatalf("UnsealAccess = (%+v, %v), want ErrCorruptSealedCredential", got, err)
			}
			if got != (AccessCredential{}) {
				t.Errorf("UnsealAccess returned %+v alongside its error", got)
			}
		})
	}
}
