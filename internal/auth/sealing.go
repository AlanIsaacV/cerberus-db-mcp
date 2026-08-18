package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Sealing errors are sentinels so the middleware can choose a refusal class
// without learning anything about the cipher or the bytes it was handed.
var (
	ErrEmptySealedCredential          = errors.New("sealed credential is empty")
	ErrSealedCredentialMissingPrefix  = errors.New("sealed credential has no prefix")
	ErrUnknownSealedCredentialVersion = errors.New("sealed credential has an unknown version")
	ErrMalformedSealedCredential      = errors.New("sealed credential is malformed")
	ErrTruncatedSealedCredential      = errors.New("sealed credential is truncated")
	ErrCorruptSealedCredential        = errors.New("sealed credential is corrupt")
	ErrSealedCredentialWrongPurpose   = errors.New("sealed credential has the wrong purpose")
	ErrInvalidSealingSecret           = errors.New("credential sealing secret is not usable")
	ErrSealingUnavailable             = errors.New("credential sealing is unavailable")
)

const (
	sealingSecretLength = 32
	credentialVersion   = "cdb1"
	// credentialMarker includes the version and a colon delimiter. Google access
	// tokens are opaque to us, but their URL-safe opaque form cannot begin with
	// this delimiter-bearing marker; a bare "cdb" could, and must stay on the
	// Google validation path.
	credentialMarker = credentialVersion + ":"
)

// Secret is configuration whose accidental rendering must not disclose its
// value. It follows internal/db's redaction convention, but lives here because a
// credential sealing secret is not a database password and auth deliberately
// does not cross that package boundary.
type Secret string

const redactedSecret = "[redacted]"

func (Secret) String() string { return redactedSecret }

// GoString covers %#v, which does not consult String.
func (Secret) GoString() string { return strconv.Quote(redactedSecret) }

// MarshalText covers encoders that prefer a TextMarshaler over the underlying
// string.
func (Secret) MarshalText() ([]byte, error) { return []byte(redactedSecret), nil }

func (s Secret) reveal() string { return string(s) }

// Purpose separates credential kinds at the key-derivation boundary.
type Purpose string

const (
	AccessPurpose            Purpose = "access"
	RefreshPurpose           Purpose = "refresh"
	AuthorizationCodePurpose Purpose = "authorization-code"
)

// AccessCredential is the sealed identity carried by a credential accepted at
// this server's MCP endpoint.
type AccessCredential struct {
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Verified  bool      `json:"verified"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshCredential is reserved for the upstream secret a later authorization
// flow will exchange with Google. It is sealed now so its key can never be
// retrofitted onto live access credentials.
type RefreshCredential struct {
	UpstreamSecret string `json:"upstream_secret"`
}

// AuthorizationCodeCredential is the stateless authorization result a later
// token endpoint will exchange for this server's credentials.
type AuthorizationCodeCredential struct {
	UpstreamSecret      string    `json:"upstream_secret"`
	Subject             string    `json:"subject"`
	Email               string    `json:"email"`
	Verified            bool      `json:"verified"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// Sealer issues and accepts this process's opaque credentials. It keeps only the
// configured master secret in memory; individual credentials need no stored
// state.
type Sealer struct {
	masterSecret []byte
}

func (Sealer) String() string { return redactedSecret }

// GoString covers %#v, which does not consult String.
func (Sealer) GoString() string { return strconv.Quote(redactedSecret) }

// NewSealer builds a sealer from the configured base64 master secret.
func NewSealer(masterSecret Secret) (*Sealer, error) {
	decoded, err := decodeSealingSecret(masterSecret)
	if err != nil {
		return nil, ErrInvalidSealingSecret
	}
	return &Sealer{masterSecret: decoded}, nil
}

// IsSealedCredential reports whether value carries this credential family's
// numeric version marker. This admits an unknown future version into local
// unsealing, where it is refused, instead of sending it to Google. It does not
// authenticate the value; callers must still unseal it.
func IsSealedCredential(value string) bool {
	const familyPrefix = "cdb"
	if !strings.HasPrefix(value, familyPrefix) {
		return false
	}
	versionAndRest := value[len(familyPrefix):]
	colon := strings.IndexByte(versionAndRest, ':')
	if colon == 0 || colon == -1 {
		return false
	}
	for _, digit := range versionAndRest[:colon] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// SealAccess seals an access credential.
func (s *Sealer) SealAccess(payload AccessCredential) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrMalformedSealedCredential
	}
	return s.seal(AccessPurpose, encoded)
}

// UnsealAccess opens an access credential.
func (s *Sealer) UnsealAccess(value string) (AccessCredential, error) {
	encoded, err := s.unseal(AccessPurpose, value)
	if err != nil {
		return AccessCredential{}, err
	}
	var payload AccessCredential
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return AccessCredential{}, ErrMalformedSealedCredential
	}
	return payload, nil
}

// SealRefresh seals a refresh credential.
func (s *Sealer) SealRefresh(payload RefreshCredential) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrMalformedSealedCredential
	}
	return s.seal(RefreshPurpose, encoded)
}

// UnsealRefresh opens a refresh credential.
func (s *Sealer) UnsealRefresh(value string) (RefreshCredential, error) {
	encoded, err := s.unseal(RefreshPurpose, value)
	if err != nil {
		return RefreshCredential{}, err
	}
	var payload RefreshCredential
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return RefreshCredential{}, ErrMalformedSealedCredential
	}
	return payload, nil
}

// SealAuthorizationCode seals an authorization code credential.
func (s *Sealer) SealAuthorizationCode(payload AuthorizationCodeCredential) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrMalformedSealedCredential
	}
	return s.seal(AuthorizationCodePurpose, encoded)
}

// UnsealAuthorizationCode opens an authorization code credential.
func (s *Sealer) UnsealAuthorizationCode(value string) (AuthorizationCodeCredential, error) {
	encoded, err := s.unseal(AuthorizationCodePurpose, value)
	if err != nil {
		return AuthorizationCodeCredential{}, err
	}
	var payload AuthorizationCodeCredential
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return AuthorizationCodeCredential{}, ErrMalformedSealedCredential
	}
	return payload, nil
}

func (s *Sealer) seal(purpose Purpose, payload []byte) (string, error) {
	prefix, err := prefixFor(purpose)
	if err != nil {
		return "", err
	}
	aead, err := s.aead(purpose)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrSealingUnavailable
	}
	// Additional data is the derived wire prefix, and it deliberately differs from
	// the HKDF info label so the two bind different things.
	//
	// What it actually enforces is the purpose tag, and only that. The version it
	// carries is dead weight today, and measurably so: dropping credentialVersion
	// from this argument leaves every test in the package green. parseCredential
	// recomputes the prefix from prefixFor(purpose) — from the compile-time
	// constant, never from the wire bytes — and refuses an unrecognised version in
	// plaintext before this AEAD is reached, so the sealed version and the opened
	// version can never differ on any path a caller can take.
	//
	// That is a tension rather than an oversight, and whoever adds acceptance of a
	// second version has to resolve it: a distinguishable
	// ErrUnknownSealedCredentialVersion needs the plaintext refusal to come first,
	// while binding the version cryptographically needs the AEAD to see what the
	// wire actually said. Today the first governs. Do not read this line as
	// version binding, because it is not.
	sealed := aead.Seal(nil, nonce, payload, []byte(prefix))
	encoded := append(nonce, sealed...)
	return prefix + "." + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (s *Sealer) unseal(want Purpose, value string) ([]byte, error) {
	prefix, got, encoded, err := parseCredential(value)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, ErrSealedCredentialWrongPurpose
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrMalformedSealedCredential
	}
	return s.open(want, prefix, raw)
}

func (s *Sealer) open(purpose Purpose, prefix string, raw []byte) ([]byte, error) {
	aead, err := s.aead(purpose)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrTruncatedSealedCredential
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	// Additional data binds the derived wire prefix, including credentialVersion.
	// It deliberately differs from the HKDF info label; bumping credentialVersion
	// changes it automatically because prefix is derived from credentialMarker.
	payload, err := aead.Open(nil, nonce, ciphertext, []byte(prefix))
	if err != nil {
		return nil, ErrCorruptSealedCredential
	}
	return payload, nil
}

func (s *Sealer) aead(purpose Purpose) (cipher.AEAD, error) {
	// The HKDF info label separates keys per purpose. It deliberately differs
	// from the wire-prefix additional data that the AEAD authenticates.
	label, err := labelFor(purpose)
	if err != nil {
		return nil, err
	}
	derivedKey, err := hkdf.Key(sha256.New, s.masterSecret, nil, label, sealingSecretLength)
	if err != nil {
		return nil, ErrSealingUnavailable
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, ErrSealingUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrSealingUnavailable
	}
	return aead, nil
}

func prefixFor(purpose Purpose) (string, error) {
	switch purpose {
	case AccessPurpose:
		return credentialMarker + "a", nil
	case RefreshPurpose:
		return credentialMarker + "r", nil
	case AuthorizationCodePurpose:
		return credentialMarker + "c", nil
	default:
		return "", ErrSealedCredentialWrongPurpose
	}
}

func labelFor(purpose Purpose) (string, error) {
	switch purpose {
	case AccessPurpose:
		return "cerberus-db-mcp/sealed-credential/access/v1", nil
	case RefreshPurpose:
		return "cerberus-db-mcp/sealed-credential/refresh/v1", nil
	case AuthorizationCodePurpose:
		return "cerberus-db-mcp/sealed-credential/authorization-code/v1", nil
	default:
		return "", ErrSealedCredentialWrongPurpose
	}
}

func parseCredential(value string) (prefix string, purpose Purpose, encoded string, err error) {
	if value == "" {
		return "", "", "", ErrEmptySealedCredential
	}
	version, remainder, found := strings.Cut(value, ":")
	if !found {
		return "", "", "", ErrSealedCredentialMissingPrefix
	}
	if version != credentialVersion {
		return "", "", "", ErrUnknownSealedCredentialVersion
	}
	parts := strings.Split(remainder, ".")
	if len(parts) != 2 {
		return "", "", "", ErrMalformedSealedCredential
	}
	switch parts[0] {
	case "a":
		purpose = AccessPurpose
	case "r":
		purpose = RefreshPurpose
	case "c":
		purpose = AuthorizationCodePurpose
	default:
		return "", "", "", ErrMalformedSealedCredential
	}
	if parts[1] == "" {
		return "", "", "", ErrTruncatedSealedCredential
	}
	prefix, err = prefixFor(purpose)
	if err != nil {
		return "", "", "", err
	}
	return prefix, purpose, parts[1], nil
}

func decodeSealingSecret(secret Secret) ([]byte, error) {
	if secret == "" || strings.ContainsAny(secret.reveal(), whitespace) {
		return nil, ErrInvalidSealingSecret
	}
	decoded, err := base64.StdEncoding.DecodeString(secret.reveal())
	if err != nil || len(decoded) != sealingSecretLength {
		return nil, ErrInvalidSealingSecret
	}
	return decoded, nil
}
