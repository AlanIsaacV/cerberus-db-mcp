package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	assertionType          = "cerberus-gw-assertion+jwt"
	assertionTypeFamily    = "cerberus-gw"
	assertionAlgorithm     = "EdDSA"
	assertionIssuer        = "cerberus-gw"
	assertionSegments      = 3
	assertionClockSkew     = 30 * time.Second
	assertionMaxLifetime   = 300
	gatewayKeyIDBytes      = 8
	gatewayPublicKeyLength = ed25519.PublicKeySize
)

var (
	errAssertionRejected      = errors.New("gateway assertion rejected")
	errAssertionWrongAudience = errors.New("gateway assertion is for another audience")
	errAssertionExpired       = errors.New("gateway assertion expired")
	errInvalidGatewayKey      = errors.New("gateway public key is not usable")
)

type assertionHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type assertionClaims struct {
	Iss    string   `json:"iss"`
	Aud    string   `json:"aud"`
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	Perms  []string `json:"perms"`
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

type assertionVerifier struct {
	publicKey ed25519.PublicKey
	keyID     string
	audience  string
}

func isGatewayAssertion(token string) bool {
	first, _, _ := strings.Cut(token, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(first, "="))
	if err != nil {
		return false
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(decoded, &header) != nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(header.Typ), assertionTypeFamily)
}

func isUnreadableAssertion(token string) bool {
	segments := strings.Split(token, ".")
	if len(segments) != assertionSegments {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segments[0], "="))
	if err != nil || len(decoded) == 0 || decoded[0] != '{' {
		return false
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(decoded, &header) != nil {
		return true
	}
	typ, present := header["typ"]
	if !present {
		return false
	}
	return len(typ) == 0 || typ[0] != '"'
}

func decodeGatewayPublicKey(encoded string) (ed25519.PublicKey, error) {
	if encoded == "" || strings.ContainsAny(encoded, whitespace) {
		return nil, errInvalidGatewayKey
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != gatewayPublicKeyLength {
		return nil, errInvalidGatewayKey
	}
	return ed25519.PublicKey(decoded), nil
}

func gatewayKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:gatewayKeyIDBytes])
}

func (c Config) GatewayTrust() (audience, kid string, trusted bool) {
	verifier := newAssertionVerifier(c)
	if verifier == nil {
		return "", "", false
	}
	return verifier.audience, verifier.keyID, true
}

func newAssertionVerifier(cfg Config) *assertionVerifier {
	if cfg.GatewayPublicKey == "" || cfg.GatewayAudience == "" {
		return nil
	}
	publicKey, err := decodeGatewayPublicKey(cfg.GatewayPublicKey)
	if err != nil {
		return nil
	}
	return &assertionVerifier{
		publicKey: publicKey,
		keyID:     gatewayKeyID(publicKey),
		audience:  cfg.GatewayAudience,
	}
}

func (v *assertionVerifier) verify(token string, now time.Time) (assertionClaims, error) {
	segments := strings.Split(token, ".")
	if len(segments) != assertionSegments {
		return assertionClaims{}, errAssertionRejected
	}
	var header assertionHeader
	if !decodeSegment(segments[0], &header) {
		return assertionClaims{}, errAssertionRejected
	}
	if header.Alg != assertionAlgorithm || header.Typ != assertionType || header.Kid != v.keyID {
		return assertionClaims{}, errAssertionRejected
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return assertionClaims{}, errAssertionRejected
	}
	if !ed25519.Verify(v.publicKey, []byte(segments[0]+"."+segments[1]), signature) {
		return assertionClaims{}, errAssertionRejected
	}
	var asserted assertionClaims
	if !decodeSegment(segments[1], &asserted) {
		return assertionClaims{}, errAssertionRejected
	}
	if asserted.Iss != assertionIssuer {
		return assertionClaims{}, errAssertionRejected
	}
	if asserted.Aud != v.audience {
		return assertionClaims{}, errAssertionWrongAudience
	}
	if asserted.Sub == "" || asserted.Email == "" {
		return assertionClaims{}, errAssertionRejected
	}
	if asserted.Iat <= 0 || asserted.Exp-asserted.Iat > assertionMaxLifetime {
		return assertionClaims{}, errAssertionRejected
	}
	if time.Unix(asserted.Iat, 0).After(now.Add(assertionClockSkew)) {
		return assertionClaims{}, errAssertionRejected
	}
	if !time.Unix(asserted.Exp, 0).After(now) {
		return assertionClaims{}, errAssertionExpired
	}
	return asserted, nil
}

func decodeSegment(segment string, into any) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	return json.Unmarshal(decoded, into) == nil
}
