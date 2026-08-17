package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// realm is what a 401 names in its WWW-Authenticate header. It identifies the
// protection space to a client and it is not a secret, a hostname or a path: it
// is the same string for every deployment of this server, which is why it is a
// constant and not a variable an operator has to set.
const realm = "cerberus-db-mcp"

// The failure classes a rejection is logged under. They are coarse on purpose —
// each one says what an operator should do next and nothing about what was
// presented — and they are distinct because collapsing them would put "the client
// sent no header" and "this person is not allowed" in the same bucket.
const (
	failureAbsentHeader    = "absent_header"
	failureRepeatedHeader  = "repeated_header"
	failureMalformedHeader = "malformed_header"
	failureTokenRejected   = "token_rejected"
	failureUnavailable     = "validation_unavailable"
	failureNotAllowlisted  = "identity_not_allowlisted"
	// failureNoEmailInToken is the allowlist refusal that no edit to the allowlist
	// can fix: Google vouched for the token and returned no address to match. It is
	// its own class because the line an operator reads on the class beside it tells
	// them to add an address, and there is none here to add.
	failureNoEmailInToken               = "no_email_in_token"
	failureEmailUnverified              = "email_unverified"
	failureNoTokenValidation            = "no_validator"
	failureNoSealedCredentialValidation = "no_sealer"
	// Sealed-credential classes are deliberately distinct from Google-token
	// classes: their operator action is to replace the local credential, not to
	// investigate a Google Tokeninfo result.
	failureSealedCredentialExpired      = "sealed_credential_expired"
	failureSealedCredentialCorrupt      = "sealed_credential_corrupt"
	failureSealedCredentialWrongPurpose = "sealed_credential_wrong_purpose"
)

// NewMiddleware builds the authentication seam internal/mcp applies to its MCP
// endpoint.
//
// It validates the configuration it was handed, so a [Config] assembled by hand
// is held to the same rules as one that was loaded — including the two that make
// this middleware's existence meaningful: there is a client ID to check an
// audience against, and there is at least one identity that may pass. A server
// wired with a middleware that admits everybody is worse than one with no
// middleware at all, because it looks authenticated.
//
// The returned function is the only thing this package hands out. The validator
// behind it, its endpoint and its bounds are not reachable or replaceable by a
// caller.
func NewMiddleware(cfg Config, log zerolog.Logger) (func(http.Handler) http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	sealer, err := NewSealer(cfg.SealingSecret)
	if err != nil {
		return nil, err
	}
	v := newValidator(cfg.ClientID, tokeninfoURL, newHTTPClient(validationTimeout), time.Now)
	return newMiddlewareWithSealer(cfg, log, v, sealer, time.Now), nil
}

// newMiddleware is the whole decision, over a validator a test can point
// somewhere else.
//
// The order of the three checks is the order of what each one costs and of who
// can fix it. The header is parsed first because it needs nothing but the request.
// The token is validated second, and only a well-formed header gets that far, so
// a client sending nonsense cannot make this process talk to Google. The
// allowlist is asked last, after the token is known to be Google's, because a
// membership check folded into validation would make "not one of ours" and "not
// valid" the same event — indistinguishable in the log and identical on the wire,
// which is precisely the distinction an operator needs when their colleague
// cannot connect.
func newMiddleware(cfg Config, log zerolog.Logger, v *validator) func(http.Handler) http.Handler {
	sealer, _ := NewSealer(cfg.SealingSecret)
	// This helper is used only by package tests. [NewMiddleware] validates the
	// configuration before reaching here; NewSealer already returns nil on error,
	// and that nil sealer fails closed below.
	return newMiddlewareWithSealer(cfg, log, v, sealer, time.Now)
}

// newMiddlewareWithSealer is the whole decision, with the local credential
// dependencies explicit so its expiry boundary can be driven without sleeping.
func newMiddlewareWithSealer(cfg Config, log zerolog.Logger, v *validator, sealer *Sealer, now func() time.Time) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedEmails))
	for _, address := range cfg.Allowlist() {
		allowed[address] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			values := r.Header.Values("Authorization")
			// Read once and then removed from the request, before the branch below and
			// so on every path out of this handler, admitted or refused. What is
			// downstream is the go-sdk, which hands a tool handler the inbound header map
			// by reference as CallToolRequest.Extra.Header and sanitises nothing; leaving
			// the credential there would mean a debug line added in internal/mcp — a
			// package that is not supposed to know what a token is — could print one.
			// Deleting it is what makes "the token lives in internal/auth and nowhere
			// else" true of the process and not only of the source.
			r.Header.Del("Authorization")
			token, class := bearerToken(values)
			if class != "" {
				unauthorized(w, log, class)
				return
			}
			if IsSealedCredential(token) {
				if sealer == nil {
					// A nil sealer is a process construction mistake, not a statement
					// about the credential. Unsealing has no upstream, so once a sealer
					// exists every sealed-credential failure is local and credential
					// specific; a missing one cannot be repaired by reauthorizing.
					unauthorized(w, log, failureNoSealedCredentialValidation)
					return
				}
				sealed, err := sealer.UnsealAccess(token)
				if err != nil {
					class := failureSealedCredentialCorrupt
					if errors.Is(err, ErrSealedCredentialWrongPurpose) {
						class = failureSealedCredentialWrongPurpose
					}
					// Unsealing is entirely local: it has no upstream whose temporary
					// failure could make a good credential look bad. With a sealer in
					// place, every refusal here is therefore a statement about the
					// credential and is challenged; there is no sealed counterpart to
					// validation_unavailable.
					unauthorized(w, log, class)
					return
				}
				if !sealed.ExpiresAt.After(now()) {
					unauthorized(w, log, failureSealedCredentialExpired)
					return
				}
				caller := claims{subject: sealed.Subject, email: sealed.Email, emailVerified: sealed.Verified}
				if caller.subject == "" || normaliseEmail(caller.email) == "" {
					forbidden(w, log, failureNoEmailInToken, caller, true)
					return
				}
				if !allowed[normaliseEmail(caller.email)] {
					forbidden(w, log, failureNotAllowlisted, caller, true)
					return
				}
				if !caller.emailVerified {
					forbidden(w, log, failureEmailUnverified, caller, true)
					return
				}
				next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), Identity{
					Subject: caller.subject,
					Email:   caller.email,
				})))
				return
			}
			if v == nil {
				// A middleware with no validator would admit every caller, so it admits
				// none. Unreachable through [NewMiddleware]; here because the failure
				// mode of the alternative is silent.
				unauthorized(w, log, failureNoTokenValidation)
				return
			}
			caller, err := v.validate(r.Context(), token)
			if err != nil {
				class := failureUnavailable
				if errors.Is(err, errTokenRejected) {
					class = failureTokenRejected
				}
				unauthorized(w, log, class)
				return
			}
			// Before the allowlist, because the two are different problems with
			// different fixes: the allowlist's own line exists so an operator can paste
			// the refused address into their configuration, and here there is no address
			// to paste. Whether Tokeninfo returns `email` for an *access* token at all is
			// still open in this objective; if it does not, every correctly configured
			// caller arrives here, and this class is what keeps the first hour of
			// diagnosis off an allowlist that was already right.
			if normaliseEmail(caller.email) == "" {
				forbidden(w, log, failureNoEmailInToken, caller, false)
				return
			}
			// Membership before verification, so that a stranger's rejection reads as
			// "not on the list" and only an address an operator actually wrote down can
			// produce the narrower "their email is not verified" — which is the one an
			// operator has to do something unusual about.
			if !allowed[normaliseEmail(caller.email)] {
				forbidden(w, log, failureNotAllowlisted, caller, false)
				return
			}
			if !caller.emailVerified {
				forbidden(w, log, failureEmailUnverified, caller, false)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), Identity{
				Subject: caller.subject,
				Email:   caller.email,
			})))
		})
	}
}

// bearerToken extracts the one bearer token a request is allowed to carry, or
// names the class of what was wrong with the attempt.
//
// Exactly one Authorization header, exactly two fields, the first of them Bearer,
// and a second that is not empty. More than one header is refused rather than
// resolved by taking the first or the last: two headers mean two clients'
// intentions in one request — a proxy adding one and an agent adding another —
// and no reading of that is safe enough to guess at.
func bearerToken(values []string) (token, failureClass string) {
	switch {
	case len(values) == 0:
		return "", failureAbsentHeader
	case len(values) > 1:
		return "", failureRepeatedHeader
	}
	// Fields rather than a split on one space, so that "Bearer  x" is the token x
	// and "Bearer x y" is refused instead of yielding "x y".
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", failureMalformedHeader
	}
	return parts[1], ""
}

// unauthorized answers a request this process could not authenticate.
//
// The body is one word and the log line carries the class. The challenge, when it
// is sent, is what makes this a 401 and not a wall: it tells the client what kind
// of credential this endpoint wants, which is the difference between an agent
// that can prompt for a login and one that reports a broken server. When it is
// not sent, see [challengesTheCredential].
func unauthorized(w http.ResponseWriter, log zerolog.Logger, class string) {
	// The application log, never the audit stream. An AuditEvent is shaped around a
	// tool call — tool, alias, statement, verdict — and a request refused here
	// reached no tool, so every one of those fields would be empty. What was
	// attempted against somebody else's database is the audit stream's subject;
	// who failed to get in is this one's.
	log.Warn().
		Str("failure_class", class).
		Int("status", http.StatusUnauthorized).
		Msg("request refused before any tool: no usable bearer token")
	if challengesTheCredential(class) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// challengesTheCredential reports whether a 401 of this class is a statement
// about what the client presented.
//
// To a spec-compliant MCP or OAuth client, WWW-Authenticate means "the credential
// you presented is not acceptable here, get another one" — so it is the right
// answer to an absent, malformed or rejected one, and the wrong answer to
// validation_unavailable, where the credential may be perfectly good and what
// failed is this process's conversation with Google: a timeout, a 429, a shed
// concurrency slot, a body over the cap. Challenging there would push every
// connected agent into a reauthorization flow over a transient fault that a retry
// would have cleared. no_validator is the same shape of thing — a construction
// mistake in this process — and no credential a caller can fetch will change it.
func challengesTheCredential(class string) bool {
	switch class {
	case failureAbsentHeader, failureRepeatedHeader, failureMalformedHeader, failureTokenRejected,
		failureSealedCredentialExpired, failureSealedCredentialCorrupt, failureSealedCredentialWrongPurpose:
		return true
	default:
		return false
	}
}

// forbidden answers a request whose token was good and whose identity is not
// admitted here.
//
// It logs the identity, in full and unredacted. That is the whole value of the
// line: an allowlist refusal is nearly always an operator who has not added a
// colleague yet, and a log that says only "somebody was refused" leaves them
// guessing at the address to add. An email that Google vouched for is not a
// credential, and the token that carried it is not in this line in any form.
//
// The auth_refusal field exists to be told apart from the other 403 this process
// can answer: the go-sdk turns on DNS-rebinding protection by itself when the
// listener is loopback, and answers 403 to any request whose Host header is not
// loopback either. That refusal happens inside the wrapped handler, after this
// middleware has already admitted the request, and produces no line from this
// package — so a 403 with an auth_refusal field is this one, and a 403 without any
// log line from here is that one. Which of this package's own 403s it is, the
// failure_class says.
func forbidden(w http.ResponseWriter, log zerolog.Logger, class string, caller claims, sealed bool) {
	log.Warn().
		Str("failure_class", class).
		Str("auth_refusal", "identity_allowlist").
		Str("email", caller.email).
		Str("subject", caller.subject).
		Bool("email_verified", caller.emailVerified).
		Int("status", http.StatusForbidden).
		Msg(refusalMessage(class, sealed))
	http.Error(w, "forbidden: this identity is not allowed on this server", http.StatusForbidden)
}

// refusalMessage is what each 403 tells the operator reading it to do next, which
// is the only thing that differs between the three of them.
func refusalMessage(class string, sealed bool) string {
	if class == failureNoEmailInToken {
		if sealed {
			return "request refused before any tool: this server's sealed credential carried no usable subject or email address; replace the local credential or investigate the local credential issuer before changing the allowlist"
		}
		// Named as the wrong problem, this reads as an allowlist that is missing an
		// address — and the address it appears to be missing does not exist, so the
		// operator edits a correct configuration for as long as it takes them to
		// notice that the refused email field is empty.
		return "request refused before any tool: Google vouched for this token and returned no email address with it, so there is nothing for the allowlist to match; check that the client requested the email scope before changing the allowlist"
	}
	return "request refused before any tool: the identity behind this token is not allowed on this server"
}
