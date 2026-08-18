package auth

import (
	"errors"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"
)

// This file holds the sealing master secret — [Config.SealingSecret] is where it
// enters the process — so, like sealing.go, like tokeninfo.go and like
// internal/authflow/config.go, it imports no formatter and no logger. That is why
// the refusals below are assembled from constants rather than written with
// fmt.Errorf: a file that has nothing to render with cannot render a value it was
// handed by mistake, whatever the value ends up being called.

// Configuration errors. They are sentinels for the reason internal/db's and
// internal/mcp's are: an error about a variable names the variable and never
// quotes the value. The sealing secret makes that essential here, but the rule
// applies to every value: a rule with exceptions is one somebody has to
// remember.
var (
	// ErrInvalidVariable reports a CERBERUS_AUTH_* variable whose value this
	// package cannot use.
	ErrInvalidVariable = errors.New("variable value is not usable")
	// ErrNoClientID reports a missing Google OAuth client ID. Without it there is
	// nothing to check a token's audience against, and a validator that accepted
	// any audience would accept tokens issued to any Google application on earth.
	ErrNoClientID = errors.New("no Google OAuth client ID was configured")
	// ErrNoAllowlist reports an absent or empty identity allowlist.
	//
	// It is a refusal rather than a default because both defaults are wrong: an
	// empty list meaning "allow every Google account" is a database reader on the
	// public internet, and an empty list meaning "allow nobody" is a server that
	// starts, logs nothing unusual and answers 403 to its only user. This follows
	// the ErrNoAuditor and ErrNoGate convention of internal/mcp and internal/db —
	// a dependency whose absence would leave a guarantee unenforced fails
	// construction by name.
	ErrNoAllowlist = errors.New("no identity allowlist was configured")
	// ErrNoSealingMaterial reports a missing master secret. Credentials sealed by
	// this process must remain usable across a restart, so making one up here
	// would turn a deploy into a silent mass logout.
	ErrNoSealingMaterial = errors.New("no credential sealing material was configured")
)

// Config is the whole of this package's configuration. Like the other two
// groups' it comes from the environment and only from the environment: there is
// no configuration file and nothing here reads one.
type Config struct {
	// ClientID is the OAuth 2.0 client ID this deployment accepts tokens for. A
	// token is only usable here when both `aud` and `azp` on Google's Tokeninfo
	// response equal it, which is what stops a token minted for some other
	// application from being replayed at this server.
	//
	// It is a public identifier and it is logged unredacted at startup on
	// purpose: a client ID that does not match the one the agent was configured
	// with produces a 401 for every request and nothing else, and seeing both
	// values in a deploy log is how that gets diagnosed in minutes rather than in
	// an afternoon. It remains public even though this configuration also holds
	// the master secret used to seal this server's own credentials.
	ClientID string `env:"CERBERUS_AUTH_GOOGLE_CLIENT_ID"`

	// AllowedEmails is the set of verified Google addresses that may reach a
	// tool, as a comma-separated list.
	//
	// Addresses rather than subject ids, because nobody can write a `sub` into a
	// deployment's environment before that person has logged in once; and
	// addresses rather than a domain, because a domain admits every account an
	// administrator creates in it, including ones created after this deployment
	// was reviewed. Entries are trimmed and compared case-insensitively, and a
	// blank entry — the trailing comma somebody leaves behind — is ignored rather
	// than treated as an address that can never match.
	AllowedEmails []string `env:"CERBERUS_AUTH_ALLOWED_EMAILS" envSeparator:","`

	// SealingSecret is the base64-encoded, 32-byte master secret from which the
	// distinct access and refresh credential keys are derived. It is deliberately
	// not generated here: a generated value would invalidate every credential on
	// the next process restart.
	SealingSecret Secret `env:"CERBERUS_AUTH_SEALING_SECRET"`
}

// LoadConfig reads the configuration from the process environment.
//
// A variable set to the empty string is treated as unset, which is the rule both
// other configuration groups already follow: a variable emptied by a broken
// template substitution should be indistinguishable from one nobody set, so that
// it fails the same way instead of failing a different way somebody works around.
func LoadConfig() (*Config, error) {
	environ := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && value != "" {
			environ[key] = value
		}
	}
	return LoadConfigFrom(environ)
}

// LoadConfigFrom reads the configuration from an explicit environment, so that
// configuration can be tested without mutating the process's own.
func LoadConfigFrom(environ map[string]string) (*Config, error) {
	var cfg Config
	if err := env.ParseWithOptions(&cfg, env.Options{Environment: environ}); err != nil {
		return nil, parseError(err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// variableForms is, per field of [Config], the variable it is read from and the
// form a usable value takes.
//
// It exists for the reason internal/mcp's does: env's own error names the struct
// field rather than the variable, and its message quotes the offending value
// because it wraps strconv's or time's error. So the message is discarded and the
// replacement is built from this table. TestVariableFormsCoverEveryField keeps it
// in step with the struct's tags.
var variableForms = map[string]struct{ variable, form string }{
	"ClientID":      {"CERBERUS_AUTH_GOOGLE_CLIENT_ID", "a Google OAuth client ID, with no spaces in it"},
	"AllowedEmails": {"CERBERUS_AUTH_ALLOWED_EMAILS", "a comma-separated list of email addresses"},
	"SealingSecret": {"CERBERUS_AUTH_SEALING_SECRET", "a base64-encoded 32-byte master secret, with no spaces in it"},
}

// variableFault is a refusal naming a variable, assembled rather than formatted.
// Its message is built from constants and variable names alone, and its cause is
// what errors.Is answers on, so it wraps exactly as the fmt.Errorf %w it replaced
// did. internal/authflow/config.go carries the same type for the same reason.
type variableFault struct {
	message string
	cause   error
}

func (f variableFault) Error() string { return f.message }

func (f variableFault) Unwrap() error { return f.cause }

func fault(detail string, cause error) error {
	return variableFault{message: "auth: " + detail + ": " + cause.Error(), cause: cause}
}

// mustBe is the "this variable must be that form" half of a refusal, for the
// fields whose value can be present and unusable.
func mustBe(field string) string {
	return variableForms[field].variable + " must be " + variableForms[field].form
}

func parseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fault("a CERBERUS_AUTH_* variable could not be parsed", ErrInvalidVariable)
	}
	var named []string
	for _, member := range aggregate.Errors {
		var parseErr env.ParseError
		if !errors.As(member, &parseErr) {
			continue
		}
		if f, ok := variableForms[parseErr.Name]; ok {
			named = append(named, f.variable+" must be "+f.form)
		}
	}
	if len(named) == 0 {
		// env grew a failure this code does not recognise. Its own text holds the
		// value, so it goes no further.
		return fault("a CERBERUS_AUTH_* variable could not be parsed", ErrInvalidVariable)
	}
	return fault(strings.Join(named, "; "), ErrInvalidVariable)
}

func (c Config) validate() error {
	if c.ClientID == "" {
		return fault(variableForms["ClientID"].variable+" is not set", ErrNoClientID)
	}
	// Refused rather than trimmed. A client ID with whitespace in it is a
	// credential file read with its trailing newline or a value pasted across two
	// lines, and both produce a process where every single request is answered 401
	// for a reason no log line can name. Trimming would make that start
	// successfully and work, which is fine right up to the value that trimming
	// cannot repair.
	if strings.ContainsAny(c.ClientID, whitespace) {
		return fault(mustBe("ClientID"), ErrInvalidVariable)
	}
	allowed := c.Allowlist()
	if len(allowed) == 0 {
		return fault(variableForms["AllowedEmails"].variable+" is not set, or holds no address", ErrNoAllowlist)
	}
	for _, address := range allowed {
		if !isAddress(address) {
			// The offending entry is not quoted, and that is not caution about a
			// secret — it is that the rule is the same rule everywhere in this
			// repository. Naming the variable and the form is enough to find it: the
			// operator is looking at the list.
			return fault(mustBe("AllowedEmails"), ErrInvalidVariable)
		}
	}
	if c.SealingSecret == "" {
		return fault(variableForms["SealingSecret"].variable+" is not set", ErrNoSealingMaterial)
	}
	if _, err := decodeSealingSecret(c.SealingSecret); err != nil {
		return fault(mustBe("SealingSecret"), ErrInvalidVariable)
	}
	return nil
}

// whitespace is every ASCII whitespace character, spelled out because
// unicode.IsSpace over a client ID is a wider question than this needs.
const whitespace = " \t\n\v\f\r"

// Allowlist is [Config.AllowedEmails] in the form the middleware matches
// against: trimmed, lowercased, and with the blank entries dropped.
//
// Lowercased on both sides, because the address Google returns and the address an
// operator typed differ in case often enough that a case-sensitive allowlist
// would refuse the right person for a reason invisible in the log.
//
// It is exported so that the binary can log this list beside the raw one at
// startup. That is the pair an operator debugging a 403 needs: the raw slice is
// what reads against the variable they set, and this one is what a request is
// actually compared with, so a trailing comma or a stray space is visible as the
// difference between the two rather than inferred from a count.
func (c Config) Allowlist() []string {
	out := make([]string, 0, len(c.AllowedEmails))
	for _, entry := range c.AllowedEmails {
		if address := normaliseEmail(entry); address != "" {
			out = append(out, address)
		}
	}
	return out
}

func normaliseEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// isAddress reports whether an allowlist entry can ever match an email Google
// returns.
//
// It is a shape check and not an RFC 5322 parse. What it is for is the entry that
// silently matches nothing: a bare domain written by an operator who expected the
// list to admit everyone in it, a name with the @ left out, two addresses
// separated by a space instead of a comma. Each of those starts a server that
// answers 403 to its only user, and an unmatchable entry is much cheaper to find
// at startup than in a log.
func isAddress(address string) bool {
	local, domain, found := strings.Cut(address, "@")
	if !found || local == "" || domain == "" {
		return false
	}
	if strings.Contains(domain, "@") {
		return false
	}
	return !strings.ContainsAny(address, whitespace)
}
