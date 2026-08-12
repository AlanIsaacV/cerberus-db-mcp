package auth

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"
)

// Configuration errors. They are sentinels for the reason internal/db's and
// internal/mcp's are: an error about a variable names the variable and never
// quotes the value. Nothing in this group is a secret — a client ID is public and
// an allowlist is a list of colleagues — but the rule is the repository's and not
// the value's, and a rule with exceptions is one somebody has to remember.
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
	// an afternoon. There is no client secret in this process — validating
	// somebody else's token does not need one — so there is nothing in this group
	// to redact.
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
}

func parseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fmt.Errorf("auth: a CERBERUS_AUTH_* variable could not be parsed: %w", ErrInvalidVariable)
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
		return fmt.Errorf("auth: a CERBERUS_AUTH_* variable could not be parsed: %w", ErrInvalidVariable)
	}
	return fmt.Errorf("auth: %s: %w", strings.Join(named, "; "), ErrInvalidVariable)
}

func (c Config) validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("auth: %s is not set: %w", variableForms["ClientID"].variable, ErrNoClientID)
	}
	// Refused rather than trimmed. A client ID with whitespace in it is a
	// credential file read with its trailing newline or a value pasted across two
	// lines, and both produce a process where every single request is answered 401
	// for a reason no log line can name. Trimming would make that start
	// successfully and work, which is fine right up to the value that trimming
	// cannot repair.
	if strings.ContainsAny(c.ClientID, whitespace) {
		return fmt.Errorf("auth: %s must be %s: %w", variableForms["ClientID"].variable, variableForms["ClientID"].form, ErrInvalidVariable)
	}
	allowed := c.Allowlist()
	if len(allowed) == 0 {
		return fmt.Errorf("auth: %s is not set, or holds no address: %w", variableForms["AllowedEmails"].variable, ErrNoAllowlist)
	}
	for _, address := range allowed {
		if !isAddress(address) {
			// The offending entry is not quoted, and that is not caution about a
			// secret — it is that the rule is the same rule everywhere in this
			// repository. Naming the variable and the form is enough to find it: the
			// operator is looking at the list.
			return fmt.Errorf("auth: %s must be %s: %w", variableForms["AllowedEmails"].variable, variableForms["AllowedEmails"].form, ErrInvalidVariable)
		}
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
