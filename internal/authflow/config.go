// Package authflow owns this process's authorization-server half of the Google
// authorization-code flow. It intentionally sits beside auth: auth validates a
// credential presented to the MCP endpoint, while this package starts a new
// authorization and turns Google's answer into this server's authorization code.
package authflow

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
)

// This file holds this deployment's Google client secret — [Config.ClientSecret]
// is where it enters the process — so, like exchange.go and like
// internal/auth/tokeninfo.go, it imports no formatter and no logger. That is why
// the refusals below are assembled from constants rather than written with
// fmt.Errorf: a file that has nothing to render with cannot render a value it
// was handed by mistake.

var (
	// ErrInvalidVariable reports a CERBERUS_AUTH_* variable whose value cannot
	// safely configure the authorization flow.
	ErrInvalidVariable = errors.New("variable value is not usable")
	// ErrNoGoogleClientMaterial reports a missing Google OAuth client secret.
	ErrNoGoogleClientMaterial = errors.New("no Google OAuth client secret was configured")
	// ErrNoPublicBaseURL reports the externally reachable HTTPS origin this
	// process needs for its Google callback.
	ErrNoPublicBaseURL = errors.New("no public base URL was configured")
	// ErrNoClientRedirectURIs reports an empty client registry. There is no
	// dynamic registration in this server, so an empty registry is a deployment
	// mistake rather than an endpoint that silently admits no client.
	ErrNoClientRedirectURIs = errors.New("no client redirect URIs were configured")
)

// Config is the authorization flow's environment-only configuration.
type Config struct {
	// ClientSecret authenticates this deployment's authorization-code exchange
	// with Google. auth.Secret redacts every ordinary rendering.
	ClientSecret auth.Secret `env:"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET"`
	// PublicBaseURL is the HTTPS URL clients and Google use to reach this
	// process. Its trailing slash is removed during validation.
	PublicBaseURL string `env:"CERBERUS_AUTH_PUBLIC_BASE_URL"`
	// ClientRedirectURIs is the complete, exact-match registry for clients this
	// deployment may redirect an authorization code to.
	ClientRedirectURIs []string `env:"CERBERUS_AUTH_CLIENT_REDIRECT_URIS" envSeparator:","`
}

// LoadConfig reads configuration from the process environment.
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

// LoadConfigFrom reads configuration from an explicit environment for tests.
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

var variableForms = map[string]struct{ variable, form string }{
	"ClientSecret":       {"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET", "a Google OAuth client secret, with no spaces in it"},
	"PublicBaseURL":      {"CERBERUS_AUTH_PUBLIC_BASE_URL", "an absolute HTTPS URL with no query or fragment"},
	"ClientRedirectURIs": {"CERBERUS_AUTH_CLIENT_REDIRECT_URIS", "a comma-separated list of absolute client redirect URIs with no fragment"},
}

// variableFault is a refusal naming a variable, assembled rather than
// formatted. Its message is built from constants and variable names alone, and
// its cause is what errors.Is answers on.
type variableFault struct {
	message string
	cause   error
}

func (f variableFault) Error() string { return f.message }

func (f variableFault) Unwrap() error { return f.cause }

func fault(detail string, cause error) error {
	return variableFault{message: "authflow: " + detail + ": " + cause.Error(), cause: cause}
}

func parseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fault("a CERBERUS_AUTH_* variable could not be parsed", ErrInvalidVariable)
	}
	var named []string
	for _, member := range aggregate.Errors {
		var parseErr env.ParseError
		if errors.As(member, &parseErr) {
			if form, ok := variableForms[parseErr.Name]; ok {
				named = append(named, form.variable+" must be "+form.form)
			}
		}
	}
	if len(named) == 0 {
		return fault("a CERBERUS_AUTH_* variable could not be parsed", ErrInvalidVariable)
	}
	return fault(strings.Join(named, "; "), ErrInvalidVariable)
}

func (c *Config) validate() error {
	if c.ClientSecret == "" {
		return fault(variableForms["ClientSecret"].variable+" is not set", ErrNoGoogleClientMaterial)
	}
	if strings.ContainsAny(string(c.ClientSecret), whitespace) {
		return fault(mustBe("ClientSecret"), ErrInvalidVariable)
	}
	baseURL, ok := normalisePublicBaseURL(c.PublicBaseURL)
	if !ok {
		if c.PublicBaseURL == "" {
			return fault(variableForms["PublicBaseURL"].variable+" is not set", ErrNoPublicBaseURL)
		}
		return fault(mustBe("PublicBaseURL"), ErrInvalidVariable)
	}
	c.PublicBaseURL = baseURL
	if len(c.ClientRedirectURIs) == 0 || onlyBlank(c.ClientRedirectURIs) {
		return fault(variableForms["ClientRedirectURIs"].variable+" is not set, or holds no URI", ErrNoClientRedirectURIs)
	}
	for _, redirectURI := range c.ClientRedirectURIs {
		if !validClientRedirectURI(redirectURI) {
			return fault(mustBe("ClientRedirectURIs"), ErrInvalidVariable)
		}
	}
	return nil
}

func mustBe(field string) string {
	return variableForms[field].variable + " must be " + variableForms[field].form
}

func normalisePublicBaseURL(value string) (string, bool) {
	if strings.ContainsAny(value, whitespace) || strings.ContainsAny(value, "?#") {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String(), true
}

func onlyBlank(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func validClientRedirectURI(value string) bool {
	if strings.ContainsAny(value, whitespace) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme != "" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

const whitespace = " \t\n\v\f\r"
