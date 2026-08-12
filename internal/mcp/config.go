package mcp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Configuration errors. They are sentinels for the same reason internal/db's
// are: an error about a variable names the variable and never quotes the value.
// Nothing in this group is a credential today, but the rule is the package's and
// not the value's, and a rule with exceptions is one somebody has to remember.
var (
	// ErrInvalidVariable reports a CERBERUS_MCP_* variable whose value this
	// package cannot use.
	ErrInvalidVariable = errors.New("variable value is not usable")
)

// Config is the whole of this package's configuration. Like internal/db's, it
// comes from the environment and only from the environment: there is no
// configuration file and nothing here reads one.
type Config struct {
	// Address is where the HTTP listener binds.
	//
	// The default is loopback, and that is a safety property rather than a
	// convenience. This objective builds no authentication — [Deps.Middleware] is
	// a seam with a no-op default — so a process that bound every interface out of
	// the box would be an unauthenticated database reader reachable from the
	// network the moment someone ran it. Loopback means exposing it costs a
	// deliberate edit to this one variable, which is a thing a reviewer can see.
	//
	// This is the only address default in the package; there is no fallback
	// elsewhere that could quietly answer for an empty value. TestNoOtherListenAddressDefaultExists
	// checks that by reading the source.
	Address string `env:"CERBERUS_MCP_ADDRESS" envDefault:"127.0.0.1:8080"`

	// Path is where the MCP endpoint is mounted on the mux. It is configurable
	// because the tunnel in front of this process may want to route on it, and it
	// is a whole path rather than a prefix because the SDK's handler serves one
	// endpoint.
	Path string `env:"CERBERUS_MCP_PATH" envDefault:"/mcp"`

	// ShutdownTimeout bounds how long [Server.Run] waits for in-flight calls
	// after a signal before it stops waiting and closes the pools anyway.
	//
	// It is longer than internal/db's query timeout plus its grace by default, so
	// that an ordinary in-flight query finishes rather than being cut off by our
	// own shutdown. It is a bound and not a promise: a client holding a
	// connection open cannot delay this process indefinitely.
	ShutdownTimeout time.Duration `env:"CERBERUS_MCP_SHUTDOWN_TIMEOUT" envDefault:"30s"`

	// Audit names where the audit stream is written: "stdout", "stderr", or a
	// path to a file that is appended to.
	//
	// It is configurable because where this stream belongs is a deployment
	// question that this objective cannot answer — beside the application log on
	// a host with log shipping, in its own file on one without — and answering it
	// wrongly in code would be answering it for every deployment.
	Audit string `env:"CERBERUS_MCP_AUDIT" envDefault:"stdout"`
}

// The audit destinations that are not file paths.
const (
	AuditStdout = "stdout"
	AuditStderr = "stderr"
)

// pathRejected are the characters [Config.Path] may not contain: every ASCII
// whitespace character, and the two that make an http.ServeMux pattern a
// wildcard. See [Config.validate] for why each is refused.
const pathRejected = "{} \t\n\v\f\r"

// LoadConfig reads the configuration from the process environment.
//
// A variable set to the empty string is treated as unset, which is the rule
// internal/db already follows: a variable emptied by a broken template
// substitution should get the default rather than fail a parse, and for the
// listen address in particular "empty" must never resolve to "every interface".
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
// It exists for the reason internal/db's settingForms does: env's own error
// names the struct field rather than the variable, and its message quotes the
// offending value because it wraps strconv's or time's error. So the message is
// discarded and the replacement is built from this table.
// TestVariableFormsCoverEveryField keeps it in step with the struct's tags.
var variableForms = map[string]struct{ variable, form string }{
	"Address":         {"CERBERUS_MCP_ADDRESS", "a host and port, such as 127.0.0.1:8080"},
	"Path":            {"CERBERUS_MCP_PATH", "an absolute path with no spaces or braces, such as /mcp"},
	"ShutdownTimeout": {"CERBERUS_MCP_SHUTDOWN_TIMEOUT", "a duration with a unit, such as 30s"},
	"Audit":           {"CERBERUS_MCP_AUDIT", `"stdout", "stderr", or a path to a file`},
}

func parseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fmt.Errorf("mcp: a CERBERUS_MCP_* variable could not be parsed: %w", ErrInvalidVariable)
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
		return fmt.Errorf("mcp: a CERBERUS_MCP_* variable could not be parsed: %w", ErrInvalidVariable)
	}
	return fmt.Errorf("mcp: %s: %w", strings.Join(named, "; "), ErrInvalidVariable)
}

func (c Config) validate() error {
	if _, _, err := splitAddress(c.Address); err != nil {
		return err
	}
	// Braces and whitespace are refused, not only a missing leading slash,
	// because http.ServeMux reads its argument as a pattern rather than as a
	// path. A value containing a space is a pattern with a method or a host in
	// it and makes mux.Handle panic — which happens in [Server.Run] after the
	// listener has bound and logged "serving", so the operator's evidence is a
	// stack trace from a process that appeared to start. A value containing
	// braces is worse for being accepted: "/mcp/{id}" is a valid wildcard
	// pattern, so the endpoint silently answers on /mcp/anything, which is a
	// wider route surface than the variable looks like it asked for.
	if !strings.HasPrefix(c.Path, "/") || strings.ContainsAny(c.Path, pathRejected) {
		return fmt.Errorf("mcp: %s must be %s: %w", variableForms["Path"].variable, variableForms["Path"].form, ErrInvalidVariable)
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("mcp: %s must be a positive duration: %w", variableForms["ShutdownTimeout"].variable, ErrInvalidVariable)
	}
	if c.Audit == "" {
		return fmt.Errorf("mcp: %s must be %s: %w", variableForms["Audit"].variable, variableForms["Audit"].form, ErrInvalidVariable)
	}
	return nil
}

// splitAddress parses the listen address, rejecting the forms net.Listen would
// accept and this process should not.
//
// A missing host — ":8080" — is refused rather than defaulted, because that
// spelling means every interface and it is the one an operator is most likely to
// reach for without meaning it. Making the whole address explicit is what keeps
// [Config.IsLoopback] answerable by reading the variable.
func splitAddress(address string) (host string, port int, err error) {
	invalid := func() error {
		return fmt.Errorf("mcp: %s must be %s: %w", variableForms["Address"].variable, variableForms["Address"].form, ErrInvalidVariable)
	}
	host, portText, splitErr := net.SplitHostPort(address)
	if splitErr != nil || host == "" {
		return "", 0, invalid()
	}
	// strconv's error text quotes its input, so it is discarded rather than
	// wrapped, exactly as internal/db does for a port.
	port, convErr := strconv.Atoi(portText)
	if convErr != nil || port < 0 || port > 65535 {
		return "", 0, invalid()
	}
	return host, port, nil
}

// IsLoopback reports whether the configured address can only be reached from
// this machine.
//
// It is used to warn at startup rather than to refuse, because refusing would
// make the deployment objective — which puts a Cloudflare Tunnel and an
// authenticating middleware in front of this process — fight its own server. The
// warning is what makes an unauthenticated exposure visible in a log rather than
// silent.
func (c Config) IsLoopback() bool {
	host, _, err := splitAddress(c.Address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
