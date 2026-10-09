package redisdb

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/caarlos0/env/v11"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

var (
	ErrNoAliases           = errors.New("no redis aliases are configured")
	ErrInvalidAlias        = errors.New("alias name is not usable in a variable name")
	ErrDuplicateAlias      = errors.New("two aliases share one name or one variable family")
	ErrMissingVariable     = errors.New("required variable is not set")
	ErrInvalidVariable     = errors.New("variable value is not usable")
	ErrUnsupportedVariable = errors.New("variable is set and is not read by this package")
)

type Secret string

const redacted = "[redacted]"

func (Secret) String() string { return redacted }

func (Secret) GoString() string { return strconv.Quote(redacted) }

func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (s Secret) reveal() string { return string(s) }

type TLSMode string

const (
	TLSDisable         TLSMode = "disable"
	TLSRequire         TLSMode = "require"
	TLSRequireInsecure TLSMode = "require-insecure"
)

func tlsModes() []TLSMode {
	return []TLSMode{TLSDisable, TLSRequire, TLSRequireInsecure}
}

type Settings struct {
	CommandTimeout  time.Duration `env:"CERBERUS_REDIS_COMMAND_TIMEOUT" envDefault:"20s"`
	ConnectTimeout  time.Duration `env:"CERBERUS_REDIS_CONNECT_TIMEOUT" envDefault:"10s"`
	MaxConns        int           `env:"CERBERUS_REDIS_MAX_CONNS" envDefault:"4"`
	ReplyByteBudget int           `env:"CERBERUS_REDIS_REPLY_BYTE_BUDGET" envDefault:"32768"`
	MaxElements     int           `env:"CERBERUS_REDIS_MAX_ELEMENTS" envDefault:"1000"`
	MaxCount        int           `env:"CERBERUS_REDIS_MAX_COUNT" envDefault:"1000"`
	MaxArgs         int           `env:"CERBERUS_REDIS_MAX_ARGS" envDefault:"1024"`
	MaxArgvBytes    int           `env:"CERBERUS_REDIS_MAX_ARGV_BYTES" envDefault:"65536"`
	Aliases         []string      `env:"CERBERUS_REDIS_ALIASES" envSeparator:","`
}

func (s Settings) GateLimits() redisgate.Limits {
	return redisgate.Limits{
		MaxElements: s.MaxElements,
		MaxCount:    s.MaxCount,
		MaxArgs:     s.MaxArgs,
		MaxBytes:    s.MaxArgvBytes,
	}
}

func (s Settings) validate() error {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"CERBERUS_REDIS_COMMAND_TIMEOUT", s.CommandTimeout > 0},
		{"CERBERUS_REDIS_CONNECT_TIMEOUT", s.ConnectTimeout > 0},
		{"CERBERUS_REDIS_MAX_CONNS", s.MaxConns > 0},
		{"CERBERUS_REDIS_REPLY_BYTE_BUDGET", s.ReplyByteBudget > 0},
		{"CERBERUS_REDIS_MAX_ELEMENTS", s.MaxElements > 0},
		{"CERBERUS_REDIS_MAX_COUNT", s.MaxCount > 0},
		{"CERBERUS_REDIS_MAX_ARGS", s.MaxArgs > 0},
		{"CERBERUS_REDIS_MAX_ARGV_BYTES", s.MaxArgvBytes > 0},
	} {
		if !c.ok {
			return fmt.Errorf("redisdb: %s must be positive: %w", c.name, ErrInvalidVariable)
		}
	}
	return nil
}

type AliasSpec struct {
	Alias    string
	Host     string
	Port     int
	Database int
	User     string
	Password Secret
	TLS      TLSMode
}

type Config struct {
	Settings Settings
	Aliases  []AliasSpec
}

const (
	suffixHost      = "_HOST"
	suffixPort      = "_PORT"
	suffixUser      = "_USER"
	suffixPassword  = "_PASSWORD"
	suffixDatabases = "_DATABASES"
	suffixTLS       = "_TLS"
)

func aliasSuffixes() []string {
	return []string{suffixHost, suffixPort, suffixUser, suffixPassword, suffixDatabases, suffixTLS}
}

const (
	aliasPrefix           = "CERBERUS_REDIS_"
	derivedAliasSeparator = "."
	maxAliasLength        = 64
)

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

func LoadConfigFrom(environ map[string]string) (*Config, error) {
	var settings Settings
	if err := env.ParseWithOptions(&settings, env.Options{Environment: environ}); err != nil {
		return nil, settingParseError(err)
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}

	aliases := make([]string, 0, len(settings.Aliases))
	for _, a := range settings.Aliases {
		if a = strings.TrimSpace(a); a != "" {
			aliases = append(aliases, a)
		}
	}
	if len(aliases) == 0 {
		return nil, fmt.Errorf("redisdb: CERBERUS_REDIS_ALIASES is empty: %w", ErrNoAliases)
	}
	settings.Aliases = aliases

	families := make([]string, len(aliases))
	seen := make(map[string]int, len(aliases))
	for i, alias := range aliases {
		family, err := variableFamily(alias)
		if err != nil {
			return nil, fmt.Errorf("redisdb: CERBERUS_REDIS_ALIASES entry %d %w", i+1, err)
		}
		if other, ok := seen[family]; ok {
			return nil, fmt.Errorf("redisdb: CERBERUS_REDIS_ALIASES entries %d and %d resolve to one variable family: %w", other+1, i+1, ErrDuplicateAlias)
		}
		seen[family] = i
		families[i] = family
	}

	names := make(map[string]bool, len(aliases))
	for _, alias := range aliases {
		names[alias] = true
	}

	cfg := &Config{Settings: settings}
	for i, alias := range aliases {
		specs, err := parseAlias(alias, families[i], environ)
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			if err := claimAlias(names, spec.Alias, families[i]+suffixDatabases); err != nil {
				return nil, err
			}
			cfg.Aliases = append(cfg.Aliases, spec)
		}
	}
	return cfg, nil
}

func claimAlias(names map[string]bool, name, variable string) error {
	if names[name] {
		return fmt.Errorf("redisdb: %s derives an alias name that is already in use: %w", variable, ErrDuplicateAlias)
	}
	names[name] = true
	return nil
}

func settingParseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fmt.Errorf("redisdb: a CERBERUS_REDIS_* setting could not be parsed: %w", ErrInvalidVariable)
	}
	settingsType := reflect.TypeFor[Settings]()
	var named []string
	for _, member := range aggregate.Errors {
		var parseErr env.ParseError
		if !errors.As(member, &parseErr) {
			continue
		}
		field, ok := settingsType.FieldByName(parseErr.Name)
		if !ok {
			continue
		}
		form := "a whole number"
		if field.Type == reflect.TypeFor[time.Duration]() {
			form = "a duration with a unit (ms, s, m or h)"
		}
		named = append(named, field.Tag.Get("env")+" must be "+form)
	}
	if len(named) == 0 {
		return fmt.Errorf("redisdb: a CERBERUS_REDIS_* setting could not be parsed: %w", ErrInvalidVariable)
	}
	return fmt.Errorf("redisdb: %s: %w", strings.Join(named, "; "), ErrInvalidVariable)
}

func settingVariables() []string {
	settingsType := reflect.TypeFor[Settings]()
	out := make([]string, 0, settingsType.NumField())
	for i := range settingsType.NumField() {
		if name := settingsType.Field(i).Tag.Get("env"); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func variableFamily(alias string) (string, error) {
	if alias == "" {
		return "", fmt.Errorf("is empty: %w", ErrInvalidAlias)
	}
	if len(alias) > maxAliasLength {
		return "", fmt.Errorf("is longer than %d characters: %w", maxAliasLength, ErrInvalidAlias)
	}
	var b strings.Builder
	for i, r := range alias {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune('_')
		case r >= '0' && r <= '9':
			if i == 0 {
				return "", fmt.Errorf("begins with a digit: %w", ErrInvalidAlias)
			}
			b.WriteRune(r)
		default:
			return "", fmt.Errorf("contains a character other than a letter, a digit, %q or %q: %w", "-", "_", ErrInvalidAlias)
		}
	}
	return aliasPrefix + b.String(), nil
}

func parseAlias(alias, family string, environ map[string]string) ([]AliasSpec, error) {
	required := func(suffix string) (string, error) {
		name := family + suffix
		v, ok := environ[name]
		if !ok || v == "" {
			return "", fmt.Errorf("redisdb: %s: %w", name, ErrMissingVariable)
		}
		return v, nil
	}

	spec := AliasSpec{TLS: TLSDisable}
	var err error
	if spec.Host, err = required(suffixHost); err != nil {
		return nil, err
	}
	portText, err := required(suffixPort)
	if err != nil {
		return nil, err
	}
	port, convErr := strconv.Atoi(portText)
	if convErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("redisdb: %s must be a TCP port between 1 and 65535: %w", family+suffixPort, ErrInvalidVariable)
	}
	spec.Port = port
	if spec.User, err = required(suffixUser); err != nil {
		return nil, err
	}
	password, err := required(suffixPassword)
	if err != nil {
		return nil, err
	}
	if strings.IndexFunc(password, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("redisdb: %s contains whitespace, which is refused rather than trimmed: %w", family+suffixPassword, ErrInvalidVariable)
	}
	spec.Password = Secret(password)

	databases, err := parseDatabases(family, environ)
	if err != nil {
		return nil, err
	}

	if mode, ok := environ[family+suffixTLS]; ok && mode != "" {
		if !slices.Contains(tlsModes(), TLSMode(mode)) {
			return nil, fmt.Errorf("redisdb: %s must be one of %v: %w", family+suffixTLS, tlsModes(), ErrInvalidVariable)
		}
		spec.TLS = TLSMode(mode)
	}

	out := make([]AliasSpec, 0, len(databases))
	for _, database := range databases {
		derived := spec
		derived.Alias = alias + derivedAliasSeparator + strconv.Itoa(database)
		derived.Database = database
		out = append(out, derived)
	}
	return out, nil
}

func parseDatabases(family string, environ map[string]string) ([]int, error) {
	name := family + suffixDatabases
	raw, ok := environ[name]
	if !ok || raw == "" {
		return nil, fmt.Errorf("redisdb: %s: %w", name, ErrMissingVariable)
	}
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		text := strings.TrimSpace(part)
		if text == "" {
			return nil, fmt.Errorf("redisdb: %s lists an empty entry: %w", name, ErrInvalidVariable)
		}
		n, err := strconv.Atoi(text)
		switch {
		case err != nil:
			return nil, fmt.Errorf("redisdb: %s lists an entry that is not a whole number: %w", name, ErrInvalidVariable)
		case n < 0:
			return nil, fmt.Errorf("redisdb: %s lists a negative database number: %w", name, ErrInvalidVariable)
		case strconv.Itoa(n) != text:
			return nil, fmt.Errorf("redisdb: %s lists a database number with a sign or a leading zero: %w", name, ErrInvalidVariable)
		case slices.Contains(out, n):
			return nil, fmt.Errorf("redisdb: %s lists the same database twice: %w", name, ErrInvalidVariable)
		}
		out = append(out, n)
	}
	return out, nil
}

func refuseUnknownVariables(specs []AliasSpec) error {
	known := make(map[string]bool)
	for _, name := range settingVariables() {
		known[name] = true
	}
	for i, spec := range specs {
		parent, _, _ := strings.Cut(spec.Alias, derivedAliasSeparator)
		family, err := variableFamily(parent)
		if err != nil {
			return fmt.Errorf("redisdb: configured alias %d %w", i+1, err)
		}
		for _, suffix := range aliasSuffixes() {
			known[family+suffix] = true
		}
	}
	var stray []string
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" || !strings.HasPrefix(key, aliasPrefix) || known[key] {
			continue
		}
		stray = append(stray, key)
	}
	if len(stray) == 0 {
		return nil
	}
	slices.Sort(stray)
	return fmt.Errorf("redisdb: %s is set and is not a variable of this configuration: %w", strings.Join(stray, ", "), ErrUnsupportedVariable)
}
