package db

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// Configuration errors. They are sentinels rather than typed values because the
// one thing a configuration error must not do is carry the value it rejected:
// the whole point of naming the alias and the variable is that neither of them
// is a secret, and the value always might be.
var (
	// ErrNoAliases reports an empty CERBERUS_DB_ALIASES. A server with no
	// database is a server with no purpose, so it is an error rather than an
	// empty registry.
	ErrNoAliases = errors.New("no database aliases are configured")
	// ErrInvalidAlias reports an alias name that cannot be turned into an
	// environment variable name.
	ErrInvalidAlias = errors.New("alias name is not usable in a variable name")
	// ErrDuplicateAlias reports two aliases that resolve to the same variable
	// family, which would silently give them the same credentials.
	ErrDuplicateAlias = errors.New("two aliases share one variable family")
	// ErrMissingVariable reports a required per-alias variable that is unset or
	// empty.
	ErrMissingVariable = errors.New("required variable is not set")
	// ErrInvalidVariable reports a variable this package cannot use: a value it
	// cannot parse, or a variable that has been replaced by another one. The error
	// never quotes the value.
	ErrInvalidVariable = errors.New("variable value is not usable")
	// ErrUnsupportedVariable reports a variable that is set, is not this
	// package's, and would decide something this package insists on deciding
	// itself. See [refuseForeignConfiguration].
	ErrUnsupportedVariable = errors.New("variable is set and is not supported by this package")
)

// Secret holds a password. Its whole purpose is that the obvious ways of
// rendering a value — fmt's verbs, encoding/json, a log call that takes the
// whole config struct — go through a method that returns a placeholder instead.
//
// It is not a defence against a caller who wants the password: [Secret.reveal]
// exists, and a caller in another package can still convert the value to a
// string. It is a defence against the accident, which is the failure mode that
// actually happens: something in the credential's neighbourhood gets printed by
// a struct-wide verb nobody audited.
type Secret string

// redacted is what every rendering of a [Secret] produces. It is deliberately
// not the empty string: an empty rendering reads as "there was no password",
// which is a different and misleading claim.
const redacted = "[redacted]"

func (Secret) String() string { return redacted }

// GoString covers %#v, which does not consult String.
func (Secret) GoString() string { return strconv.Quote(redacted) }

// MarshalText covers encoding/json, which prefers a TextMarshaler over the
// underlying string.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (s Secret) reveal() string { return string(s) }

// TLSMode is the transport-security choice for one alias, expressed in terms
// this package defines rather than in any driver's vocabulary.
//
// It is a closed set of three values, and that is the point. The obvious
// alternative — one variable holding driver parameters passed through verbatim —
// would be a second input capable of weakening this layer, sitting next to the
// gate's ruleset overlay, and would need the same scrutiny for far less benefit.
// A closed set can be mapped to each driver's spelling here, once, where the
// mapping is reviewable.
type TLSMode string

const (
	// TLSDefault leaves the driver's own default in force: sslmode=prefer on
	// PostgreSQL, no TLS on MySQL, and on SQL Server the driver's "optional",
	// which is no transport encryption. Whether SQL Server's login packet is
	// encrypted regardless is unresolved — see the comment on TLSDisable in
	// mssql.go — so this mode makes no promise about the credential either.
	TLSDefault TLSMode = ""
	// TLSDisable asks for no transport encryption.
	TLSDisable TLSMode = "disable"
	// TLSRequire asks for encryption with the server's certificate verified.
	TLSRequire TLSMode = "require"
	// TLSRequireInsecure asks for encryption without verifying the certificate.
	// It is the mode an on-premise server with a self-signed certificate needs,
	// and it is spelled unpleasantly on purpose.
	TLSRequireInsecure TLSMode = "require-insecure"
)

func tlsModes() []TLSMode {
	return []TLSMode{TLSDisable, TLSRequire, TLSRequireInsecure}
}

// Settings are the bounds that apply to every alias. Their names are fixed at
// compile time, so unlike the per-alias family they can be parsed by tag.
type Settings struct {
	// RowCap is the most rows any single result may contain. It is enforced by
	// stopping the iteration, never by editing the statement.
	RowCap int `env:"CERBERUS_DB_ROW_CAP" envDefault:"1000"`

	// QueryTimeout is the bound the *server* is asked to enforce: PostgreSQL's
	// statement_timeout and MySQL's max_execution_time are both set from it. On
	// SQL Server, which has no statement-level server bound, it is the context
	// deadline instead — and there a context deadline does tear the session down.
	QueryTimeout time.Duration `env:"CERBERUS_DB_QUERY_TIMEOUT" envDefault:"20s"`

	// TimeoutGrace is how much longer than QueryTimeout the context deadline is
	// allowed to be on the engines that have a server-side bound.
	//
	// The ordering is deliberate and it is not cosmetic. A context deadline is
	// enforced by the client: on PostgreSQL it aborts the query, and on MySQL it
	// demonstrably does not — the driver closes the socket and never sends
	// KILL QUERY, so the query runs to completion on the server with nobody
	// waiting for it. Letting the server's own bound expire first means the
	// engine is what stops the work, and the context is only the backstop for a
	// server that failed to honour its own setting. Set the two equal and which
	// mechanism fires becomes a race, on the engine where losing that race means
	// the query is not stopped at all.
	TimeoutGrace time.Duration `env:"CERBERUS_DB_TIMEOUT_GRACE" envDefault:"5s"`

	// LockTimeout bounds how long a statement may wait for a lock. It matters
	// most on SQL Server, where our reads are the only thing that could block a
	// third party's own users, and where SET LOCK_TIMEOUT has no
	// connection-string parameter and has to be issued as a statement.
	LockTimeout time.Duration `env:"CERBERUS_DB_LOCK_TIMEOUT" envDefault:"3s"`

	// ConnectTimeout bounds establishing a connection, which on a VPN link is a
	// separate and much likelier failure than a slow query.
	ConnectTimeout time.Duration `env:"CERBERUS_DB_CONNECT_TIMEOUT" envDefault:"10s"`

	// MaxConns is the per-alias pool ceiling. It is small because the pool's
	// purpose is to avoid a handshake per call, not to achieve concurrency
	// against someone else's production server.
	MaxConns int `env:"CERBERUS_DB_MAX_CONNS" envDefault:"4"`

	// Aliases names every configured connection. An alias here whose variables
	// are missing is a startup error: a silently absent alias would look, to the
	// agent, exactly like one it had never been told about.
	Aliases []string `env:"CERBERUS_DB_ALIASES" envSeparator:","`
}

func (s Settings) validate() error {
	for _, c := range []struct {
		name string
		ok   bool
		want string
	}{
		{"CERBERUS_DB_ROW_CAP", s.RowCap >= 1, "at least 1"},
		{"CERBERUS_DB_QUERY_TIMEOUT", s.QueryTimeout > 0, "a positive duration"},
		{"CERBERUS_DB_TIMEOUT_GRACE", s.TimeoutGrace > 0, "a positive duration"},
		{"CERBERUS_DB_LOCK_TIMEOUT", s.LockTimeout > 0, "a positive duration"},
		{"CERBERUS_DB_CONNECT_TIMEOUT", s.ConnectTimeout > 0, "a positive duration"},
		{"CERBERUS_DB_MAX_CONNS", s.MaxConns >= 1, "at least 1"},
	} {
		if !c.ok {
			return fmt.Errorf("db: %s must be %s: %w", c.name, c.want, ErrInvalidVariable)
		}
	}
	return nil
}

// statementDeadline is how long the caller's context is given for one execution.
// On the two engines with a server-side statement bound it is deliberately
// longer than that bound; see [Settings.TimeoutGrace].
func (s Settings) statementDeadline(e gate.Engine) time.Duration {
	if e == gate.SQLServer {
		return s.QueryTimeout
	}
	return s.QueryTimeout + s.TimeoutGrace
}

// AliasSpec is one connection's whole topology. There is no DSN field and no
// method that renders one: a DSN is assembled inside the per-engine file that
// needs it and is never held, so there is nothing for a stray print to find.
type AliasSpec struct {
	Alias  string
	Engine gate.Engine
	Host   string
	Port   int
	// Database is empty when the alias exposes no single database, which is a
	// configuration an operator may choose on MySQL and SQL Server: the connection
	// then has no default database and the login reads whatever it can reach
	// through a qualified name. It is never empty on PostgreSQL, where a
	// connection is bound to one database by the protocol; [parseDatabases] is
	// what enforces that.
	Database string
	User     string
	Password Secret
	TLS      TLSMode
}

// Config is the whole of this package's configuration. There is no
// configuration file, by decision, so this is the only shape configuration has.
type Config struct {
	Settings Settings
	Aliases  []AliasSpec
}

// per-alias variable suffixes. The names are values rather than a struct tag
// because they are only known once an alias name is.
const (
	suffixEngine    = "_ENGINE"
	suffixHost      = "_HOST"
	suffixPort      = "_PORT"
	suffixDatabases = "_DATABASES"
	suffixUser      = "_USER"
	suffixPassword  = "_PASSWORD"
	suffixTLS       = "_TLS"
)

// suffixRetiredDatabase is the singular variable [suffixDatabases] replaced. It is
// named here for one purpose, which is to refuse a configuration that still sets
// it, and it is deliberately not read as configuration anywhere.
//
// Tolerating it would be worse than either alternative. An operator who left
// _DATABASE on a MySQL alias would get a working connection to no default
// database and no hint that the name they chose was never read; on PostgreSQL they
// would be told a variable is missing while looking at one they had set. So the
// refusal names both variables and is the whole migration instruction.
const suffixRetiredDatabase = "_DATABASE"

// derivedAliasSeparator joins a parent alias to one of the databases it lists. A
// dot is the one character that cannot appear in a declared alias — see
// [variableFamily], which refuses it — and that refusal is what makes a derived
// name unable to collide with a declared one. It is load-bearing rather than
// incidental: relax it and two aliases can silently become one.
//
// A derived name never becomes part of a variable name, so nothing reads
// CERBERUS_DB_CRM.SALES_* and none of variableFamily's rules apply to it.
const derivedAliasSeparator = "."

// aliasPrefix is the fixed part of every per-alias variable name.
const aliasPrefix = "CERBERUS_DB_"

// LoadConfig reads the whole configuration from the process environment.
//
// A variable set to the empty string is treated as unset. That is the same rule
// the reference implementation uses, and here it has a second reason: an empty
// CERBERUS_DB_<ALIAS>_PASSWORD is far more likely to be a broken secret
// injection than a deliberate passwordless account, and connecting anyway would
// turn a configuration mistake into a login attempt.
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

// LoadConfigFrom reads the configuration from an explicit environment. It exists
// so that configuration can be tested without mutating the process's own
// environment, which no parallel test can do safely.
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
		return nil, fmt.Errorf("db: CERBERUS_DB_ALIASES is empty: %w", ErrNoAliases)
	}
	settings.Aliases = aliases

	// Every alias name is resolved to its variable family before any alias is
	// parsed. A collision has to be reported as a collision: parse first and the
	// operator is told a variable is missing, which is true and useless, because
	// the variable they set is being consumed by the other alias.
	families := make([]string, len(aliases))
	seen := make(map[string]string, len(aliases))
	for i, alias := range aliases {
		family, err := variableFamily(alias)
		if err != nil {
			return nil, err
		}
		if other, ok := seen[family]; ok {
			return nil, fmt.Errorf("db: aliases %q and %q both use %s*: %w", other, alias, family, ErrDuplicateAlias)
		}
		seen[family] = alias
		families[i] = family
	}

	// names is every alias name that will exist once derivation has run, seeded
	// with all the declared ones before any of it does. Seeding first is what makes
	// the check symmetric: a derived name has to be refused whether the alias it
	// would shadow appears before its parent in CERBERUS_DB_ALIASES or after it.
	names := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		names[alias] = alias
	}

	cfg := &Config{Settings: settings}
	for i, alias := range aliases {
		specs, err := parseAlias(alias, families[i], environ)
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			// A spec that kept its parent's name was claimed by the seeding above;
			// only a derived name is a new claim.
			if spec.Alias != alias {
				if err := claimAlias(names, alias, spec.Alias, families[i]+suffixDatabases); err != nil {
					return nil, err
				}
			}
			cfg.Aliases = append(cfg.Aliases, spec)
		}
	}
	return cfg, nil
}

// claimAlias records one alias name and refuses a name that is already in use.
//
// It is unreachable through [LoadConfigFrom] as this package stands, and it is
// here rather than deleted because of what makes it unreachable: a derived name
// always contains [derivedAliasSeparator] and [variableFamily] refuses that
// character in a declared name, so the two sets cannot meet while that refusal
// stands — and it stands one edit away from not standing. This is what would stop
// two connections silently sharing a name on the day somebody relaxes it.
//
// The comparison is a map lookup, so it is exact and case-sensitive. That is the
// same rule alias lookup follows in [Executor.Execute], deliberately: REPORTING
// and reporting are two names here as they are everywhere else in this package.
func claimAlias(names map[string]string, parent, name, variable string) error {
	if other, taken := names[name]; taken {
		return fmt.Errorf("db: alias %q: %s derives the alias %q, which alias %q already uses: %w",
			parent, variable, name, other, ErrDuplicateAlias)
	}
	names[name] = parent
	return nil
}

// serviceFileVariables are the variables that make pgx read a service file. The
// read is decided by the presence of the "service" key in the merged settings
// (pgconn/config.go:357), so no value in the connection string this package
// builds can prevent it, and a missing or unreadable file makes ParseConfig fail
// outright — which means an operator's psql habits decide whether this process
// starts.
//
// PGSERVICEFILE is refused alongside PGSERVICE even though, measured against pgx
// v5.10.0, it is inert on its own: the file is only read when a service is also
// named. It is the other half of one mechanism, and the half whose value is a
// path.
var serviceFileVariables = []string{"PGSERVICE", "PGSERVICEFILE"}

// epaVariable is the last variable outside CERBERUS_DB_* that a driver in this
// package's dependency closure still reads in non-test code. msdsn.Parse consults
// it whenever the connection string omits the "epa encryption" key, which this
// package's own DSN always does (msdsn/conn_str.go:655-666), and it decides
// whether the driver negotiates Extended Protection during login.
//
// It is neither a file read nor a credential, so criterion 1 does not reach it. It
// is refused anyway, for the same reason as the service-file variables: what this
// process negotiates with a third party's server is not something an unrelated
// variable in the shell that launched it gets to decide. The alternative is worse
// than it looks — an unparseable value makes msdsn.Parse fail, which surfaces from
// [openSQLServer] as an open error quoting the value back, and a value quoted in an
// error is what the rest of this file exists to prevent.
const epaVariable = "MSSQL_USE_EPA"

// refuseForeignConfiguration fails when a variable outside this package's own
// family would decide something this package insists on deciding itself, and an
// alias uses the driver that reads it. For the PG* pair, criterion 1 is
// unqualified — no file is read for configuration — and they are the one residue
// of it that cannot be closed by writing a connection-string key, so they are
// closed by refusing to start; see [epaVariable] for the third.
//
// Three decisions are worth stating because each had a plausible alternative:
//
//   - It refuses rather than unsetting the variable. This process shares its
//     environment with everything else in its container, so clearing a variable
//     somebody deliberately set would be a side effect on them, and a silent one.
//   - It reads the process environment directly, which makes this the only place
//     in this package that reads a variable outside CERBERUS_DB_*. It has to: the
//     process environment is what the drivers themselves consult, so checking the
//     map [LoadConfigFrom] was handed would be checking the wrong input — and that
//     map is deliberately not the process environment.
//   - Emptiness follows the drivers, all of which ignore one of these variables
//     set to the empty string: pgx skips any PG* variable whose value is empty
//     (pgconn/config.go:609-613), and msdsn guards its own read with
//     `if epaString != ""` (msdsn/conn_str.go:660), measured to give EpaEnabled
//     false for both unset and empty. An empty value cannot change what the driver
//     does, so refusing on it would be a refusal on a condition that does not
//     exist.
//
// The error names the variable and quotes no value, for the reason on the
// sentinels above: PGSERVICEFILE's value is a path, and a path is exactly the
// kind of thing that must not appear. It does not name the engine either, because
// the engine is the value of a CERBERUS_DB_<ALIAS>_ENGINE variable and criterion
// 1's rule is about values rather than about which of them are secret.
func refuseForeignConfiguration(specs []AliasSpec) error {
	// Each check is gated on an alias that would actually reach the driver that
	// reads the variable. An operator with PGSERVICE set for their own psql and no
	// PostgreSQL alias configured has broken nothing.
	//
	// It scans specs rather than declared aliases, which is what keeps it correct
	// now that one variable family produces one spec per database it lists: a
	// derived spec carries its parent's engine, and every declared alias yields at
	// least one spec whether or not it lists any database. Answer this question from
	// anything that can be empty for a configured alias and the refusal silently
	// stops applying to the driver it was written for.
	uses := func(engine gate.Engine) bool {
		return slices.ContainsFunc(specs, func(s AliasSpec) bool { return s.Engine == engine })
	}
	if uses(gate.PostgreSQL) {
		for _, name := range serviceFileVariables {
			if os.Getenv(name) == "" {
				continue
			}
			return fmt.Errorf("db: %s is set and an alias uses the driver that reads it: this package takes its configuration only from CERBERUS_DB_* variables, and %s would make that driver read a service file: %w",
				name, name, ErrUnsupportedVariable)
		}
	}
	if uses(gate.SQLServer) && os.Getenv(epaVariable) != "" {
		return fmt.Errorf("db: %s is set and an alias uses the driver that reads it: this package takes its configuration only from CERBERUS_DB_* variables, and %s would decide whether that driver negotiates Extended Protection during login: %w",
			epaVariable, epaVariable, ErrUnsupportedVariable)
	}
	return nil
}

// settingForms is, per field of [Settings], the variable that field is read from
// and the form a value has to take to be parseable.
//
// It exists because env's error names the struct field and not the variable:
// env.ParseError carries sf.Name, and its message quotes the offending value —
// it wraps strconv's or time's error, both of which echo their input. So the
// message is discarded and this table is what the replacement is built from.
// TestSettingFormsCoverEverySetting keeps it in step with the struct's own tags,
// so a renamed variable is a failed test rather than a stale message.
var settingForms = map[string]struct{ variable, form string }{
	"RowCap":         {"CERBERUS_DB_ROW_CAP", "a whole number of rows"},
	"QueryTimeout":   {"CERBERUS_DB_QUERY_TIMEOUT", "a duration with a unit, such as 20s"},
	"TimeoutGrace":   {"CERBERUS_DB_TIMEOUT_GRACE", "a duration with a unit, such as 5s"},
	"LockTimeout":    {"CERBERUS_DB_LOCK_TIMEOUT", "a duration with a unit, such as 3s"},
	"ConnectTimeout": {"CERBERUS_DB_CONNECT_TIMEOUT", "a duration with a unit, such as 10s"},
	"MaxConns":       {"CERBERUS_DB_MAX_CONNS", "a whole number of connections"},
	"Aliases":        {"CERBERUS_DB_ALIASES", "a comma-separated list of alias names"},
}

// settingParseError names every global setting env could not parse, and the form
// each of them wants, quoting no value.
//
// Naming the variable is the whole point: "a CERBERUS_DB_* setting could not be
// parsed" leaves an operator to bisect their environment, and it is not the
// value that makes an error useful, it is the name.
func settingParseError(err error) error {
	var aggregate env.AggregateError
	if !errors.As(err, &aggregate) {
		return fmt.Errorf("db: a CERBERUS_DB_* setting could not be parsed: %w", ErrInvalidVariable)
	}
	var named []string
	for _, member := range aggregate.Errors {
		var parseErr env.ParseError
		if !errors.As(member, &parseErr) {
			continue
		}
		if f, ok := settingForms[parseErr.Name]; ok {
			named = append(named, f.variable+" must be "+f.form)
		}
	}
	if len(named) == 0 {
		// env grew a failure this code does not recognise, or a field this table
		// does not know. Its own text holds the value, so it goes no further.
		return fmt.Errorf("db: a CERBERUS_DB_* setting could not be parsed: %w", ErrInvalidVariable)
	}
	return fmt.Errorf("db: %s: %w", strings.Join(named, "; "), ErrInvalidVariable)
}

// variableFamily maps an alias to the prefix its variables share. Lower case is
// accepted in CERBERUS_DB_ALIASES because that is how aliases read in a tool
// call, and hyphens are accepted because that is how they read in a hostname;
// both become the upper-case underscored form an environment variable has to be.
func variableFamily(alias string) (string, error) {
	if len(alias) > 64 {
		return "", fmt.Errorf("db: alias %q is longer than 64 characters: %w", alias, ErrInvalidAlias)
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
				return "", fmt.Errorf("db: alias %q begins with a digit: %w", alias, ErrInvalidAlias)
			}
			b.WriteRune(r)
		default:
			return "", fmt.Errorf("db: alias %q contains a character other than a letter, a digit, %q or %q: %w", alias, "-", "_", ErrInvalidAlias)
		}
	}
	return aliasPrefix + b.String(), nil
}

// parseAlias resolves one declared alias into the connections it configures:
// one per database it lists, or a single one exposing no particular database.
func parseAlias(alias, family string, environ map[string]string) ([]AliasSpec, error) {
	required := func(suffix string) (string, error) {
		name := family + suffix
		v, ok := environ[name]
		if !ok || v == "" {
			return "", fmt.Errorf("db: alias %q: %s: %w", alias, name, ErrMissingVariable)
		}
		return v, nil
	}

	// Ahead of everything else, including the engine. An operator migrating from
	// the singular variable wants to be told that before being told what is missing
	// as a consequence of it.
	if retired, ok := environ[family+suffixRetiredDatabase]; ok && retired != "" {
		return nil, fmt.Errorf("db: alias %q: %s was replaced by %s, which takes a comma-separated list of database names: %w",
			alias, family+suffixRetiredDatabase, family+suffixDatabases, ErrInvalidVariable)
	}

	spec := AliasSpec{Alias: alias}

	engineName, err := required(suffixEngine)
	if err != nil {
		return nil, err
	}
	engine, err := gate.ParseEngine(engineName)
	if err != nil {
		// The offending value is not quoted, deliberately. Naming the variable and
		// the closed set of accepted values says everything an operator needs, and
		// the value could be anything — including, when a family is filled in from
		// the wrong template, a credential.
		return nil, fmt.Errorf("db: alias %q: %s must be one of %v: %w", alias, family+suffixEngine, gate.Engines(), ErrInvalidVariable)
	}
	spec.Engine = engine

	if spec.Host, err = required(suffixHost); err != nil {
		return nil, err
	}
	portText, err := required(suffixPort)
	if err != nil {
		return nil, err
	}
	// strconv's error text quotes the input, so it is discarded rather than
	// wrapped.
	port, convErr := strconv.Atoi(portText)
	if convErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("db: alias %q: %s must be a TCP port between 1 and 65535: %w", alias, family+suffixPort, ErrInvalidVariable)
	}
	spec.Port = port

	// After the engine is assigned, because whether this variable is required is a
	// question about the engine.
	databases, err := parseDatabases(alias, family, spec.Engine, environ)
	if err != nil {
		return nil, err
	}
	if spec.User, err = required(suffixUser); err != nil {
		return nil, err
	}
	password, err := required(suffixPassword)
	if err != nil {
		return nil, err
	}
	spec.Password = Secret(password)

	if mode, ok := environ[family+suffixTLS]; ok && mode != "" {
		if !slices.Contains(tlsModes(), TLSMode(mode)) {
			return nil, fmt.Errorf("db: alias %q: %s must be one of %v: %w", alias, family+suffixTLS, tlsModes(), ErrInvalidVariable)
		}
		spec.TLS = TLSMode(mode)
	}

	// One spec whatever happens, which is the invariant [refuseForeignConfiguration]
	// depends on: it asks whether any spec uses a given engine, and an alias that
	// produced no spec at all would be an alias whose driver nothing knows is in
	// play.
	if len(databases) == 0 {
		return []AliasSpec{spec}, nil
	}

	// A single-element list still derives, so CERBERUS_DB_CRM_DATABASES=sales is the
	// alias crm.sales and not crm. Keeping the parent's name for a one-element list
	// was the obvious alternative and it was rejected: adding a second database
	// would then silently rename the first alias, and a renamed alias is something
	// an agent finds out about by being told the alias it just used is unknown.
	out := make([]AliasSpec, 0, len(databases))
	for _, database := range databases {
		derived := spec
		derived.Alias = alias + derivedAliasSeparator + database
		derived.Database = database
		out = append(out, derived)
	}
	return out, nil
}

// parseDatabases resolves the set of databases one alias exposes. It returns no
// databases when the variable is absent and the engine allows that.
//
// The list is comma-separated to match CERBERUS_DB_ALIASES, each element is
// trimmed, and an empty element is refused rather than skipped: "a,,b" is a typo
// far more often than it is a way of writing two databases, and skipping it would
// produce a configuration the operator did not write.
//
// PostgreSQL is the engine where absence cannot be accepted. A pgx connection is
// bound to one database by the protocol and there is no cross-database query, so
// there is nothing for a database-less connection to read — and pgx sets no
// database default of its own, which means omitting the name makes the *server*
// default it to the user name. That is a silent surprise rather than a useful
// default, so it is a refusal at startup instead.
func parseDatabases(alias, family string, engine gate.Engine, environ map[string]string) ([]string, error) {
	name := family + suffixDatabases
	raw, ok := environ[name]
	if !ok || raw == "" {
		if engine == gate.PostgreSQL {
			return nil, fmt.Errorf("db: alias %q: %s: %w", alias, name, ErrMissingVariable)
		}
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		database := strings.TrimSpace(part)
		if database == "" {
			return nil, fmt.Errorf("db: alias %q: %s lists an empty database name: %w", alias, name, ErrInvalidVariable)
		}
		// Exact, so case-sensitive, for the reason given on [claimAlias]. Two
		// databases whose names differ only in case are two databases on MySQL and
		// on PostgreSQL, and folding them together here would refuse a
		// configuration that works.
		if slices.Contains(out, database) {
			return nil, fmt.Errorf("db: alias %q: %s lists the same database twice: %w", alias, name, ErrInvalidVariable)
		}
		out = append(out, database)
	}
	return out, nil
}

// milliseconds renders a duration the way every one of the three engines wants
// its timeouts: an integer count of milliseconds, floored at one so that a
// sub-millisecond setting does not become the "no timeout" sentinel zero.
func milliseconds(d time.Duration) int64 {
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return ms
}

// seconds does the same for the engines that want whole seconds.
func seconds(d time.Duration) int64 {
	s := int64(d.Seconds())
	if s < 1 {
		s = 1
	}
	return s
}
