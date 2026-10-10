package redisdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

const knownPassword = "pa55-redis-not-in-any-error"

func isolateEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(key, aliasPrefix) {
			t.Setenv(key, "")
		}
	}
}

func setEnvironment(t *testing.T, environ map[string]string) {
	t.Helper()
	isolateEnvironment(t)
	for k, v := range environ {
		t.Setenv(k, v)
	}
}

func minimalEnvironment() map[string]string {
	return map[string]string{
		"CERBERUS_REDIS_ALIASES":         "cache",
		"CERBERUS_REDIS_CACHE_HOST":      "redis.internal.example",
		"CERBERUS_REDIS_CACHE_PORT":      "6379",
		"CERBERUS_REDIS_CACHE_USER":      "svc_reader",
		"CERBERUS_REDIS_CACHE_PASSWORD":  knownPassword,
		"CERBERUS_REDIS_CACHE_DATABASES": "3",
	}
}

func TestLoadConfigAccepts(t *testing.T) {
	base := func(edit func(map[string]string)) map[string]string {
		environ := minimalEnvironment()
		edit(environ)
		return environ
	}
	cacheSpec := func(database int, tls TLSMode) AliasSpec {
		return AliasSpec{
			Alias:    "cache." + fmt.Sprint(database),
			Host:     "redis.internal.example",
			Port:     6379,
			Database: database,
			User:     "svc_reader",
			Password: Secret(knownPassword),
			TLS:      tls,
		}
	}
	defaults := Settings{
		CommandTimeout:  20 * time.Second,
		ConnectTimeout:  10 * time.Second,
		MaxConns:        4,
		ReplyByteBudget: 32768,
		MaxElements:     1000,
		MaxCount:        1000,
		MaxArgs:         1024,
		MaxArgvBytes:    65536,
		Aliases:         []string{"cache"},
	}
	for _, tt := range []struct {
		name         string
		environ      map[string]string
		wantSettings Settings
		wantAliases  []AliasSpec
	}{
		{
			name:         "every shared setting defaults and _TLS defaults to disable",
			environ:      minimalEnvironment(),
			wantSettings: defaults,
			wantAliases:  []AliasSpec{cacheSpec(3, TLSDisable)},
		},
		{
			name: "every shared setting is read",
			environ: base(func(e map[string]string) {
				e["CERBERUS_REDIS_COMMAND_TIMEOUT"] = "7s"
				e["CERBERUS_REDIS_CONNECT_TIMEOUT"] = "3s"
				e["CERBERUS_REDIS_MAX_CONNS"] = "2"
				e["CERBERUS_REDIS_REPLY_BYTE_BUDGET"] = "4096"
				e["CERBERUS_REDIS_MAX_ELEMENTS"] = "50"
				e["CERBERUS_REDIS_MAX_COUNT"] = "60"
				e["CERBERUS_REDIS_MAX_ARGS"] = "70"
				e["CERBERUS_REDIS_MAX_ARGV_BYTES"] = "8000"
			}),
			wantSettings: Settings{
				CommandTimeout:  7 * time.Second,
				ConnectTimeout:  3 * time.Second,
				MaxConns:        2,
				ReplyByteBudget: 4096,
				MaxElements:     50,
				MaxCount:        60,
				MaxArgs:         70,
				MaxArgvBytes:    8000,
				Aliases:         []string{"cache"},
			},
			wantAliases: []AliasSpec{cacheSpec(3, TLSDisable)},
		},
		{
			name:         "_TLS disable",
			environ:      base(func(e map[string]string) { e["CERBERUS_REDIS_CACHE_TLS"] = "disable" }),
			wantSettings: defaults,
			wantAliases:  []AliasSpec{cacheSpec(3, TLSDisable)},
		},
		{
			name:         "_TLS require",
			environ:      base(func(e map[string]string) { e["CERBERUS_REDIS_CACHE_TLS"] = "require" }),
			wantSettings: defaults,
			wantAliases:  []AliasSpec{cacheSpec(3, TLSRequire)},
		},
		{
			name:         "_TLS require-insecure",
			environ:      base(func(e map[string]string) { e["CERBERUS_REDIS_CACHE_TLS"] = "require-insecure" }),
			wantSettings: defaults,
			wantAliases:  []AliasSpec{cacheSpec(3, TLSRequireInsecure)},
		},
		{
			name: "only _HOST and _DATABASES: _PORT defaults to 6379 and no AUTH is sent",
			environ: base(func(e map[string]string) {
				delete(e, "CERBERUS_REDIS_CACHE_PORT")
				delete(e, "CERBERUS_REDIS_CACHE_USER")
				delete(e, "CERBERUS_REDIS_CACHE_PASSWORD")
			}),
			wantSettings: defaults,
			wantAliases: []AliasSpec{{
				Alias: "cache.3", Host: "redis.internal.example", Port: 6379, Database: 3, TLS: TLSDisable,
			}},
		},
		{
			name: "empty _PORT, _USER and _PASSWORD read as unset",
			environ: base(func(e map[string]string) {
				e["CERBERUS_REDIS_CACHE_PORT"] = ""
				e["CERBERUS_REDIS_CACHE_USER"] = ""
				e["CERBERUS_REDIS_CACHE_PASSWORD"] = ""
			}),
			wantSettings: defaults,
			wantAliases: []AliasSpec{{
				Alias: "cache.3", Host: "redis.internal.example", Port: 6379, Database: 3, TLS: TLSDisable,
			}},
		},
		{
			name:         "_PASSWORD without _USER authenticates the default user",
			environ:      base(func(e map[string]string) { delete(e, "CERBERUS_REDIS_CACHE_USER") }),
			wantSettings: defaults,
			wantAliases: []AliasSpec{{
				Alias: "cache.3", Host: "redis.internal.example", Port: 6379, Database: 3,
				Password: Secret(knownPassword), TLS: TLSDisable,
			}},
		},
		{
			name:         "a non-default _PORT is read",
			environ:      base(func(e map[string]string) { e["CERBERUS_REDIS_CACHE_PORT"] = "6380" }),
			wantSettings: defaults,
			wantAliases: func() []AliasSpec {
				spec := cacheSpec(3, TLSDisable)
				spec.Port = 6380
				return []AliasSpec{spec}
			}(),
		},
		{
			name:         "each database becomes a derived alias in declared order",
			environ:      base(func(e map[string]string) { e["CERBERUS_REDIS_CACHE_DATABASES"] = "12, 0,3" }),
			wantSettings: defaults,
			wantAliases:  []AliasSpec{cacheSpec(12, TLSDisable), cacheSpec(0, TLSDisable), cacheSpec(3, TLSDisable)},
		},
		{
			name: "a hyphenated alias reads the underscored family",
			environ: map[string]string{
				"CERBERUS_REDIS_ALIASES":              "edge-cache",
				"CERBERUS_REDIS_EDGE_CACHE_HOST":      "10.0.0.7",
				"CERBERUS_REDIS_EDGE_CACHE_PORT":      "6380",
				"CERBERUS_REDIS_EDGE_CACHE_USER":      "ro",
				"CERBERUS_REDIS_EDGE_CACHE_PASSWORD":  knownPassword,
				"CERBERUS_REDIS_EDGE_CACHE_DATABASES": "1",
			},
			wantSettings: func() Settings { s := defaults; s.Aliases = []string{"edge-cache"}; return s }(),
			wantAliases: []AliasSpec{{
				Alias: "edge-cache.1", Host: "10.0.0.7", Port: 6380, Database: 1,
				User: "ro", Password: Secret(knownPassword), TLS: TLSDisable,
			}},
		},
		{
			name: "two aliases keep their declared order",
			environ: base(func(e map[string]string) {
				e["CERBERUS_REDIS_ALIASES"] = "cache, sessions"
				e["CERBERUS_REDIS_SESSIONS_HOST"] = "sessions.internal.example"
				e["CERBERUS_REDIS_SESSIONS_PORT"] = "6390"
				e["CERBERUS_REDIS_SESSIONS_USER"] = "svc_sessions"
				e["CERBERUS_REDIS_SESSIONS_PASSWORD"] = "another-secret"
				e["CERBERUS_REDIS_SESSIONS_DATABASES"] = "3"
				e["CERBERUS_REDIS_SESSIONS_TLS"] = "require"
			}),
			wantSettings: func() Settings { s := defaults; s.Aliases = []string{"cache", "sessions"}; return s }(),
			wantAliases: []AliasSpec{
				cacheSpec(3, TLSDisable),
				{
					Alias: "sessions.3", Host: "sessions.internal.example", Port: 6390, Database: 3,
					User: "svc_sessions", Password: Secret("another-secret"), TLS: TLSRequire,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setEnvironment(t, tt.environ)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig() = %v", err)
			}
			if !reflect.DeepEqual(cfg.Settings, tt.wantSettings) {
				t.Errorf("settings:\n got %+v\nwant %+v", cfg.Settings, tt.wantSettings)
			}
			if !reflect.DeepEqual(cfg.Aliases, tt.wantAliases) {
				t.Errorf("aliases:\n got %#v\nwant %#v", cfg.Aliases, tt.wantAliases)
			}
			wantLimits := redisgate.Limits{
				MaxElements: tt.wantSettings.MaxElements,
				MaxCount:    tt.wantSettings.MaxCount,
				MaxArgs:     tt.wantSettings.MaxArgs,
				MaxBytes:    tt.wantSettings.MaxArgvBytes,
			}
			if got := cfg.Settings.GateLimits(); got != wantLimits {
				t.Errorf("GateLimits() = %+v, want %+v", got, wantLimits)
			}
		})
	}
}

func TestLoadConfigRefusesAndNamesTheVariable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		variable string
		value    string
		extra    map[string]string
		want     error
	}{
		{name: "a zero command timeout", variable: "CERBERUS_REDIS_COMMAND_TIMEOUT", value: "0s", want: ErrInvalidVariable},
		{name: "a negative command timeout", variable: "CERBERUS_REDIS_COMMAND_TIMEOUT", value: "-3s", want: ErrInvalidVariable},
		{name: "an unparsable command timeout", variable: "CERBERUS_REDIS_COMMAND_TIMEOUT", value: "soonish", want: ErrInvalidVariable},
		{name: "a zero connect timeout", variable: "CERBERUS_REDIS_CONNECT_TIMEOUT", value: "0s", want: ErrInvalidVariable},
		{name: "a negative connect timeout", variable: "CERBERUS_REDIS_CONNECT_TIMEOUT", value: "-4s", want: ErrInvalidVariable},
		{name: "a zero pool size", variable: "CERBERUS_REDIS_MAX_CONNS", value: "0", want: ErrInvalidVariable},
		{name: "a negative pool size", variable: "CERBERUS_REDIS_MAX_CONNS", value: "-5", want: ErrInvalidVariable},
		{name: "an unparsable pool size", variable: "CERBERUS_REDIS_MAX_CONNS", value: "plenty", want: ErrInvalidVariable},
		{name: "a zero byte budget", variable: "CERBERUS_REDIS_REPLY_BYTE_BUDGET", value: "0", want: ErrInvalidVariable},
		{name: "a negative byte budget", variable: "CERBERUS_REDIS_REPLY_BYTE_BUDGET", value: "-6", want: ErrInvalidVariable},
		{name: "a zero element cap", variable: "CERBERUS_REDIS_MAX_ELEMENTS", value: "0", want: ErrInvalidVariable},
		{name: "a negative element cap", variable: "CERBERUS_REDIS_MAX_ELEMENTS", value: "-7", want: ErrInvalidVariable},
		{name: "a zero count cap", variable: "CERBERUS_REDIS_MAX_COUNT", value: "0", want: ErrInvalidVariable},
		{name: "a negative count cap", variable: "CERBERUS_REDIS_MAX_COUNT", value: "-8", want: ErrInvalidVariable},
		{name: "a zero argument cap", variable: "CERBERUS_REDIS_MAX_ARGS", value: "0", want: ErrInvalidVariable},
		{name: "a negative argument cap", variable: "CERBERUS_REDIS_MAX_ARGS", value: "-9", want: ErrInvalidVariable},
		{name: "a zero argv byte cap", variable: "CERBERUS_REDIS_MAX_ARGV_BYTES", value: "0", want: ErrInvalidVariable},
		{name: "a negative argv byte cap", variable: "CERBERUS_REDIS_MAX_ARGV_BYTES", value: "-42", want: ErrInvalidVariable},
		{name: "an unparsable argv byte cap", variable: "CERBERUS_REDIS_MAX_ARGV_BYTES", value: "lots", want: ErrInvalidVariable},
		{name: "no alias", variable: "CERBERUS_REDIS_ALIASES", value: " , ", want: ErrNoAliases},
		{name: "an alias beginning with a digit", variable: "CERBERUS_REDIS_ALIASES", value: "9lives", want: ErrInvalidAlias},
		{name: "an alias containing a dot", variable: "CERBERUS_REDIS_ALIASES", value: "cache.main", want: ErrInvalidAlias},
		{name: "an alias containing a space", variable: "CERBERUS_REDIS_ALIASES", value: "my cache", want: ErrInvalidAlias},
		{name: "an alias longer than sixty-four characters", variable: "CERBERUS_REDIS_ALIASES", value: strings.Repeat("q", 65), want: ErrInvalidAlias},
		{name: "two aliases in one variable family", variable: "CERBERUS_REDIS_ALIASES", value: "hot-cache,hot_cache", want: ErrDuplicateAlias},
		{name: "two aliases differing only in case", variable: "CERBERUS_REDIS_ALIASES", value: "Cache,cache", want: ErrDuplicateAlias},
		{name: "a missing host", variable: "CERBERUS_REDIS_CACHE_HOST", value: "", want: ErrMissingVariable},
		{name: "a port that is not a number", variable: "CERBERUS_REDIS_CACHE_PORT", value: "redisport", want: ErrInvalidVariable},
		{name: "a port above the range", variable: "CERBERUS_REDIS_CACHE_PORT", value: "70000", want: ErrInvalidVariable},
		{name: "a zero port", variable: "CERBERUS_REDIS_CACHE_PORT", value: "0", want: ErrInvalidVariable},
		{name: "a user without a password", variable: "CERBERUS_REDIS_CACHE_PASSWORD", value: "", want: ErrMissingVariable},
		{name: "a password with an inner space", variable: "CERBERUS_REDIS_CACHE_PASSWORD", value: "pa55 word-secret", want: ErrInvalidVariable},
		{name: "a password with a trailing newline", variable: "CERBERUS_REDIS_CACHE_PASSWORD", value: "pa55word-secret\n", want: ErrInvalidVariable},
		{name: "a password with a leading tab", variable: "CERBERUS_REDIS_CACHE_PASSWORD", value: "\tpa55word-secret", want: ErrInvalidVariable},
		{name: "missing databases", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "", want: ErrMissingVariable},
		{name: "a negative database", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "-7", want: ErrInvalidVariable},
		{name: "a database that is not an integer", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "sessions", want: ErrInvalidVariable},
		{name: "a fractional database", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "4.5", want: ErrInvalidVariable},
		{name: "a database with a leading zero", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "07", want: ErrInvalidVariable},
		{name: "a database with a plus sign", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "+8", want: ErrInvalidVariable},
		{name: "a database written as negative zero", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "-0", want: ErrInvalidVariable},
		{name: "an empty database entry", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "3,,4", want: ErrInvalidVariable},
		{name: "a duplicate database", variable: "CERBERUS_REDIS_CACHE_DATABASES", value: "47,47", want: ErrInvalidVariable},
		{name: "a TLS mode outside the closed set", variable: "CERBERUS_REDIS_CACHE_TLS", value: "verify-full", want: ErrInvalidVariable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			environ := minimalEnvironment()
			environ[tt.variable] = tt.value
			setEnvironment(t, environ)
			cfg, err := LoadConfig()
			if err == nil {
				t.Fatalf("LoadConfig() = %+v, want an error", cfg)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("LoadConfig() = %v, want %v", err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.variable) {
				t.Errorf("the error does not name %s: %v", tt.variable, err)
			}
			for _, part := range strings.Split(tt.value, ",") {
				if strings.TrimSpace(part) == "" {
					continue
				}
				if strings.Contains(err.Error(), part) || strings.Contains(err.Error(), strings.TrimSpace(part)) {
					t.Errorf("the error quotes the rejected value %q: %v", part, err)
				}
			}
			if strings.Contains(err.Error(), knownPassword) {
				t.Errorf("the error quotes the password: %v", err)
			}
		})
	}
}

func TestClaimAliasRefusesADerivedNameAlreadyInUse(t *testing.T) {
	names := map[string]bool{"cache": true, "cache.3": true}
	err := claimAlias(names, "cache.3", "CERBERUS_REDIS_CACHE_DATABASES")
	if !errors.Is(err, ErrDuplicateAlias) {
		t.Fatalf("claimAlias() = %v, want ErrDuplicateAlias", err)
	}
	if !strings.Contains(err.Error(), "CERBERUS_REDIS_CACHE_DATABASES") {
		t.Errorf("the error does not name the variable: %v", err)
	}
	if strings.Contains(err.Error(), "cache.3") {
		t.Errorf("the error quotes the derived name: %v", err)
	}
	if err := claimAlias(names, "cache.4", "CERBERUS_REDIS_CACHE_DATABASES"); err != nil {
		t.Fatalf("claimAlias() on a free name = %v", err)
	}
}

func TestPasswordRendersRedacted(t *testing.T) {
	s := Secret(knownPassword)
	text, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() = %v", err)
	}
	for _, tt := range []struct {
		name string
		got  string
	}{
		{"String", s.String()},
		{"GoString", s.GoString()},
		{"%v", fmt.Sprintf("%v", s)},
		{"%+v", fmt.Sprintf("%+v", s)},
		{"%#v", fmt.Sprintf("%#v", s)},
		{"%s", fmt.Sprintf("%s", s)},
		{"MarshalText", string(text)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.got, knownPassword) {
				t.Fatalf("%s renders the password: %s", tt.name, tt.got)
			}
			if !strings.Contains(tt.got, "[redacted]") {
				t.Fatalf("%s = %q, want [redacted]", tt.name, tt.got)
			}
		})
	}
}

func TestConfigRendersNoPassword(t *testing.T) {
	setEnvironment(t, minimalEnvironment())
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() = %v", err)
	}
	if got := cfg.Aliases[0].Password.reveal(); got != knownPassword {
		t.Fatalf("the config does not hold the password it was given")
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() = %v", err)
	}
	for _, tt := range []struct {
		name string
		got  string
	}{
		{"%v", fmt.Sprintf("%v", cfg)},
		{"%+v", fmt.Sprintf("%+v", cfg)},
		{"%#v", fmt.Sprintf("%#v", cfg)},
		{"%+v of the alias", fmt.Sprintf("%+v", cfg.Aliases[0])},
		{"json", string(encoded)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.got, knownPassword) {
				t.Fatalf("%s renders the password: %s", tt.name, tt.got)
			}
			if !strings.Contains(tt.got, "[redacted]") {
				t.Fatalf("%s does not show the password redacted: %s", tt.name, tt.got)
			}
		})
	}
}
