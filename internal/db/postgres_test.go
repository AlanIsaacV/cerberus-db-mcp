package db

import (
	"maps"
	"strconv"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// pgSpec is a PostgreSQL alias whose every value is distinctive, so that finding
// one somewhere it should not be means something.
func pgSpec() AliasSpec {
	return AliasSpec{
		Alias:    "pg",
		Engine:   gate.PostgreSQL,
		Host:     "pg-01.corp.internal.example",
		Port:     54321,
		Database: "OperationsWarehouse",
		User:     "svc_cerberus_reader",
		Password: Secret("Tr0ub4dor&3-actual-password"),
	}
}

func pgSettings() Settings {
	return Settings{
		RowCap:         100,
		QueryTimeout:   20 * time.Second,
		TimeoutGrace:   5 * time.Second,
		LockTimeout:    3 * time.Second,
		ConnectTimeout: 10 * time.Second,
		MaxConns:       4,
	}
}

// TestPostgresConfigTakesNothingFromTheEnvironment is criterion 1's "and nowhere
// else" clause against the one driver that goes looking. pgx follows libpq and
// merges every recognised PG* variable into the settings it parses, so a variable
// outside the CERBERUS_DB_* family could otherwise configure this service.
//
// PGOPTIONS is the case that made this worth a test rather than a comment: it
// arrives as the "options" runtime parameter, which travels in the same startup
// packet as our own statement_timeout, and with -c statement_timeout=0 in it
// which one the server honours comes down to map iteration order — the
// blast-radius bound defeated by a variable nobody in this package named.
func TestPostgresConfigTakesNothingFromTheEnvironment(t *testing.T) {
	// postgresConfig calls ParseConfig without passing through New, so the refusal
	// that would otherwise stop an ambient PGSERVICE never runs and pgx reads the
	// operator's own service file. See neutraliseForeignVariables.
	neutraliseForeignVariables(t)

	// t.Setenv rather than a map: the process environment is exactly what pgx
	// reads, and reading it is the behaviour under test. It also makes this test
	// non-parallel, which is correct.
	for name, value := range map[string]string{
		"PGOPTIONS":         "-c statement_timeout=0 -c lock_timeout=0",
		"PGTZ":              "Pacific/Kiritimati",
		"PGAPPNAME":         "definitely-not-cerberus",
		"PGHOST":            "somewhere-else.example",
		"PGPORT":            "6543",
		"PGDATABASE":        "someone_elses_database",
		"PGUSER":            "someone_else",
		"PGPASSWORD":        "someone-elses-password",
		"PGCONNECT_TIMEOUT": "1",
	} {
		t.Setenv(name, value)
	}

	spec, s := pgSpec(), pgSettings()
	cfg, err := postgresConfig(spec, s)
	if err != nil {
		t.Fatalf("postgresConfig() = %v", err)
	}

	// Only what this package set may survive, so the whole map is compared rather
	// than the keys the test happens to think of. An "options" or "timezone" key
	// here is a PG* variable reaching the server.
	want := map[string]string{
		"statement_timeout":                   strconv.FormatInt(milliseconds(s.QueryTimeout), 10),
		"lock_timeout":                        strconv.FormatInt(milliseconds(s.LockTimeout), 10),
		"idle_in_transaction_session_timeout": strconv.FormatInt(milliseconds(s.QueryTimeout+s.TimeoutGrace), 10),
		"application_name":                    applicationName,
	}
	if got := cfg.ConnConfig.RuntimeParams; !maps.Equal(got, want) {
		t.Errorf("RuntimeParams = %v, want exactly %v", got, want)
	}

	if got := cfg.ConnConfig.Host; got != spec.Host {
		t.Errorf("Host = %q, want %q", got, spec.Host)
	}
	if got := int(cfg.ConnConfig.Port); got != spec.Port {
		t.Errorf("Port = %d, want %d", got, spec.Port)
	}
	if got := cfg.ConnConfig.Database; got != spec.Database {
		t.Errorf("Database = %q, want %q", got, spec.Database)
	}
	if got := cfg.ConnConfig.User; got != spec.User {
		t.Errorf("User = %q, want %q", got, spec.User)
	}
	if got := cfg.ConnConfig.Password; got != spec.Password.reveal() {
		t.Error("Password is not the alias's own")
	}
	// PGCONNECT_TIMEOUT sets this field and installs a dialer carrying it, and
	// only the field is obvious. The dialer is rebuilt from our value too — it
	// cannot be compared here, because functions are not comparable, so what this
	// asserts is the half that can be.
	if got := cfg.ConnConfig.ConnectTimeout; got != s.ConnectTimeout {
		t.Errorf("ConnectTimeout = %v, want %v", got, s.ConnectTimeout)
	}
	if cfg.ConnConfig.DialFunc == nil {
		t.Error("DialFunc is nil, so pgx would dial with no timeout of ours")
	}
}

// TestPostgresTLSIsNotDecidedByTheEnvironment pins the transport decision to
// CERBERUS_DB_<ALIAS>_TLS. PGSSLMODE used to answer it for any alias that left
// the mode unset, and PGSSLROOTCERT could both force verify-full and make pgx
// read a CA file — a file deciding configuration, which criterion 1 forbids
// outright.
func TestPostgresTLSIsNotDecidedByTheEnvironment(t *testing.T) {
	// Set on the parent, which every subtest inherits: this test reaches pgx
	// without passing through New. See neutraliseForeignVariables.
	neutraliseForeignVariables(t)

	for _, tt := range []struct {
		name string
		mode TLSMode
		// hostile is the PGSSLMODE that would change the outcome if it were
		// honoured: the opposite of what the alias asked for.
		hostile   string
		wantTLS   bool
		wantVerif bool
	}{
		{name: "disable is not turned into TLS", mode: TLSDisable, hostile: "verify-full"},
		{name: "the default is prefer and not whatever PGSSLMODE says", mode: TLSDefault, hostile: "verify-full", wantTLS: true},
		{name: "require is not turned off", mode: TLSRequire, hostile: "disable", wantTLS: true, wantVerif: true},
		{name: "require-insecure is not turned off", mode: TLSRequireInsecure, hostile: "disable", wantTLS: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PGSSLMODE", tt.hostile)
			// A path that does not exist. If pgx reads it, ParseConfig fails with
			// "unable to read CA file" — so this test failing on the error below is
			// itself the report that a file was read for configuration.
			t.Setenv("PGSSLROOTCERT", "/cerberus/no/such/ca.pem")
			t.Setenv("PGSSLNEGOTIATION", "direct")

			spec := pgSpec()
			spec.TLS = tt.mode
			cfg, err := postgresConfig(spec, pgSettings())
			if err != nil {
				t.Fatalf("postgresConfig() = %v", err)
			}
			if (cfg.ConnConfig.TLSConfig != nil) != tt.wantTLS {
				t.Fatalf("TLSConfig = %v, want a TLS config: %v", cfg.ConnConfig.TLSConfig, tt.wantTLS)
			}
			if tt.wantTLS {
				// verify-full is the only mode that verifies, and pgx expresses it as
				// a ServerName with verification left on.
				verifies := !cfg.ConnConfig.TLSConfig.InsecureSkipVerify
				if verifies != tt.wantVerif {
					t.Errorf("the TLS config verifies the certificate = %v, want %v", verifies, tt.wantVerif)
				}
				if cfg.ConnConfig.TLSConfig.RootCAs != nil {
					t.Error("the TLS config carries root CAs, so PGSSLROOTCERT was read")
				}
			}
			// A fallback with a nil TLSConfig is pgx's way of saying "plaintext is
			// acceptable", so a required mode must not have one.
			if tt.mode == TLSRequire || tt.mode == TLSRequireInsecure {
				for _, f := range cfg.ConnConfig.Fallbacks {
					if f.TLSConfig == nil {
						t.Error("a required mode left a plaintext fallback, which pgx will try")
					}
				}
			}
			if cfg.ConnConfig.SSLNegotiation == "direct" {
				t.Error("PGSSLNEGOTIATION chose the handshake style")
			}
		})
	}
}
