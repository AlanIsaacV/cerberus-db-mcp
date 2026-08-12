package db

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// completeEnvironment is one fully configured alias plus the values that must
// never appear in any error. Every value here is distinctive so that a test can
// look for it in an error text and mean something by finding it.
func completeEnvironment() map[string]string {
	return map[string]string{
		"CERBERUS_DB_ALIASES":              "warehouse",
		"CERBERUS_DB_WAREHOUSE_ENGINE":     "sqlserver",
		"CERBERUS_DB_WAREHOUSE_HOST":       "sql.internal.example",
		"CERBERUS_DB_WAREHOUSE_PORT":       "1433",
		"CERBERUS_DB_WAREHOUSE_DATABASE":   "OperationsWarehouse",
		"CERBERUS_DB_WAREHOUSE_USER":       "svc_reader_account",
		"CERBERUS_DB_WAREHOUSE_PASSWORD":   "pa55word-not-in-any-error",
		"CERBERUS_DB_WAREHOUSE_TLS":        "require-insecure",
		"CERBERUS_DB_ROW_CAP":              "250",
		"CERBERUS_DB_QUERY_TIMEOUT":        "7s",
		"CERBERUS_DB_TIMEOUT_GRACE":        "2s",
		"CERBERUS_DB_LOCK_TIMEOUT":         "1s",
		"CERBERUS_DB_CONNECT_TIMEOUT":      "4s",
		"CERBERUS_DB_MAX_CONNS":            "2",
		"CERBERUS_DB_WAREHOUSE_UNRELATED":  "ignored",
		"SOMETHING_ELSE_ENTIRELY_PASSWORD": "also-not-in-any-error",
	}
}

func TestLoadConfigAcceptsACompleteAlias(t *testing.T) {
	cfg, err := LoadConfigFrom(completeEnvironment())
	if err != nil {
		t.Fatalf("LoadConfigFrom() = %v", err)
	}
	if len(cfg.Aliases) != 1 {
		t.Fatalf("got %d aliases, want 1", len(cfg.Aliases))
	}
	got := cfg.Aliases[0]
	want := AliasSpec{
		Alias:    "warehouse",
		Engine:   gate.SQLServer,
		Host:     "sql.internal.example",
		Port:     1433,
		Database: "OperationsWarehouse",
		User:     "svc_reader_account",
		Password: Secret("pa55word-not-in-any-error"),
		TLS:      TLSRequireInsecure,
	}
	if got != want {
		t.Errorf("alias spec mismatch:\n got %+v\nwant %+v", got, want)
	}
	if cfg.Settings.RowCap != 250 || cfg.Settings.QueryTimeout != 7*time.Second ||
		cfg.Settings.TimeoutGrace != 2*time.Second || cfg.Settings.LockTimeout != time.Second ||
		cfg.Settings.ConnectTimeout != 4*time.Second || cfg.Settings.MaxConns != 2 {
		t.Errorf("settings mismatch: %+v", cfg.Settings)
	}
}

func TestLoadConfigDefaultsEverySettingButTheAliases(t *testing.T) {
	env := map[string]string{
		"CERBERUS_DB_ALIASES":      "one",
		"CERBERUS_DB_ONE_ENGINE":   "postgresql",
		"CERBERUS_DB_ONE_HOST":     "localhost",
		"CERBERUS_DB_ONE_PORT":     "5432",
		"CERBERUS_DB_ONE_DATABASE": "app",
		"CERBERUS_DB_ONE_USER":     "reader",
		"CERBERUS_DB_ONE_PASSWORD": "secret",
	}
	cfg, err := LoadConfigFrom(env)
	if err != nil {
		t.Fatalf("LoadConfigFrom() = %v", err)
	}
	if cfg.Settings.RowCap < 1 || cfg.Settings.QueryTimeout <= 0 || cfg.Settings.LockTimeout <= 0 ||
		cfg.Settings.ConnectTimeout <= 0 || cfg.Settings.TimeoutGrace <= 0 || cfg.Settings.MaxConns < 1 {
		t.Fatalf("a default is missing or unusable: %+v", cfg.Settings)
	}
	if cfg.Aliases[0].TLS != TLSDefault {
		t.Errorf("TLS = %q, want the driver default", cfg.Aliases[0].TLS)
	}
}

// TestLoadConfigRejectsAndNamesTheVariable is the whole of acceptance criterion
// 1's second half. Every case asserts three things: the error is the right
// sentinel, it names the alias and the variable, and it contains none of the
// environment's values.
func TestLoadConfigRejectsAndNamesTheVariable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		bend     func(env map[string]string)
		want     error
		wantText []string
	}{
		{
			name:     "the password is missing",
			bend:     func(env map[string]string) { delete(env, "CERBERUS_DB_WAREHOUSE_PASSWORD") },
			want:     ErrMissingVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_PASSWORD"},
		},
		{
			name:     "the password is set to the empty string",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_PASSWORD"] = "" },
			want:     ErrMissingVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_PASSWORD"},
		},
		{
			name:     "the port is not a number",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_PORT"] = "fourteen-thirty-three" },
			want:     ErrInvalidVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_PORT"},
		},
		{
			name:     "the port is out of range",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_PORT"] = "70000" },
			want:     ErrInvalidVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_PORT"},
		},
		{
			name:     "the engine is not one of the three",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_ENGINE"] = "oracle" },
			want:     ErrInvalidVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_ENGINE"},
		},
		{
			name:     "the engine is the right engine in the wrong case",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_ENGINE"] = "SQLServer" },
			want:     ErrInvalidVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_ENGINE"},
		},
		{
			name: "the alias is named and entirely absent",
			bend: func(env map[string]string) {
				env["CERBERUS_DB_ALIASES"] = "warehouse,ghost"
			},
			want:     ErrMissingVariable,
			wantText: []string{"ghost", "CERBERUS_DB_GHOST_ENGINE"},
		},
		{
			name:     "the TLS mode is not one of ours",
			bend:     func(env map[string]string) { env["CERBERUS_DB_WAREHOUSE_TLS"] = "yes-please" },
			want:     ErrInvalidVariable,
			wantText: []string{"warehouse", "CERBERUS_DB_WAREHOUSE_TLS"},
		},
		{
			name:     "no aliases at all",
			bend:     func(env map[string]string) { delete(env, "CERBERUS_DB_ALIASES") },
			want:     ErrNoAliases,
			wantText: []string{"CERBERUS_DB_ALIASES"},
		},
		{
			name:     "the alias list is only separators",
			bend:     func(env map[string]string) { env["CERBERUS_DB_ALIASES"] = " , , " },
			want:     ErrNoAliases,
			wantText: []string{"CERBERUS_DB_ALIASES"},
		},
		{
			name:     "an alias name cannot be a variable name",
			bend:     func(env map[string]string) { env["CERBERUS_DB_ALIASES"] = "ware house" },
			want:     ErrInvalidAlias,
			wantText: []string{"ware house"},
		},
		{
			name:     "an alias name starts with a digit",
			bend:     func(env map[string]string) { env["CERBERUS_DB_ALIASES"] = "1warehouse" },
			want:     ErrInvalidAlias,
			wantText: []string{"1warehouse"},
		},
		{
			name: "two aliases share one variable family",
			bend: func(env map[string]string) {
				env["CERBERUS_DB_ALIASES"] = "ware-house,ware_house"
			},
			want:     ErrDuplicateAlias,
			wantText: []string{"ware-house", "ware_house", "CERBERUS_DB_WARE_HOUSE"},
		},
		{
			name:     "the row cap is zero",
			bend:     func(env map[string]string) { env["CERBERUS_DB_ROW_CAP"] = "0" },
			want:     ErrInvalidVariable,
			wantText: []string{"CERBERUS_DB_ROW_CAP"},
		},
		{
			name:     "the query timeout is negative",
			bend:     func(env map[string]string) { env["CERBERUS_DB_QUERY_TIMEOUT"] = "-1s" },
			want:     ErrInvalidVariable,
			wantText: []string{"CERBERUS_DB_QUERY_TIMEOUT"},
		},
		{
			name:     "the query timeout is not a duration",
			bend:     func(env map[string]string) { env["CERBERUS_DB_QUERY_TIMEOUT"] = "forever" },
			want:     ErrInvalidVariable,
			wantText: []string{"CERBERUS_DB_QUERY_TIMEOUT"},
		},
		{
			name:     "the row cap is not a number",
			bend:     func(env map[string]string) { env["CERBERUS_DB_ROW_CAP"] = "many" },
			want:     ErrInvalidVariable,
			wantText: []string{"CERBERUS_DB_ROW_CAP"},
		},
		{
			// env reports every field it could not parse, so both variables have to
			// be named. Only one being named would send an operator round the loop
			// twice.
			name: "two global settings are unparseable at once",
			bend: func(env map[string]string) {
				env["CERBERUS_DB_ROW_CAP"] = "many"
				env["CERBERUS_DB_LOCK_TIMEOUT"] = "a while"
			},
			want:     ErrInvalidVariable,
			wantText: []string{"CERBERUS_DB_ROW_CAP", "CERBERUS_DB_LOCK_TIMEOUT"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := completeEnvironment()
			tt.bend(env)
			_, err := LoadConfigFrom(env)
			if err == nil {
				t.Fatalf("LoadConfigFrom() = nil, want %v", tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("LoadConfigFrom() = %v, want %v", err, tt.want)
			}
			text := err.Error()
			for _, want := range tt.wantText {
				if !strings.Contains(text, want) {
					t.Errorf("error does not name %q: %s", want, text)
				}
			}
			assertNoValues(t, text, env)
		})
	}
}

// assertNoValues is the "never printing a value" half of criterion 1. It checks
// the error against the environment's own values rather than against a list of
// patterns, so a value nobody thought of is still caught.
func assertNoValues(t *testing.T, text string, env map[string]string) {
	t.Helper()
	for name, value := range env {
		if value == "" || len(value) < 4 {
			// Too short to be evidence of anything: "2s" appears in a duration
			// message by coincidence, not by disclosure.
			continue
		}
		// The alias list is not a value in the sense that matters — it is the one
		// variable whose contents are names, and naming the alias is required.
		if name == "CERBERUS_DB_ALIASES" {
			continue
		}
		if strings.Contains(text, value) {
			t.Errorf("error text contains the value of %s: %s", name, text)
		}
	}
}

// TestSettingFormsCoverEverySetting keeps [settingForms] honest against the
// struct tags it paraphrases. Without this, renaming a variable would leave an
// unparseable value naming the old one — an error that is worse than the vague
// message it replaced, because it is confidently wrong.
func TestSettingFormsCoverEverySetting(t *testing.T) {
	fields := reflect.TypeOf(Settings{})
	if fields.NumField() != len(settingForms) {
		t.Errorf("Settings has %d fields and settingForms knows %d", fields.NumField(), len(settingForms))
	}
	for i := range fields.NumField() {
		field := fields.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			form, ok := settingForms[field.Name]
			if !ok {
				t.Fatalf("settingForms has no entry for %s, so an unparseable %s would go unnamed", field.Name, field.Tag.Get("env"))
			}
			if want := field.Tag.Get("env"); form.variable != want {
				t.Errorf("settingForms says %s is read from %s, the tag says %s", field.Name, form.variable, want)
			}
			if strings.TrimSpace(form.form) == "" {
				t.Errorf("%s has no described form", field.Name)
			}
		})
	}
}

// TestSecretRedactsItself covers the renderings something might reach for while
// holding a whole config struct.
func TestSecretRedactsItself(t *testing.T) {
	spec := AliasSpec{Alias: "a", Password: Secret("hunter2-the-actual-password")}
	for _, tt := range []struct {
		name string
		got  string
	}{
		{"%v", fmt.Sprintf("%v", spec)},
		{"%+v", fmt.Sprintf("%+v", spec)},
		{"%#v", fmt.Sprintf("%#v", spec)},
		{"%s on the secret", fmt.Sprintf("%s", spec.Password)},
		{"%q on the secret", fmt.Sprintf("%q", spec.Password)},
		{"String", spec.Password.String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.got, "hunter2") {
				t.Fatalf("rendering leaked the password: %s", tt.got)
			}
			if !strings.Contains(tt.got, redacted) {
				t.Fatalf("rendering does not say it redacted anything: %s", tt.got)
			}
		})
	}
	if spec.Password.reveal() != "hunter2-the-actual-password" {
		t.Fatal("reveal must still return the password; it is the only way to connect")
	}
}

func TestStatementDeadlineOutlivesTheServerBoundExceptOnSQLServer(t *testing.T) {
	s := Settings{QueryTimeout: 10 * time.Second, TimeoutGrace: 3 * time.Second}
	if got := s.statementDeadline(gate.PostgreSQL); got != 13*time.Second {
		t.Errorf("postgresql deadline = %v, want 13s", got)
	}
	if got := s.statementDeadline(gate.MySQL); got != 13*time.Second {
		t.Errorf("mysql deadline = %v, want 13s", got)
	}
	// SQL Server has no server-side statement bound, so the context is the bound
	// rather than the backstop and there is nothing to outlive.
	if got := s.statementDeadline(gate.SQLServer); got != 10*time.Second {
		t.Errorf("sqlserver deadline = %v, want 10s", got)
	}
}

func TestVariableFamily(t *testing.T) {
	for _, tt := range []struct {
		alias string
		want  string
	}{
		{"warehouse", "CERBERUS_DB_WAREHOUSE"},
		{"WAREHOUSE", "CERBERUS_DB_WAREHOUSE"},
		{"ware-house", "CERBERUS_DB_WARE_HOUSE"},
		{"ware_house2", "CERBERUS_DB_WARE_HOUSE2"},
	} {
		t.Run(tt.alias, func(t *testing.T) {
			got, err := variableFamily(tt.alias)
			if err != nil {
				t.Fatalf("variableFamily(%q) = %v", tt.alias, err)
			}
			if got != tt.want {
				t.Errorf("variableFamily(%q) = %q, want %q", tt.alias, got, tt.want)
			}
		})
	}
}

// TestLoadConfigFromDoesNotReadTheProcessEnvironment is the "and nowhere else"
// half of criterion 1 for the parsing path: the map is the whole input.
func TestLoadConfigFromDoesNotReadTheProcessEnvironment(t *testing.T) {
	env := completeEnvironment()
	before := maps.Clone(env)
	t.Setenv("CERBERUS_DB_ROW_CAP", "99999")
	t.Setenv("CERBERUS_DB_WAREHOUSE_HOST", "somewhere-else.example")
	cfg, err := LoadConfigFrom(env)
	if err != nil {
		t.Fatalf("LoadConfigFrom() = %v", err)
	}
	if cfg.Settings.RowCap != 250 {
		t.Errorf("RowCap = %d, want the map's 250 rather than the process's 99999", cfg.Settings.RowCap)
	}
	if cfg.Aliases[0].Host != "sql.internal.example" {
		t.Errorf("Host = %q, want the map's value", cfg.Aliases[0].Host)
	}
	if !maps.Equal(env, before) {
		t.Error("LoadConfigFrom modified the environment it was given")
	}
}
