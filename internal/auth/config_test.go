package auth

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// testSealingSecret is a base64 encoding of exactly 32 bytes. It is a fixed test
// fixture, not a credential accepted by any deployment.
const testSealingSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// TestNoConfigurationLoadsWithoutAClientIDAndANonEmptyAllowlist is acceptance
// criterion 7.
//
// It is the property that makes an unauthenticated deployment impossible by
// omission: there is no value of the environment for which this loader returns a
// configuration that admits everybody, and no value for which it returns one that
// admits nobody either. Both would start, and one of them would be a database on
// the internet.
func TestNoConfigurationLoadsWithoutAClientIDAndANonEmptyAllowlist(t *testing.T) {
	for _, tt := range []struct {
		name    string
		environ map[string]string
		want    error
		names   string
	}{
		{
			name:    "nothing at all is set",
			environ: map[string]string{},
			want:    ErrNoClientID,
			names:   "CERBERUS_AUTH_GOOGLE_CLIENT_ID",
		},
		{
			name:    "a client ID with no allowlist beside it",
			environ: map[string]string{"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID},
			want:    ErrNoAllowlist,
			names:   "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "a sealing secret that is absent",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
			},
			want:  ErrNoSealingMaterial,
			names: "CERBERUS_AUTH_SEALING_SECRET",
		},
		{
			name: "a sealing secret that is not base64",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
				"CERBERUS_AUTH_SEALING_SECRET":   "not base64!",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_SEALING_SECRET",
		},
		{
			name: "a sealing secret that decodes to the wrong length",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
				"CERBERUS_AUTH_SEALING_SECRET":   "AQID",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_SEALING_SECRET",
		},
		{
			name: "a sealing secret with trailing whitespace is refused rather than repaired",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
				"CERBERUS_AUTH_SEALING_SECRET":   testSealingSecret + "\n",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_SEALING_SECRET",
		},
		{
			name: "an allowlist variable that is present and empty",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "",
			},
			want:  ErrNoAllowlist,
			names: "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "an allowlist of separators and spaces",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   " , , ",
			},
			want:  ErrNoAllowlist,
			names: "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "an allowlist holding a bare domain",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				// The mistake this refuses is an operator expecting a domain to admit
				// everyone in it. Accepting the entry would start a server that admits
				// nobody, for a reason nothing says out loud.
				"CERBERUS_AUTH_ALLOWED_EMAILS": "unmatchable-domain.example",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "two addresses separated by a space instead of a comma",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test two@example.test",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "an allowlist entry with no local part",
			environ: map[string]string{
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "@example.test",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_ALLOWED_EMAILS",
		},
		{
			name: "a client ID with a space in it",
			environ: map[string]string{
				// What this catches in practice is a value pasted across two lines or
				// read out of a file with its newline attached, both of which otherwise
				// produce a server that answers 401 to a correct token.
				"CERBERUS_AUTH_GOOGLE_CLIENT_ID": "clientid with a space in it.apps.googleusercontent.com",
				"CERBERUS_AUTH_ALLOWED_EMAILS":   "one@example.test",
			},
			want:  ErrInvalidVariable,
			names: "CERBERUS_AUTH_GOOGLE_CLIENT_ID",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadConfigFrom(tt.environ)
			if !errors.Is(err, tt.want) {
				t.Fatalf("LoadConfigFrom = (%+v, %v), want an error wrapping %v", cfg, err, tt.want)
			}
			if cfg != nil {
				t.Errorf("LoadConfigFrom returned a configuration alongside its error: %+v", cfg)
			}
			// Naming the variable is the whole value of the message: an operator told
			// only that "a CERBERUS_AUTH_* variable is wrong" has to bisect their
			// environment.
			if !strings.Contains(err.Error(), tt.names) {
				t.Errorf("the error does not name %s: %s", tt.names, err)
			}
			// And no supplied value appears in it, which is this repository's rule for
			// every configuration error whether or not the value is a secret.
			for name, value := range tt.environ {
				if value != "" && strings.Contains(err.Error(), value) {
					t.Errorf("the error quotes the value of %s: %s", name, err)
				}
			}
		})
	}
}

// TestAnEmptyVariableIsTreatedAsUnset pins the rule the other two configuration
// groups already follow, through the loader that reads the process environment.
func TestAnEmptyVariableIsTreatedAsUnset(t *testing.T) {
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", testClientID)
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", testSealingSecret)

	cfg, err := LoadConfig()
	if !errors.Is(err, ErrNoAllowlist) {
		t.Fatalf("LoadConfig = (%+v, %v), want an error wrapping ErrNoAllowlist", cfg, err)
	}
}

func TestAWholeConfigurationLoadsFromTheEnvironment(t *testing.T) {
	t.Setenv("CERBERUS_AUTH_GOOGLE_CLIENT_ID", testClientID)
	t.Setenv("CERBERUS_AUTH_ALLOWED_EMAILS", "one@example.test,two@example.test")
	t.Setenv("CERBERUS_AUTH_SEALING_SECRET", testSealingSecret)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := &Config{ClientID: testClientID, AllowedEmails: []string{"one@example.test", "two@example.test"}, SealingSecret: testSealingSecret}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("LoadConfig = %+v, want %+v", cfg, want)
	}
}

// TestTheAllowlistAdmitsAnAddressWhateverCaseAndSpacingItWasWrittenIn matters
// because the failure it prevents is invisible: an address that differs from
// Google's by a capital letter is refused with a 403 that looks exactly like the
// 403 of somebody who was never added.
func TestTheAllowlistAdmitsAnAddressWhateverCaseAndSpacingItWasWrittenIn(t *testing.T) {
	cfg, err := LoadConfigFrom(map[string]string{
		"CERBERUS_AUTH_GOOGLE_CLIENT_ID": testClientID,
		"CERBERUS_AUTH_ALLOWED_EMAILS":   " Alan.Vazquez@Example.Test , second@example.test,",
		"CERBERUS_AUTH_SEALING_SECRET":   testSealingSecret,
	})
	if err != nil {
		t.Fatalf("LoadConfigFrom: %v", err)
	}
	// The operator's own spelling is kept on the struct, so that what a startup log
	// or a diff shows is what they wrote.
	if cfg.AllowedEmails[0] != " Alan.Vazquez@Example.Test " {
		t.Errorf("AllowedEmails[0] = %q, want the value exactly as it was set", cfg.AllowedEmails[0])
	}
	got := cfg.Allowlist()
	want := []string{"alan.vazquez@example.test", "second@example.test"}
	if !slices.Equal(got, want) {
		t.Errorf("Allowlist() = %q, want %q; the trailing comma must not become an entry", got, want)
	}
}

func TestASealingSecretIsRedactedByEveryOrdinaryRendering(t *testing.T) {
	secret := Secret(testSealingSecret)
	for _, tt := range []struct {
		name string
		got  func() string
	}{
		{"String", secret.String},
		{"GoString", secret.GoString},
		{"MarshalText", func() string { text, _ := secret.MarshalText(); return string(text) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(); got != redactedSecret && got != `"`+redactedSecret+`"` {
				t.Errorf("%s rendered %q, want a redaction", tt.name, got)
			}
			if strings.Contains(tt.got(), testSealingSecret) {
				t.Errorf("%s rendered the sealing secret", tt.name)
			}
		})
	}
}

// TestVariableFormsCoverEveryField keeps [variableForms] in step with the struct
// it describes. A field added without an entry produces an error message that
// names no variable, which is the failure mode the table exists to prevent.
func TestVariableFormsCoverEveryField(t *testing.T) {
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		form, ok := variableForms[field.Name]
		if !ok {
			t.Errorf("Config.%s has no entry in variableForms", field.Name)
			continue
		}
		if want := field.Tag.Get("env"); form.variable != want {
			t.Errorf("variableForms[%q].variable = %q, want %q from the struct tag", field.Name, form.variable, want)
		}
		if !strings.HasPrefix(form.variable, "CERBERUS_AUTH_") {
			t.Errorf("variableForms[%q].variable = %q, want a CERBERUS_AUTH_* variable", field.Name, form.variable)
		}
	}
	for name := range variableForms {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("variableForms has an entry for %q, which is not a field of Config", name)
		}
	}
}

// TestBuildingAMiddlewareIsRefusedForTheSameReasonsLoadingIs closes the route
// around the loader: a Config assembled in code is held to the same three rules, so
// the binary cannot acquire an unauthenticated middleware by building its own
// configuration.
func TestBuildingAMiddlewareIsRefusedForTheSameReasonsLoadingIs(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  Config
		want error
	}{
		{"no client ID", Config{AllowedEmails: []string{"one@example.test"}}, ErrNoClientID},
		{"no allowlist", Config{ClientID: testClientID}, ErrNoAllowlist},
		{"no sealing secret", Config{ClientID: testClientID, AllowedEmails: []string{"one@example.test"}}, ErrNoSealingMaterial},
		{"an allowlist of one blank entry", Config{ClientID: testClientID, AllowedEmails: []string{"  "}}, ErrNoAllowlist},
		{"an unmatchable allowlist entry", Config{ClientID: testClientID, AllowedEmails: []string{"nobody"}}, ErrInvalidVariable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewMiddleware(tt.cfg, discardLogger())
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewMiddleware = %v, want an error wrapping %v", err, tt.want)
			}
			if middleware != nil {
				t.Error("NewMiddleware returned a middleware alongside its error, which a caller ignoring the error would install")
			}
		})
	}
}
