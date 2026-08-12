package mcp

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestDefaultsAreLoopbackAndNothingElse is acceptance criterion 9's loader half:
// with nothing set beyond the database variables, the resolved listen address is
// loopback. The source half — that no other default exists anywhere in the
// package — is TestNoOtherListenAddressDefaultExists in guards_test.go.
//
// It matters because this objective builds no authentication. Every other
// default in this struct is a convenience; this one is the only thing standing
// between an unconfigured run and an unauthenticated database reader on the
// network.
func TestDefaultsAreLoopbackAndNothingElse(t *testing.T) {
	// An empty environment, not the process's: the point is what happens when
	// nothing is set.
	cfg, err := LoadConfigFrom(map[string]string{})
	if err != nil {
		t.Fatalf("LoadConfigFrom(nothing) = %v, want a usable default configuration", err)
	}

	host, port, err := splitAddress(cfg.Address)
	if err != nil {
		t.Fatalf("the default address %q is not usable: %v", cfg.Address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Errorf("the default host is %q, which is not a loopback address", host)
	}
	if !cfg.IsLoopback() {
		t.Errorf("IsLoopback() = false for the default address %q", cfg.Address)
	}
	if port == 0 {
		t.Errorf("the default port is 0, which would bind an arbitrary port")
	}

	want := &Config{
		Address:         "127.0.0.1:8080",
		Path:            "/mcp",
		ShutdownTimeout: 30 * time.Second,
		Audit:           AuditStdout,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("LoadConfigFrom(nothing) = %+v, want %+v", cfg, want)
	}
}

// TestReachingEveryInterfaceTakesADeliberateSetting is the other side of
// criterion 9: 0.0.0.0 is reachable, and only by writing it down.
func TestReachingEveryInterfaceTakesADeliberateSetting(t *testing.T) {
	cfg, err := LoadConfigFrom(map[string]string{"CERBERUS_MCP_ADDRESS": "0.0.0.0:8080"})
	if err != nil {
		t.Fatalf("LoadConfigFrom = %v, want the explicit address to be accepted", err)
	}
	if cfg.Address != "0.0.0.0:8080" {
		t.Errorf("Address = %q, want the value that was set", cfg.Address)
	}
	if cfg.IsLoopback() {
		t.Error("IsLoopback() = true for 0.0.0.0, so nothing would warn about an unauthenticated exposure")
	}
}

func TestConfigRejectsUnusableValues(t *testing.T) {
	for _, tt := range []struct {
		name    string
		environ map[string]string
	}{
		{"an address with no port", map[string]string{"CERBERUS_MCP_ADDRESS": "127.0.0.1"}},
		{"an address with no host", map[string]string{"CERBERUS_MCP_ADDRESS": ":8080"}},
		{"an address with a word for a port", map[string]string{"CERBERUS_MCP_ADDRESS": "127.0.0.1:http"}},
		{"a port out of range", map[string]string{"CERBERUS_MCP_ADDRESS": "127.0.0.1:70000"}},
		{"a relative mount path", map[string]string{"CERBERUS_MCP_PATH": "mcp"}},
		// The three below are refused at load for the same reason a relative path
		// is: http.ServeMux takes a pattern, not a path. A space makes Handle
		// panic — and it panics from Run, after the port is open and the log says
		// the server is serving — and a brace is accepted as a wildcard, which
		// mounts the endpoint on /mcp/anything without saying so. Every other
		// unusable value in this loader is an error at startup and so is this.
		{"a mount path containing a space", map[string]string{"CERBERUS_MCP_PATH": "/mcp x"}},
		{"a mount path with an unbalanced brace", map[string]string{"CERBERUS_MCP_PATH": "/mcp/{"}},
		{"a mount path that is a wildcard pattern", map[string]string{"CERBERUS_MCP_PATH": "/mcp/{id}"}},
		{"a shutdown timeout with no unit", map[string]string{"CERBERUS_MCP_SHUTDOWN_TIMEOUT": "30"}},
		{"a shutdown timeout of zero", map[string]string{"CERBERUS_MCP_SHUTDOWN_TIMEOUT": "0s"}},
		{"a negative shutdown timeout", map[string]string{"CERBERUS_MCP_SHUTDOWN_TIMEOUT": "-1s"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfigFrom(tt.environ)
			if !errors.Is(err, ErrInvalidVariable) {
				t.Fatalf("LoadConfigFrom(%v) = %v, want an error wrapping ErrInvalidVariable", tt.environ, err)
			}
			// Naming the variable is the whole value of the message: an operator
			// told only that "a CERBERUS_MCP_* variable is wrong" has to bisect
			// their environment.
			for name := range tt.environ {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("the error does not name %s: %s", name, err)
				}
			}
		})
	}
}

// TestAnEmptyVariableIsTreatedAsUnset pins the rule internal/db already follows.
// It matters most for the address: a variable emptied by a broken template
// substitution must get the loopback default rather than become "every
// interface" or fail in a way somebody works around by setting 0.0.0.0.
func TestAnEmptyVariableIsTreatedAsUnset(t *testing.T) {
	t.Setenv("CERBERUS_MCP_ADDRESS", "")
	t.Setenv("CERBERUS_MCP_PATH", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.IsLoopback() {
		t.Errorf("Address = %q for an empty variable, want the loopback default", cfg.Address)
	}
	if cfg.Path != "/mcp" {
		t.Errorf("Path = %q for an empty variable, want the default", cfg.Path)
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
	}
	for name := range variableForms {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("variableForms has an entry for %q, which is not a field of Config", name)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for _, tt := range []struct {
		address string
		want    bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.53:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"192.168.1.10:8080", false},
		{"db.example:8080", false},
		{"nonsense", false},
		{"", false},
	} {
		t.Run(tt.address, func(t *testing.T) {
			if got := (Config{Address: tt.address}).IsLoopback(); got != tt.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}
