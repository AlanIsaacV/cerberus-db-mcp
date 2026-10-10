package mcp

import (
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcpserve"
)

var ErrInvalidVariable = mcpserve.ErrInvalidVariable

// Config is the whole of this package's configuration. Like internal/db's, it
// comes from the environment and only from the environment: there is no
// configuration file and nothing here reads one. The one path it carries,
// GateOverlay, names a gate ruleset overlay that internal/gate reads.
type Config struct {
	Address         string        `env:"CERBERUS_MCP_ADDRESS"`
	Path            string        `env:"CERBERUS_MCP_PATH"`
	ShutdownTimeout time.Duration `env:"CERBERUS_MCP_SHUTDOWN_TIMEOUT"`
	LogLevel        zerolog.Level `env:"CERBERUS_MCP_LOG_LEVEL"`
	GateOverlay     string        `env:"CERBERUS_MCP_GATE_OVERLAY"`
}

func LoadConfig() (*Config, error) {
	shared, err := mcpserve.LoadConfig()
	if err != nil {
		return nil, err
	}
	return withGateOverlay(shared, os.Getenv(variableForms["GateOverlay"].variable)), nil
}

func LoadConfigFrom(environ map[string]string) (*Config, error) {
	shared, err := mcpserve.LoadConfigFrom(environ)
	if err != nil {
		return nil, err
	}
	return withGateOverlay(shared, environ[variableForms["GateOverlay"].variable]), nil
}

func withGateOverlay(shared *mcpserve.Config, overlay string) *Config {
	return &Config{
		Address:         shared.Address,
		Path:            shared.Path,
		ShutdownTimeout: shared.ShutdownTimeout,
		LogLevel:        shared.LogLevel,
		GateOverlay:     overlay,
	}
}

func (c Config) shared() mcpserve.Config {
	return mcpserve.Config{
		Address:         c.Address,
		Path:            c.Path,
		ShutdownTimeout: c.ShutdownTimeout,
		LogLevel:        c.LogLevel,
	}
}

var variableForms = func() map[string]struct{ variable, form string } {
	forms := map[string]struct{ variable, form string }{
		"GateOverlay": {"CERBERUS_MCP_GATE_OVERLAY", "the path of a gate ruleset overlay file, or empty for the baseline alone"},
	}
	for field, f := range mcpserve.VariableForms() {
		forms[field] = struct{ variable, form string }{f.Variable, f.Form}
	}
	return forms
}()

func (c Config) validate() error {
	return c.shared().Validate()
}

var splitAddress = mcpserve.SplitAddress

func (c Config) IsLoopback() bool {
	return c.shared().IsLoopback()
}
