package gate

import (
	"errors"
	"testing"
)

func TestParseEngine(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want Engine
		err  error
	}{
		{"mysql", "mysql", MySQL, nil},
		{"postgresql", "postgresql", PostgreSQL, nil},
		{"sqlserver", "sqlserver", SQLServer, nil},
		{"unknown", "oracle", "", ErrUnknownEngine},
		{"empty", "", "", ErrUnknownEngine},
		{"wrong case", "MySQL", "", ErrUnknownEngine},
		{"alias is not accepted", "postgres", "", ErrUnknownEngine},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEngine(tt.in)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ParseEngine(%q) error = %v, want %v", tt.in, err, tt.err)
			}
			if got != tt.want {
				t.Fatalf("ParseEngine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEveryEngineHasADialect(t *testing.T) {
	for _, e := range Engines() {
		if !e.Valid() {
			t.Fatalf("engine %q has no dialect", e)
		}
	}
	if len(dialects) != len(Engines()) {
		t.Fatalf("%d dialects for %d engines: an engine without a dialect would be tokenized by nobody's rules", len(dialects), len(Engines()))
	}
	if Engine("oracle").Valid() {
		t.Fatalf("an unsupported engine reports itself as valid")
	}
}
