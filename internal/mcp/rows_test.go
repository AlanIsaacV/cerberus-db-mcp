package mcp

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// marshal is what the SDK does to a handler's output, so the assertions below
// are made on the bytes the client receives rather than on the Go value this
// package produced.
func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%#v) = %v; a value that cannot be marshalled fails the whole call, not just its own column", v, err)
	}
	return string(b)
}

// TestValueFormsAreDefinedPerClass is the converter's contract, class by class.
// Each case is a class the agent has to be able to tell apart from the others by
// looking at the JSON alone.
func TestValueFormsAreDefinedPerClass(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value any
		want  string
	}{
		{"SQL NULL", nil, `null`},
		{"text", "árbol", `"árbol"`},
		{"an empty string is not a NULL", "", `""`},
		{"a boolean", true, `true`},

		{
			// The whole reason [Binary] exists: as a bare base64 string this would be
			// indistinguishable from a text column whose contents happened to read
			// like base64.
			name:  "bytes that are not text",
			value: []byte{0xff, 0xfe, 0xfd},
			want:  `{"$base64":"//79"}`,
		},
		{"empty bytes", []byte{}, `{"$base64":""}`},

		{
			name:  "a timestamp with an offset",
			value: time.Date(2024, 3, 1, 12, 34, 56, 789000000, time.FixedZone("", -6*3600)),
			want:  `"2024-03-01T12:34:56.789-06:00"`,
		},
		{
			name:  "a timestamp in UTC",
			value: time.Date(2024, 3, 1, 12, 34, 56, 0, time.UTC),
			want:  `"2024-03-01T12:34:56Z"`,
		},

		{"an integer stays a number", int64(9007199254740993), `9007199254740993`},
		{"a negative integer", int32(-42), `-42`},
		{"an unsigned integer", uint64(math.MaxUint64), `18446744073709551615`},
		{"a float", 1.5, `1.5`},

		// JSON has no literal for any of these three and encoding/json refuses to
		// marshal them, which would fail the whole result over one column.
		{"not a number", math.NaN(), `"NaN"`},
		{"positive infinity", math.Inf(1), `"Infinity"`},
		{"negative infinity", math.Inf(-1), `"-Infinity"`},

		{
			// Nesting gets the same treatment as the top level, so a bytea inside a
			// PostgreSQL array is still marked.
			name:  "an array",
			value: []any{"a", nil, []byte{0xff}, 1},
			want:  `["a",null,{"$base64":"/w=="},1]`,
		},
		{"a typed array", []int32{1, 2, 3}, `[1,2,3]`},
		{"a nil slice", []any(nil), `null`},
		{
			name:  "a decoded JSON object",
			value: map[string]any{"k": []byte{0xff}},
			want:  `{"k":{"$base64":"/w=="}}`,
		},
		{"a pointer is followed", ptr("v"), `"v"`},
		{"a nil pointer is a NULL", (*string)(nil), `null`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := marshal(t, jsonValue(tt.value)); got != tt.want {
				t.Errorf("jsonValue(%#v) marshals to %s, want %s", tt.value, got, tt.want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestDecimalsKeepEveryDigit is the reason the converter consults driver.Valuer.
//
// pgtype.Numeric is the real type pgx hands back for a PostgreSQL numeric, used
// here rather than a stand-in: the property under test is that this converter
// gets the exact digits out of the type the driver actually produces, and a fake
// with a convenient Value method would prove nothing about that.
func TestDecimalsKeepEveryDigit(t *testing.T) {
	// More significant digits than a float64 can hold. Rendered through a number,
	// the last digits change; rendered through a string, they do not.
	const digits = "123456789012345678901234.56789"

	var numeric pgtype.Numeric
	if err := numeric.Scan(digits); err != nil {
		t.Fatalf("pgtype.Numeric.Scan(%s) = %v", digits, err)
	}
	got := marshal(t, jsonValue(numeric))
	if want := `"` + digits + `"`; got != want {
		t.Errorf("a numeric marshals to %s, want %s", got, want)
	}

	// The float route, shown failing, so that the choice is evidenced rather than
	// asserted.
	asFloat, _ := new(big.Float).SetString(digits)
	f, _ := asFloat.Float64()
	if degraded := marshal(t, f); degraded == `"`+digits+`"` || degraded == digits {
		t.Errorf("a float64 round-trip preserved %s, so this test no longer demonstrates anything", digits)
	}
}

// A NULL decimal is a NULL, not the string "null" and not a zero.
func TestANullDecimalIsANull(t *testing.T) {
	var numeric pgtype.Numeric // Valid is false: this is SQL NULL
	if got := marshal(t, jsonValue(numeric)); got != "null" {
		t.Errorf("a NULL numeric marshals to %s, want null", got)
	}
}

// brokenValuer is a driver value that says it can render itself and then cannot.
type brokenValuer struct{}

func (brokenValuer) Value() (driver.Value, error) { return nil, errors.New("no") }

func (brokenValuer) String() string { return "the value" }

// TestAValuerThatFailsIsRenderedRatherThanDropped: returning nil here would tell
// the agent the column was NULL, which is a different and wrong answer.
func TestAValuerThatFailsIsRenderedRatherThanDropped(t *testing.T) {
	if got := marshal(t, jsonValue(brokenValuer{})); got != `"the value"` {
		t.Errorf("a failing Valuer marshals to %s, want the fmt rendering", got)
	}
}

// TestJSONRowsConvertsEveryCell checks the whole-result-set wrapper, including
// that it does not alias its input.
func TestJSONRowsConvertsEveryCell(t *testing.T) {
	in := [][]any{
		{nil, []byte{0xff}},
		{"text", int64(1)},
	}
	got := marshal(t, jsonRows(in))
	if want := `[[null,{"$base64":"/w=="}],["text",1]]`; got != want {
		t.Errorf("jsonRows marshals to %s, want %s", got, want)
	}
	if _, stillBytes := in[0][1].([]byte); !stillBytes {
		t.Error("jsonRows mutated the rows internal/db handed it")
	}
}

// TestJSONRowsHandlesAnEmptyResultSet: no rows is a legitimate answer and must
// marshal to an empty array rather than to null, which an agent reads as an
// error.
func TestJSONRowsHandlesAnEmptyResultSet(t *testing.T) {
	if got := marshal(t, jsonRows([][]any{})); got != `[]` {
		t.Errorf("an empty result set marshals to %s, want []", got)
	}
}
