package mcp

import (
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"time"
)

// Binary is how a byte sequence that is not text reaches the agent.
//
// It exists because encoding/json renders every []byte as a bare base64 string,
// which is indistinguishable on the wire from a column that really did contain
// the text "3q2+7w==". An agent reading that has no way to tell whether it is
// looking at data or at an encoding of data, and the two call for different next
// steps. One wrapping object costs a few bytes on a column that is rare and
// makes the distinction readable.
//
// The key is dollar-prefixed to make a collision with a key from a JSON or JSONB
// column very unlikely — those columns' object keys reach the agent through this
// same converter — but not impossible: a stored object whose own single key is
// literally "$base64" with a string value marshals to exactly this shape and the
// agent cannot tell the two apart.
type Binary struct {
	Base64 string `json:"$base64"`
}

// The strings a float that JSON cannot express becomes.
//
// JSON has no literal for any of the three, and encoding/json does not degrade
// gracefully: it fails the whole marshal, which would turn one unusual value in
// one row into a failed tool call reporting nothing an agent could act on.
// Naming them is lossy in type but not in meaning.
const (
	notANumber       = "NaN"
	positiveInfinity = "Infinity"
	negativeInfinity = "-Infinity"
)

// jsonRows converts a whole result set.
//
// Its input has already been through internal/db's normalise, which turns a
// []byte whose contents are valid UTF-8 into a string. That conversion is not
// repeated or second-guessed here — on MySQL it is the reason every column is
// not base64, and on the other two engines its consequences are a recorded open
// question that belongs to internal/db, not to this layer. What arrives here is
// where this layer's job starts.
func jsonRows(rows [][]any) [][]any {
	out := make([][]any, len(rows))
	for i, row := range rows {
		converted := make([]any, len(row))
		for j, v := range row {
			converted[j] = jsonValue(v)
		}
		out[i] = converted
	}
	return out
}

// jsonValue turns one driver value into the form it takes on the wire.
//
// The whole reason this is written out rather than left to encoding/json is that
// encoding/json's defaults are wrong in two specific ways for database values: a
// non-text []byte becomes a string that lies about being text (see [Binary]),
// and a driver's decimal type becomes whatever its own marshaller decides —
// which for a big-enough numeric is a JSON number that a client's parser will
// round. Both failures are silent, and both produce an answer the agent has no
// way to tell from a correct one.
func jsonValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return t
	case []byte:
		// Everything valid UTF-8 became a string upstream, so what is left is
		// genuinely not text.
		return Binary{Base64: base64.StdEncoding.EncodeToString(t)}
	case bool:
		return t
	case time.Time:
		// RFC 3339 with whatever sub-second precision the value carries, in the
		// offset the driver decoded. It is deliberately not converted to UTC: the
		// offset is part of what the column said, and a silent shift to UTC is the
		// kind of correctness bug that only shows up in someone else's timezone.
		return t.Format(time.RFC3339Nano)
	case float32:
		return jsonFloat(float64(t))
	case float64:
		return jsonFloat(t)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		// Integers stay numbers. Go marshals them exactly, and whether a client's
		// JSON parser keeps every digit of a 19-digit identifier is a property of
		// that client which turning them all into strings would not fix — it would
		// only make every ordinary integer harder to use.
		return t
	}

	// driver.Valuer is checked after the concrete types and before the structural
	// fallback because it is the one interface the decimal types actually
	// implement: pgx's pgtype.Numeric returns its exact digits as a string from
	// Value, which is precisely the representation this converter wants and is
	// the reason a numeric does not have to be recognised by name here.
	if valuer, ok := v.(driver.Valuer); ok {
		inner, err := valuer.Value()
		if err != nil {
			// The type said it could render itself and then could not. Something is
			// better than nothing and nothing here is a credential — it is a value
			// the agent's own statement selected — so it is rendered rather than
			// dropped, which would look to the agent like a NULL.
			return fmt.Sprint(v)
		}
		// Not recursive without limit: Value returns a driver.Value, which is a
		// closed set of primitives, so this recursion terminates on the switch
		// above.
		return jsonValue(inner)
	}

	return jsonComposite(v)
}

// jsonFloat renders a float, naming the three values JSON cannot hold.
func jsonFloat(f float64) any {
	switch {
	case math.IsNaN(f):
		return notANumber
	case math.IsInf(f, 1):
		return positiveInfinity
	case math.IsInf(f, -1):
		return negativeInfinity
	}
	return f
}

// jsonComposite handles the values that are neither a primitive nor a decimal:
// a PostgreSQL array, a JSON document a driver decoded into a map, or a pointer
// to any of those.
//
// It is reflective rather than a type switch because the set of shapes three
// drivers can produce for a composite column is not enumerable in advance, and
// the failure mode of a missing case here is an opaque Go struct rendering that
// the agent cannot read. Recursing structurally means a nested value gets the
// same treatment as a top-level one, which is what makes a bytea inside an array
// still arrive marked.
func jsonComposite(v any) any {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return jsonValue(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = jsonValue(rv.Index(i).Interface())
		}
		return out
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		out := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			// A JSON object's keys are strings by definition; anything else is a Go
			// map a driver invented, and fmt is the only rendering available.
			out[fmt.Sprint(key.Interface())] = jsonValue(rv.MapIndex(key).Interface())
		}
		return out
	}
	// A struct or a type this converter has never seen. fmt is a poor rendering
	// but it is a stable one, and it keeps an unrecognised column from failing the
	// marshal of every other column in the row.
	return fmt.Sprint(v)
}
