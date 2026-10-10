package redismcp

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
)

func str(s string) redisdb.Value { return redisdb.Value{Type: redisdb.TypeString, Bytes: []byte(s)} }

func arr(vs ...redisdb.Value) redisdb.Value {
	if vs == nil {
		vs = []redisdb.Value{}
	}
	return redisdb.Value{Type: redisdb.TypeArray, Array: vs}
}

func encodedJSON(t *testing.T, v redisdb.Value, truncation redisdb.Truncation) string {
	t.Helper()
	raw, err := json.Marshal(encodeReply(v, truncation))
	if err != nil {
		t.Fatalf("marshal encoded reply: %v", err)
	}
	return string(raw)
}

func TestReplyEncoding(t *testing.T) {
	for _, tt := range []struct {
		name       string
		value      redisdb.Value
		truncation redisdb.Truncation
		want       string
	}{
		{"utf-8 string", str("héllo ☃ 𝄞"), redisdb.TruncationNone, `"héllo ☃ 𝄞"`},
		{"empty string", str(""), redisdb.TruncationNone, `""`},
		{"binary string", str("\xff\xfe"), redisdb.TruncationNone, `{"$base64":"//4="}`},
		{"integer", redisdb.Value{Type: redisdb.TypeInteger, Integer: -42}, redisdb.TruncationNone, `-42`},
		{"nil", redisdb.Value{Type: redisdb.TypeNil}, redisdb.TruncationNone, `null`},
		{"empty array", arr(), redisdb.TruncationNone, `[]`},
		{"nested error", arr(str("ok"), redisdb.Value{Type: redisdb.TypeError, Message: "WRONGTYPE Operation against a key holding the wrong kind of value"}), redisdb.TruncationNone,
			`["ok",{"error":"WRONGTYPE Operation against a key holding the wrong kind of value"}]`},
		{"mixed array at depth", arr(
			str("a"),
			arr(redisdb.Value{Type: redisdb.TypeInteger, Integer: 7}, arr(redisdb.Value{Type: redisdb.TypeNil}, str("\x00\xc3"))),
			str("z"),
		), redisdb.TruncationNone, `["a",[7,[null,{"$base64":"AMM="}]],"z"]`},
		{"incomplete trail without a byte budget cut stays base64", str("ab\xe2\x82"), redisdb.TruncationNone, `{"$base64":"YWLigg=="}`},
		{"incomplete trail under element_cap stays base64", str("ab\xe2\x82"), redisdb.TruncationElementCap, `{"$base64":"YWLigg=="}`},
		{"invalid byte before a cut stays base64", str("a\xffb\xe2\x82"), redisdb.TruncationByteBudget, `{"$base64":"Yf9i4oI="}`},
		{"invalid trailing byte under a cut stays base64", str("ab\xff"), redisdb.TruncationByteBudget, `{"$base64":"YWL/"}`},
		{"an orphan continuation byte under a cut stays base64", str("ab\x82"), redisdb.TruncationByteBudget, `{"$base64":"YWKC"}`},
		{"a cut string that is not the final one stays base64", arr(str("ab\xe2\x82"), str("cd")), redisdb.TruncationByteBudget, `[{"$base64":"YWLigg=="},"cd"]`},
		{"the final string of a nested reply is the cut one", arr(str("x"), arr(str("ab\xe2\x82"))), redisdb.TruncationByteBudget, `["x",["ab"]]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodedJSON(t, tt.value, tt.truncation); got != tt.want {
				t.Errorf("encodeReply = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAByteBudgetCutInsideARuneKeepsTheValidPrefix(t *testing.T) {
	for _, r := range []string{"é", "☃", "𝄞"} {
		for k := 0; k <= len(r); k++ {
			cut := "ab" + r[:k]
			want := "ab"
			if k == len(r) {
				want = cut
			}
			t.Run(fmt.Sprintf("%d-byte rune cut after %d bytes", len(r), k), func(t *testing.T) {
				wantJSON, _ := json.Marshal(want)
				if got := encodedJSON(t, str(cut), redisdb.TruncationByteBudget); got != string(wantJSON) {
					t.Errorf("top level: encodeReply(%q) = %s, want %s", cut, got, wantJSON)
				}
				wantNested := `[1,` + string(wantJSON) + `]`
				nested := arr(redisdb.Value{Type: redisdb.TypeInteger, Integer: 1}, str(cut))
				if got := encodedJSON(t, nested, redisdb.TruncationByteBudget); got != wantNested {
					t.Errorf("nested: encodeReply = %s, want %s", got, wantNested)
				}
			})
		}
	}
}
