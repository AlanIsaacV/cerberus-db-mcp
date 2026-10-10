package redismcp

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisdb"
)

type Binary struct {
	Base64 string `json:"$base64"`
}

type ReplyError struct {
	Message string `json:"error"`
}

const maxIncompleteTrail = utf8.UTFMax - 1

func encodeReply(v redisdb.Value, truncation redisdb.Truncation) any {
	e := &encoder{cut: -1}
	if truncation == redisdb.TruncationByteBudget {
		e.cut = leaves(v) - 1
	}
	return e.value(v)
}

type encoder struct {
	cut  int
	leaf int
}

func (e *encoder) value(v redisdb.Value) any {
	if v.Type == redisdb.TypeArray {
		out := make([]any, len(v.Array))
		for i := range v.Array {
			out[i] = e.value(v.Array[i])
		}
		return out
	}
	last := e.leaf == e.cut
	e.leaf++
	switch v.Type {
	case redisdb.TypeInteger:
		return v.Integer
	case redisdb.TypeNil:
		return nil
	case redisdb.TypeError:
		return ReplyError{Message: v.Message}
	default:
		return text(v.Bytes, last)
	}
}

func leaves(v redisdb.Value) int {
	if v.Type != redisdb.TypeArray {
		return 1
	}
	n := 0
	for i := range v.Array {
		n += leaves(v.Array[i])
	}
	return n
}

func text(b []byte, cut bool) any {
	if utf8.Valid(b) {
		return string(b)
	}
	if cut {
		if prefix, ok := withoutIncompleteTrail(b); ok {
			return string(prefix)
		}
	}
	return Binary{Base64: base64.StdEncoding.EncodeToString(b)}
}

func withoutIncompleteTrail(b []byte) ([]byte, bool) {
	for n := 1; n <= maxIncompleteTrail && n <= len(b); n++ {
		prefix, trail := b[:len(b)-n], b[len(b)-n:]
		if utf8.RuneStart(trail[0]) && !utf8.FullRune(trail) && utf8.Valid(prefix) {
			return prefix, true
		}
	}
	return nil, false
}
