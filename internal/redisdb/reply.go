package redisdb

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

type ValueType string

const (
	TypeString  ValueType = "string"
	TypeInteger ValueType = "integer"
	TypeNil     ValueType = "nil"
	TypeArray   ValueType = "array"
	TypeError   ValueType = "error"
)

type Value struct {
	Type    ValueType
	Bytes   []byte
	Integer int64
	Array   []Value
	Message string
}

type Truncation string

const (
	TruncationNone       Truncation = "none"
	TruncationElementCap Truncation = "element_cap"
	TruncationByteBudget Truncation = "byte_budget"
)

type replyBounds struct {
	maxElements int
	remaining   int
	truncation  Truncation
	exhausted   bool
}

func boundReply(raw any, maxElements, byteBudget int) (Value, Truncation, error) {
	b := &replyBounds{maxElements: maxElements, remaining: byteBudget, truncation: TruncationNone}
	v, err := b.value(raw)
	if err != nil {
		return Value{}, TruncationNone, err
	}
	return v, b.truncation, nil
}

func (b *replyBounds) cut(reason Truncation) {
	if b.truncation == TruncationNone {
		b.truncation = reason
	}
}

func (b *replyBounds) value(raw any) (Value, error) {
	switch v := raw.(type) {
	case nil:
		return Value{Type: TypeNil}, nil
	case int64:
		return Value{Type: TypeInteger, Integer: v}, nil
	case string:
		return b.text(v), nil
	case redis.Error:
		return Value{Type: TypeError, Message: v.Error()}, nil
	case []any:
		return b.array(v)
	default:
		return Value{}, fmt.Errorf("the reply holds a %T, which a RESP2 reply cannot", raw)
	}
}

func (b *replyBounds) text(s string) Value {
	if len(s) <= b.remaining {
		b.remaining -= len(s)
		return Value{Type: TypeString, Bytes: []byte(s)}
	}
	kept := []byte(s[:b.remaining])
	b.remaining = 0
	b.exhausted = true
	b.cut(TruncationByteBudget)
	return Value{Type: TypeString, Bytes: kept}
}

func (b *replyBounds) array(items []any) (Value, error) {
	n := min(len(items), b.maxElements)
	out := make([]Value, 0, n)
	for _, item := range items[:n] {
		v, err := b.value(item)
		if err != nil {
			return Value{}, err
		}
		out = append(out, v)
		if b.exhausted {
			return Value{Type: TypeArray, Array: out}, nil
		}
	}
	if len(items) > n {
		b.cut(TruncationElementCap)
	}
	return Value{Type: TypeArray, Array: out}, nil
}
