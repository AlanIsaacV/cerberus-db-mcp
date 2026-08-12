package auth

import (
	"context"
	"testing"
)

// TestAHandlerCanTellAnAbsentIdentityFromAnEmptyOne is why [IdentityFrom] returns
// a boolean.
//
// The two facts are indistinguishable in the value alone, and they are completely
// different: a zero Identity with ok true would be a bug in this package, and a
// zero Identity with ok false means the context path from the middleware to the
// handler is broken — which is the failure the audit stream cannot report on,
// because what it would record is an anonymous call that this server has no way of
// serving.
func TestAHandlerCanTellAnAbsentIdentityFromAnEmptyOne(t *testing.T) {
	if id, ok := IdentityFrom(context.Background()); ok {
		t.Errorf("IdentityFrom(a context nothing put an identity on) = (%+v, true), want ok false", id)
	}

	empty := WithIdentity(context.Background(), Identity{})
	id, ok := IdentityFrom(empty)
	if !ok {
		t.Error("IdentityFrom = ok false for a context an empty identity was deliberately put on")
	}
	if id != (Identity{}) {
		t.Errorf("IdentityFrom = %+v, want the empty identity that was stored", id)
	}
}

func TestAnIdentitySurvivesTheContextItWasPutOn(t *testing.T) {
	want := Identity{Subject: "108134201943512340987", Email: "one@example.test"}
	// Wrapped in the two things every server puts between a middleware and a
	// handler: a value of somebody else's and a cancellation.
	ctx := WithIdentity(context.Background(), want)
	ctx = context.WithValue(ctx, struct{ other int }{}, "unrelated")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	got, ok := IdentityFrom(ctx)
	if !ok {
		t.Fatal("IdentityFrom = ok false through a wrapped context")
	}
	if got != want {
		t.Errorf("IdentityFrom = %+v, want %+v", got, want)
	}
}

// TestNothingOutsideThisPackageCanForgeAnIdentityOnAContext pins the key's type.
// A string key, or an exported one, would let any package — including one an agent
// can influence the input to — put an identity on a context that this middleware
// never admitted.
func TestNothingOutsideThisPackageCanForgeAnIdentityOnAContext(t *testing.T) {
	// The nearest thing an outside package could construct: its own empty struct
	// type with the same name, and a string with the obvious spelling.
	type identityKey struct{}
	forged := context.WithValue(context.Background(), identityKey{}, Identity{Email: "attacker@example.test"})
	if id, ok := IdentityFrom(forged); ok {
		t.Errorf("IdentityFrom read %+v from a value stored under another package's key of the same shape", id)
	}
	type namedKey string
	stringKeyed := context.WithValue(context.Background(), namedKey("identity"), Identity{Email: "attacker@example.test"})
	if id, ok := IdentityFrom(stringKeyed); ok {
		t.Errorf("IdentityFrom read %+v from a string-keyed context value", id)
	}
}
