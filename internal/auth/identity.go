// Package auth admits a request to this process only when it carries a Google
// OAuth access token that Google itself vouches for, held by an identity an
// operator wrote into this deployment's allowlist.
//
// It is the whole of this process's authentication, and it is deliberately the
// only place in the repository that reads a credential a client presented.
// internal/mcp knows nothing about tokens: it takes a
// func(http.Handler) http.Handler and applies it to the MCP endpoint, so every
// decision about how a caller proves who they are is made here, in files
// guards_test.go holds to three absolute claims — nothing here imports an MCP or
// an OAuth library, nothing here names an endpoint other than Google's over
// HTTPS, and no code path hands the raw token to a logger.
//
// Two refusals, two statuses, and the difference is not cosmetic. A request
// whose token Google will not vouch for is 401: the caller can change the
// answer by presenting a different token. A request whose token is good but
// whose identity this deployment does not admit is 403: nothing the caller
// presents will change the answer, and an operator has to add them. Folding the
// second into the first would make an operator's allowlist mistake look exactly
// like a client's token mistake in the one log that could have told them apart.
//
// What this package does not do: issue, refresh, proxy or store a token; publish
// any OAuth metadata; or hold any state that outlives the process. There is no
// OAuth client secret anywhere in this process — checking somebody else's token
// needs only the public client ID.
package auth

import "context"

// Identity is the caller a request was admitted as.
//
// Both fields are recorded in the audit stream, and they are two fields rather
// than one because they answer different questions. The email is who a person
// reading the log recognises and what the allowlist is written in terms of; the
// subject is what stays the same when Google's account holder changes their
// address, and is the only value here that is guaranteed stable and unique for
// this OAuth client. Neither is a credential: an identity may be logged in full.
type Identity struct {
	// Subject is Google's `sub` claim for this token: opaque, stable for the
	// lifetime of the account, and scoped to the OAuth client that the token was
	// issued to. Two deployments with different client IDs see different subjects
	// for the same person, which is why the allowlist cannot be written in terms
	// of it.
	Subject string
	// Email is Google's `email` claim, verified. An [Identity] only exists for an
	// address whose `email_verified` was true, so nothing downstream has to
	// re-ask that question.
	Email string
}

// identityKey is the context key the middleware stores an [Identity] under. It
// is an unexported empty struct type, so nothing outside this package can
// collide with it or forge a value under it — a request that arrives with an
// identity on its context got it from this package.
type identityKey struct{}

// WithIdentity returns a copy of ctx carrying id.
//
// It is exported for two callers: the middleware, which uses it on the request
// it passes down, and a test that needs to drive a handler as a known identity
// without standing up a token validator.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the identity the middleware admitted this request as.
//
// The boolean is the whole point of this signature and callers are expected to
// use it. A missing identity and an identity with empty fields are the same
// value in Go and completely different facts here: the first means the context
// path from the middleware to this handler is broken, and the second cannot
// happen, because nothing in this package builds an [Identity] without a subject
// and a verified email. A caller that ignored the boolean would write an empty
// identity into the audit stream, where it reads as an anonymous call that this
// server has no way of serving — an unauthenticated request never reaches a
// handler at all.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}
