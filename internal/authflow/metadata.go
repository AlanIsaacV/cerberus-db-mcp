package authflow

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse"
)

// This file is on the writer half of this package: it holds no credential and
// reaches none. Everything it serves is public by construction — three documents
// whose entire purpose is to be fetched by a client that has not authenticated
// and cannot — which is why they are built once at startup and handed out as
// bytes, and why they are assembled here rather than in exchange.go or token.go.
//
// Every URL in them is built by concatenation from the validated public base URL.
// No absolute URL is written as a literal anywhere here, and that is enforced
// rather than habitual: internal/auth's TestEveryEndpointNamedInTheSourceIsOneOfGooglesOverHTTPS
// fails on any string in this package containing "://" that is not one of the
// three Google endpoints this process talks to.

// errNoResourcePath reports a Handlers built without the path the MCP endpoint is
// mounted at. It is a refusal and not a default for the reason every other
// configuration failure in this repository is: /mcp is internal/mcp's default and
// this package would be guessing at it, and a protected-resource document naming
// the wrong resource sends a client to authorize for something that is not there.
var errNoResourcePath = errors.New("authflow: no MCP resource path was supplied for the discovery documents")

// documents is the three discovery documents, rendered once.
//
// They depend on nothing but configuration, so rebuilding them per request would
// be work done on an unauthenticated endpoint at the request of anybody who can
// reach the listener.
type documents struct {
	authorizationServer []byte
	resource            *oauthex.ProtectedResourceMetadata
	log                 zerolog.Logger
	// suffixedResourcePath is the protected-resource document's second location:
	// the well-known path with the resource's own path appended, which is what RFC
	// 9728 section 3.1 has a client construct when the resource is not at the
	// origin root.
	suffixedResourcePath string
}

func newDocuments(publicBaseURL, resourcePath string, log zerolog.Logger) (documents, error) {
	if !strings.HasPrefix(resourcePath, "/") {
		return documents{}, errNoResourcePath
	}
	rendered, err := json.Marshal(authorizationServerMetadata(publicBaseURL))
	if err != nil {
		return documents{}, err
	}
	return documents{
		authorizationServer: rendered,
		log:                 log,
		resource: &oauthex.ProtectedResourceMetadata{
			Resource:             publicBaseURL + resourcePath,
			AuthorizationServers: []string{publicBaseURL},
			// Only the header. internal/auth reads exactly one Authorization header
			// and nothing else — not a form field, not a query parameter — so
			// advertising either of RFC 6750's other two methods would describe a
			// server that refuses what it invited.
			BearerMethodsSupported: []string{"header"},
			ResourceName:           resourceName,
		},
		suffixedResourcePath: auth.ProtectedResourceMetadataPath + resourcePath,
	}, nil
}

// resourceName is what a consent screen or a client's connection list shows.
const resourceName = "cerberus-db-mcp"

// authorizationServerDocument is RFC 8414's metadata, with the members this
// server can honestly claim and no others.
//
// It is a type of this package rather than the SDK's oauthex.AuthServerMeta, and
// the reason is one field: that struct declares jwks_uri without omitempty,
// because RFC 8414 lists it as required, so a document built from it always
// carries `"jwks_uri":""`. This server has no JWK set to publish — its credentials
// are sealed opaque values and not signed JWTs, and nothing but this process can
// or should open one — and an empty string there is an invitation for a client to
// fetch a document at the origin root. The field set below is otherwise that
// struct's, member for member and JSON name for JSON name.
type authorizationServerDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// offlineAccessScope is the whole reason this tree of work exists.
//
// Google issues a refresh token only for an authorization request carrying
// access_type=offline, and no MCP client sends that. Claude's clients do ask for
// offline_access — but only when the authorization server they discovered
// advertises it here, which Google's own metadata does not. Advertising it is what
// makes a client ask this server for a renewable session; this server then makes
// the offline request to Google itself. Removing this string leaves every endpoint
// below working and puts every client back in a browser once an hour.
const offlineAccessScope = "offline_access"

func authorizationServerMetadata(publicBaseURL string) authorizationServerDocument {
	return authorizationServerDocument{
		Issuer:                publicBaseURL,
		AuthorizationEndpoint: publicBaseURL + AuthorizationPath,
		TokenEndpoint:         publicBaseURL + TokenPath,
		// The three Google is asked for, plus the one that makes a client ask for a
		// session it can renew. What a client sends back as `scope` is not read by
		// [Handlers.authorize] at all: this server always asks Google for the same
		// three, because they are what Tokeninfo needs to answer who the caller is.
		ScopesSupported:        []string{"openid", "email", "profile", offlineAccessScope},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{grantAuthorizationCode, grantRefreshToken},
		// Every client of this server is public. There is no client registry keyed
		// by identifier here and no secret is issued to anybody: the registry is the
		// exact-match CERBERUS_AUTH_CLIENT_REDIRECT_URIS list, and what authenticates
		// a caller at the token endpoint is the PKCE verifier, which is the whole of
		// what OAuth 2.1 asks of a public client.
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{challengeMethod},
	}
}

// resourceHandler serves the protected-resource document.
//
// It is the SDK's own handler over this deployment's values. Using it rather than
// writing a fourth JSON responder means the document a client fetches is shaped by
// the same code the SDK's clients expect to have produced it, including the CORS
// headers a browser-based client needs before it will read anything here at all.
func (d documents) resourceHandler() http.Handler {
	return sdkauth.ProtectedResourceMetadataHandler(d.resource)
}

// authorizationServerHandler serves the authorization-server document.
//
// The SDK ships no handler for this one, so this is the same behaviour written
// out: any origin, GET and OPTIONS only, JSON. The CORS headers match
// [documents.resourceHandler]'s deliberately — a client that can read one document
// and not the other has discovered half an authorization server, which fails later
// and further away than a 404 would.
func (d documents) authorizationServerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			refuse.Write(w, r, d.log, refuse.Params{
				Status:       http.StatusMethodNotAllowed,
				Body:         "method not allowed",
				FailureClass: "method_not_allowed",
				Message:      "the metadata endpoint refused a non-GET request",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(d.authorizationServer)
	})
}
