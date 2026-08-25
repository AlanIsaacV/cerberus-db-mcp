package authflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/auth"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/mcp"
)

// This file is acceptance criterion 4, and it is the one test in this package that
// stands up the transport: a credential is only worth issuing if the endpoint it
// was issued for accepts it, and nothing in internal/authflow or internal/auth can
// see that on its own. The middleware is the real one, built from the same
// configuration as the handlers that minted the credential, and the tool call goes
// through the mux internal/mcp mounts rather than through a handler this file
// assembled.
//
// It runs against no database. list_connections answers from the configured
// aliases and dials nothing, which is what makes "the caller got rows" observable
// without a container.

// tokenEndpointServer is a whole process's HTTP surface: the MCP endpoint behind
// the real authentication middleware, and this package's routes mounted beside it
// exactly as cmd/cerberus-db-mcp mounts them.
func tokenEndpointServer(t *testing.T, handlers *Handlers) http.Handler {
	t.Helper()
	for _, name := range []string{"PGSERVICE", "PGSERVICEFILE", "MSSQL_USE_EPA"} {
		t.Setenv(name, "")
	}
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	executor, err := db.New(g, &db.Config{
		Settings: db.Settings{
			RowCap: 100, QueryTimeout: 5 * time.Second, TimeoutGrace: time.Second,
			LockTimeout: time.Second, ConnectTimeout: time.Second, MaxConns: 1,
		},
		// A port with nothing behind it: list_connections never dials, and anything
		// that did would fail at the socket rather than reach somebody's database.
		Aliases: []db.AliasSpec{{
			Alias: "warehouse", Engine: gate.PostgreSQL, Host: "127.0.0.1", Port: 1,
			Database: "warehouse", User: "reader", Password: db.Secret("hunter2"), TLS: db.TLSDisable,
		}},
	})
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(executor.Close)

	middleware, err := auth.NewMiddleware(testAuthentication(), testPublicBaseURL, zerologTo(io.Discard))
	if err != nil {
		t.Fatalf("auth.NewMiddleware: %v", err)
	}
	routes := make([]mcp.UnauthenticatedRoute, 0, len(handlers.Routes()))
	for _, route := range handlers.Routes() {
		routes = append(routes, mcp.UnauthenticatedRoute{Pattern: route.Pattern, Handler: route.Handler})
	}
	server, err := mcp.New(mcp.Deps{
		Config:                mcp.Config{Address: "127.0.0.1:0", Path: testResourcePath, ShutdownTimeout: 5 * time.Second},
		Executor:              executor,
		Log:                   zerologTo(io.Discard),
		Audit:                 mcp.NewAuditor(io.Discard),
		Middleware:            middleware,
		UnauthenticatedRoutes: routes,
	})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return server.Handler()
}

// callTool posts one JSON-RPC tool call at the MCP endpoint with the given bearer
// value. The server is stateless, so a call needs no prior session.
func callTool(t *testing.T, handler http.Handler, credential, tool string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	request := httptest.NewRequest(http.MethodPost, testResourcePath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// toolResult is the JSON-RPC result, dug out of whichever of the two shapes the
// SDK's streamable transport answered with.
func toolResult(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	payload := response.Body.String()
	if strings.Contains(response.Header().Get("Content-Type"), "text/event-stream") {
		payload = ""
		for _, line := range strings.Split(response.Body.String(), "\n") {
			if data, found := strings.CutPrefix(line, "data: "); found {
				payload = data
			}
		}
		if payload == "" {
			t.Fatalf("the event stream carried no data frame: %q", response.Body)
		}
	}
	var envelope struct {
		Result map[string]any  `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		t.Fatalf("the tool response is not JSON-RPC: %v in %q", err, payload)
	}
	if len(envelope.Error) != 0 {
		t.Fatalf("the tool call failed at the protocol level: %s", envelope.Error)
	}
	return envelope.Result
}

// TestACredentialFromTheTokenEndpointReachesATool is acceptance criterion 4.
func TestACredentialFromTheTokenEndpointReachesATool(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	client := authorize(t, fake)
	handler := tokenEndpointServer(t, client.handlers)
	pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))

	response := callTool(t, handler, pair.AccessToken, mcp.ToolListConnections)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body)
	}
	result := toolResult(t, response)
	if failed, _ := result["isError"].(bool); failed {
		t.Fatalf("the tool call was refused: %v", result)
	}
	// The rows the caller actually got back. list_connections answers from the
	// configured aliases, so the alias this server was built with is what proves
	// the call reached the tool rather than a handler that returned an empty
	// result.
	if !strings.Contains(response.Body.String(), "warehouse") {
		t.Errorf("the tool result carries no rows: %s", response.Body)
	}
}

// TestACredentialFromTheTokenEndpointIsRefusedOnceItExpires is criterion 4's other
// half. The credential is real and came out of /token; what is wound back is the
// clock the flow minted it against, so the middleware — which runs on the real one
// — sees a credential whose hour is over.
func TestACredentialFromTheTokenEndpointIsRefusedOnceItExpires(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	client := authorize(t, fake)
	handler := tokenEndpointServer(t, client.handlers)
	minted := time.Now().Add(-2 * time.Hour)
	client.handlers.flow.now = func() time.Time { return minted }
	pair := decodePair(t, post(t, client.handlers, codeGrant(client.code)))

	response := callTool(t, handler, pair.AccessToken, mcp.ToolListConnections)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d for a credential an hour past its expiry: %s",
			response.Code, http.StatusUnauthorized, response.Body)
	}
	// Criterion 6's other side, in the process that actually serves both: the
	// challenge names the document, and the document is mounted here.
	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="`+testPublicBaseURL+auth.ProtectedResourceMetadataPath+`"`) {
		t.Fatalf("WWW-Authenticate = %q, want it to point at the protected-resource document", challenge)
	}
	pointer := testPublicBaseURL + auth.ProtectedResourceMetadataPath
	document := httptest.NewRecorder()
	handler.ServeHTTP(document, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(pointer, testPublicBaseURL), nil))
	if document.Code != http.StatusOK {
		t.Errorf("the document the challenge points at answers %d; a client that follows the pointer finds nothing", document.Code)
	}
}

// TestTheDirectGoogleBearerPathIsUnchanged is the constraint the operator's
// current configuration depends on: this objective added an authorization server
// in front of Google and must not have taken the resource-server path away.
//
// A Google-shaped bearer token is one this process cannot validate locally, so it
// goes to Tokeninfo — which is unreachable from this test — and the refusal that
// produces is the proof that the value was routed to Google rather than unsealed
// here. What matters is that it is not refused as one of this server's own
// credentials.
func TestTheDirectGoogleBearerPathIsUnchanged(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)
	handler := tokenEndpointServer(t, handlers)

	response := callTool(t, handler, "ya29.a-google-shaped-access-token", mcp.ToolListConnections)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(response.Body.String(), "cdb") {
		t.Errorf("a Google-shaped token was answered as one of this server's own credentials: %s", response.Body)
	}
}

// TestTheDiscoveryDocumentsAreServedUnauthenticated is the mounting half of
// criterion 5: the documents and the token endpoint answer without a credential,
// while the MCP endpoint beside them still refuses one.
func TestTheDiscoveryDocumentsAreServedUnauthenticated(t *testing.T) {
	fake := newFakeGoogle(t, consentingIdentity(), testRefreshToken)
	handlers := testHandlers(t, fake, io.Discard)
	handler := tokenEndpointServer(t, handlers)

	for _, tt := range []struct {
		path string
		want int
	}{
		{AuthorizationServerMetadataPath, http.StatusOK},
		{auth.ProtectedResourceMetadataPath, http.StatusOK},
		{auth.ProtectedResourceMetadataPath + testResourcePath, http.StatusOK},
		// The token endpoint answers a GET with 405 rather than 401, which is what
		// says it is mounted outside the authentication seam.
		{TokenPath, http.StatusMethodNotAllowed},
	} {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if recorder.Code == http.StatusNotFound {
				t.Fatalf("nothing is mounted at %s", tt.path)
			}
			if recorder.Code != tt.want {
				t.Errorf("status = %d, want %d: %s", recorder.Code, tt.want, recorder.Body)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q; this route is not behind the authentication seam", got)
			}
		})
	}

	t.Run("and the MCP endpoint is still wrapped", func(t *testing.T) {
		response := callTool(t, handler, "", mcp.ToolListConnections)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	})
}
