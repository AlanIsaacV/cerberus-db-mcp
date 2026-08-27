// reachability checks that a public hostname actually reaches every HTTP route
// this server publishes.
//
// Run from the repository root:
//
//	go run ./tools/reachability https://cerberus-db-mcp.alanv.me
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	requestTimeout = 10 * time.Second

	protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
	// A bad edge response must not let a deploy check consume unbounded memory
	// before it can name the route that needs attention.
	maxResponseBody = 1 << 20
)

// probe says what an unauthenticated request proves about one route. Keeping the
// assertions here makes a new published route a deliberate addition to the
// deploy check, rather than a route that happens to be protected by the same
// ingress rule today and silently escapes the next path-limited configuration.
type probe struct {
	method string
	path   string
	want   string
	check  func(*http.Response, []byte) error
}

func main() {
	mcpPath := flag.String("mcp-path", "/mcp", "published MCP path")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-mcp-path /mcp] BASE_URL\n", os.Args[0])
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	base, err := parseBaseURL(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "base URL: %v\n", err)
		os.Exit(2)
	}
	path, err := parseMCPPath(*mcpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "MCP path: %v\n", err)
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: requestTimeout,
		// A redirect can conceal a missing origin route, especially for /authorize.
		// Keep the response so its status is a finding instead of following it to a
		// third party and reporting that party's answer as this host's health.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	probes := []probe{
		{method: http.MethodGet, path: "/healthz", want: "200", check: expectStatus(http.StatusOK)},
		{method: http.MethodGet, path: "/.well-known/oauth-authorization-server", want: "200 with parseable JSON", check: expectJSON(http.StatusOK)},
		{method: http.MethodGet, path: protectedResourceMetadataPath, want: "200 with parseable JSON", check: expectJSON(http.StatusOK)},
		{method: http.MethodGet, path: protectedResourceMetadataPath + path, want: "200 with parseable JSON", check: expectJSON(http.StatusOK)},
		{method: http.MethodGet, path: "/authorize", want: "400 without query parameters", check: expectStatus(http.StatusBadRequest)},
		{method: http.MethodGet, path: "/authorize/callback", want: "400 without query parameters", check: expectStatus(http.StatusBadRequest)},
		{method: http.MethodPost, path: "/token", want: "400 with a JSON error member", check: expectJSONError(http.StatusBadRequest)},
		{method: http.MethodPost, path: path, want: "401 with WWW-Authenticate naming resource_metadata", check: expectChallenge(http.StatusUnauthorized)},
	}

	failed := false
	for _, probe := range probes {
		if !run(client, base, probe) {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func parseBaseURL(raw string) (*url.URL, error) {
	base, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, errors.New("must use http or https")
	}
	if base.Host == "" {
		return nil, errors.New("must include a host")
	}
	if base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("must not include a query or fragment")
	}
	return base, nil
}

func parseMCPPath(raw string) (string, error) {
	if !strings.HasPrefix(raw, "/") {
		return "", errors.New("must start with /")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("must not include a query or fragment")
	}
	return parsed.Path, nil
}

func run(client *http.Client, base *url.URL, probe probe) bool {
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + probe.path
	target.RawPath = ""

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, probe.method, target.String(), nil)
	if err != nil {
		fmt.Printf("%s %s: FAIL — expected %s; could not build request: %v\n", probe.method, probe.path, probe.want, err)
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("%s %s: FAIL — expected %s; request failed: %v\n", probe.method, probe.path, probe.want, err)
		return false
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody))
	if err != nil {
		fmt.Printf("%s %s: FAIL — expected %s; could not read response: %v\n", probe.method, probe.path, probe.want, err)
		return false
	}
	if response.StatusCode == http.StatusNotFound {
		fmt.Printf("%s %s: FAIL — expected %s; got 404: %s\n", probe.method, probe.path, probe.want, diagnoseNotFound(response, body))
		return false
	}
	if err := probe.check(response, body); err != nil {
		fmt.Printf("%s %s: FAIL — expected %s; got %s: %v\n", probe.method, probe.path, probe.want, response.Status, err)
		return false
	}
	fmt.Printf("%s %s: PASS — %s\n", probe.method, probe.path, response.Status)
	return true
}

func expectStatus(want int) func(*http.Response, []byte) error {
	return func(response *http.Response, _ []byte) error {
		if response.StatusCode != want {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		return nil
	}
}

func expectJSON(want int) func(*http.Response, []byte) error {
	return func(response *http.Response, body []byte) error {
		if response.StatusCode != want {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		if !json.Valid(body) {
			return errors.New("body is not parseable JSON")
		}
		return nil
	}
}

func expectJSONError(want int) func(*http.Response, []byte) error {
	return func(response *http.Response, body []byte) error {
		if response.StatusCode != want {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(body, &document); err != nil {
			return fmt.Errorf("body is not parseable JSON: %w", err)
		}
		if _, ok := document["error"]; !ok {
			return errors.New("JSON body has no error member")
		}
		return nil
	}
}

func expectChallenge(want int) func(*http.Response, []byte) error {
	return func(response *http.Response, _ []byte) error {
		if response.StatusCode != want {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		if !strings.Contains(strings.ToLower(response.Header.Get("WWW-Authenticate")), "resource_metadata") {
			return fmt.Errorf("WWW-Authenticate = %q", response.Header.Get("WWW-Authenticate"))
		}
		return nil
	}
}

func diagnoseNotFound(response *http.Response, body []byte) string {
	contentType, hasContentType := response.Header["Content-Type"]
	nosniff, hasNosniff := response.Header["X-Content-Type-Options"]
	// These three fields are the distinction the operator cannot get from status
	// alone: net/http's NotFound writes all of them, while Cloudflare's catch-all
	// has none. Requiring the complete signature avoids blaming either side when
	// an intermediary has altered part of the response.
	origin := len(contentType) == 1 && contentType[0] == "text/plain; charset=utf-8" &&
		len(nosniff) == 1 && nosniff[0] == "nosniff" && string(body) == "404 page not found\n"
	if origin {
		return "origin 404: the process does not serve this path; fix this repository"
	}
	edge := !hasContentType && !hasNosniff && len(body) == 0
	if edge {
		return "edge 404: the tunnel ingress does not route this path to the origin; fix the cloudflared configuration"
	}
	return fmt.Sprintf("404 signals are ambiguous; content-type=%q (present=%t), x-content-type-options=%q (present=%t), body=%q", contentType, hasContentType, nosniff, hasNosniff, body)
}
