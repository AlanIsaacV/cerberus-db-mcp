package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func baseEnvironment() []string {
	var out []string
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CERBERUS_") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func authEnvironment() []string {
	return []string{
		"CERBERUS_AUTH_GOOGLE_CLIENT_ID=1234567890-abcdefghijklmnop.apps.googleusercontent.com",
		"CERBERUS_AUTH_ALLOWED_EMAILS=one@example.test",
		"CERBERUS_AUTH_SEALING_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET=test-client-secret",
		"CERBERUS_AUTH_PUBLIC_BASE_URL=https://public.example.test/",
		"CERBERUS_AUTH_CLIENT_REDIRECT_URIS=https://client.example.test/callback",
	}
}

func redisEnvironment(address string) []string {
	return append(append(baseEnvironment(), authEnvironment()...),
		"CERBERUS_MCP_ADDRESS="+address,
		"CERBERUS_MCP_PATH=/mcp",
		"CERBERUS_MCP_SHUTDOWN_TIMEOUT=5s",
		"CERBERUS_REDIS_ALIASES=cache",
		"CERBERUS_REDIS_CACHE_HOST=127.0.0.1",
		"CERBERUS_REDIS_CACHE_PORT=1",
		"CERBERUS_REDIS_CACHE_USER=reader",
		"CERBERUS_REDIS_CACHE_PASSWORD=hunter2",
		"CERBERUS_REDIS_CACHE_DATABASES=0",
	)
}

func sqlEnvironment(address string) []string {
	return append(append(baseEnvironment(), authEnvironment()...),
		"CERBERUS_MCP_ADDRESS="+address,
		"CERBERUS_MCP_PATH=/mcp",
		"CERBERUS_MCP_SHUTDOWN_TIMEOUT=5s",
		"CERBERUS_DB_ALIASES=warehouse",
		"CERBERUS_DB_WAREHOUSE_ENGINE=postgresql",
		"CERBERUS_DB_WAREHOUSE_HOST=127.0.0.1",
		"CERBERUS_DB_WAREHOUSE_PORT=1",
		"CERBERUS_DB_WAREHOUSE_DATABASES=warehouse",
		"CERBERUS_DB_WAREHOUSE_USER=reader",
		"CERBERUS_DB_WAREHOUSE_PASSWORD=hunter2",
		"CERBERUS_DB_WAREHOUSE_TLS=disable",
		"PGSERVICE=",
		"PGSERVICEFILE=",
		"MSSQL_USE_EPA=",
	)
}

func without(environ []string, names ...string) []string {
	out := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		drop := false
		for _, n := range names {
			if name == n {
				drop = true
			}
		}
		if !drop {
			out = append(out, entry)
		}
	}
	return out
}

func build(t *testing.T, dir, name string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", binary, dir)
	command.Env = append(without(os.Environ(), "CGO_ENABLED"), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", dir, err, output)
	}
	return binary
}

func reservedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return address
}

type process struct {
	output *lockedBuffer
	exit   chan error
	cmd    *exec.Cmd
	done   bool
}

func start(t *testing.T, binary string, environ []string) *process {
	t.Helper()
	p := &process{output: &lockedBuffer{}, exit: make(chan error, 1), cmd: exec.Command(binary)}
	p.cmd.Env = environ
	p.cmd.Stdout = p.output
	p.cmd.Stderr = p.output
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	go func() { p.exit <- p.cmd.Wait() }()
	t.Cleanup(func() {
		if p.done {
			return
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exit:
		case <-time.After(30 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exit
		}
	})
	return p
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case err := <-p.exit:
		p.done = true
		if err != nil {
			t.Errorf("the binary exited on SIGTERM with %v\n%s", err, p.output.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the binary did not stop after SIGTERM")
	}
}

func (p *process) waitServing(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-p.exit:
			p.done = true
			t.Fatalf("the binary exited before serving: %v\n%s", err, p.output.String())
		default:
		}
		resp, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
				t.Fatalf("/healthz = %d %q, want 200 ok", resp.StatusCode, body)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the binary never served /healthz: %v\n%s", err, p.output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func unauthenticatedPost(t *testing.T, address string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+address+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)
}

func TestTheCompiledBinaryRefusesToStartWithoutRedisAliasesOrAuthentication(t *testing.T) {
	binary := build(t, ".", "cerberus-cache-mcp")
	for _, variable := range []string{
		"CERBERUS_REDIS_ALIASES",
		"CERBERUS_AUTH_GOOGLE_CLIENT_ID",
		"CERBERUS_AUTH_ALLOWED_EMAILS",
		"CERBERUS_AUTH_GOOGLE_CLIENT_SECRET",
		"CERBERUS_AUTH_PUBLIC_BASE_URL",
		"CERBERUS_AUTH_CLIENT_REDIRECT_URIS",
	} {
		t.Run(variable, func(t *testing.T) {
			command := exec.Command(binary)
			command.Env = without(redisEnvironment(reservedAddress(t)), variable)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
				t.Fatalf("the binary did not exit non-zero without %s: %v\n%s", variable, err, output)
			}
			if !bytes.Contains(output, []byte(variable)) {
				t.Errorf("the startup refusal does not name %s:\n%s", variable, output)
			}
			if bytes.Contains(output, []byte("serving MCP")) {
				t.Errorf("the binary served before refusing:\n%s", output)
			}
		})
	}
}

func TestTheCompiledBinaryRefusesAnUnusableLogLevel(t *testing.T) {
	binary := build(t, ".", "cerberus-cache-mcp")
	command := exec.Command(binary)
	command.Env = append(redisEnvironment(reservedAddress(t)), "CERBERUS_MCP_LOG_LEVEL=trace")
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
		t.Fatalf("the binary did not exit non-zero on an unusable log level: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("CERBERUS_MCP_LOG_LEVEL")) {
		t.Errorf("the startup refusal does not name CERBERUS_MCP_LOG_LEVEL:\n%s", output)
	}
}

func TestTheCompiledBinaryAppliesTheConfiguredLogLevelToEveryLine(t *testing.T) {
	binary := build(t, ".", "cerberus-cache-mcp")
	for _, tt := range []struct {
		level     string
		infoLines bool
	}{
		{"info", true},
		{"warn", false},
	} {
		t.Run(tt.level, func(t *testing.T) {
			address := reservedAddress(t)
			p := start(t, binary, append(redisEnvironment(address), "CERBERUS_MCP_LOG_LEVEL="+tt.level))
			p.waitServing(t, address)
			p.stop(t)

			logged := p.output.String()
			if got := strings.Contains(logged, `"level":"info"`); got != tt.infoLines {
				t.Errorf("at %s, info lines present = %v, want %v:\n%s", tt.level, got, tt.infoLines, logged)
			}
		})
	}
}

func TestTheCompiledBinaryAnswersHealthAndTheSameChallengeAsTheSQLBinary(t *testing.T) {
	redisBinary := build(t, ".", "cerberus-cache-mcp")
	sqlBinary := build(t, "../cerberus-db-mcp", "cerberus-db-mcp")

	redisAddress := reservedAddress(t)
	redisProcess := start(t, redisBinary, redisEnvironment(redisAddress))
	redisProcess.waitServing(t, redisAddress)
	sqlAddress := reservedAddress(t)
	sqlProcess := start(t, sqlBinary, sqlEnvironment(sqlAddress))
	sqlProcess.waitServing(t, sqlAddress)

	status, challenge, body := unauthenticatedPost(t, redisAddress)
	sqlStatus, sqlChallenge, sqlBody := unauthenticatedPost(t, sqlAddress)

	if status != http.StatusUnauthorized {
		t.Errorf("POST /mcp without a credential = %d, want %d", status, http.StatusUnauthorized)
	}
	if challenge == "" {
		t.Error("the refusal carries no WWW-Authenticate challenge")
	}
	if status != sqlStatus || challenge != sqlChallenge || body != sqlBody {
		t.Errorf("the refusal differs from the SQL binary's:\nredis %d %q %q\nsql   %d %q %q", status, challenge, body, sqlStatus, sqlChallenge, sqlBody)
	}

	redisProcess.stop(t)
	sqlProcess.stop(t)
}
