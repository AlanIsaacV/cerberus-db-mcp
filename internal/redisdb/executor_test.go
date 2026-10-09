package redisdb

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/redisgate"
)

type silentListener struct {
	listener net.Listener
	accepted atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
	done     sync.WaitGroup
}

func startSilentListener(t *testing.T) *silentListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &silentListener{listener: l}
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
			s.done.Add(1)
			go func() {
				defer s.done.Done()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.done.Wait()
	})
	return s
}

func (s *silentListener) environment(t *testing.T, commandTimeout string) map[string]string {
	t.Helper()
	host, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	return map[string]string{
		"CERBERUS_REDIS_ALIASES":           "local",
		"CERBERUS_REDIS_LOCAL_HOST":        host,
		"CERBERUS_REDIS_LOCAL_PORT":        port,
		"CERBERUS_REDIS_LOCAL_USER":        "ro",
		"CERBERUS_REDIS_LOCAL_PASSWORD":    knownPassword,
		"CERBERUS_REDIS_LOCAL_DATABASES":   "2",
		"CERBERUS_REDIS_COMMAND_TIMEOUT":   commandTimeout,
		"CERBERUS_REDIS_CONNECT_TIMEOUT":   "5s",
		"CERBERUS_REDIS_LOCAL_TLS":         "disable",
		"CERBERUS_REDIS_REPLY_BYTE_BUDGET": "1024",
		"CERBERUS_REDIS_MAX_ELEMENTS":      "100",
		"CERBERUS_REDIS_MAX_CONNS":         "2",
		"CERBERUS_REDIS_MAX_ARGV_BYTES":    "4096",
		"CERBERUS_REDIS_MAX_COUNT":         "100",
		"CERBERUS_REDIS_MAX_ARGS":          "64",
	}
}

func newExecutor(t *testing.T, environ map[string]string) (*Executor, *redisgate.Gate) {
	t.Helper()
	setEnvironment(t, environ)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() = %v", err)
	}
	g, err := redisgate.New(cfg.Settings.GateLimits())
	if err != nil {
		t.Fatalf("redisgate.New() = %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, g
}

func TestExecuteRefusesBeforeAnyConnection(t *testing.T) {
	listener := startSilentListener(t)
	e, g := newExecutor(t, listener.environment(t, "300ms"))

	for _, argv := range [][]string{
		{"SET", "k", "v"},
		{"KEYS", "*"},
		{"SELECT", "1"},
		{"HGETALL", "k"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			want := g.Validate(argv)
			if want.Verdict != redisgate.Deny {
				t.Fatalf("the gate allows %v; this test needs a denied command", argv)
			}
			result, err := e.Execute(context.Background(), "local.2", argv)
			if err == nil {
				t.Fatalf("Execute() = %+v, want a refusal", result)
			}
			var failure *Error
			if !errors.As(err, &failure) {
				t.Fatalf("Execute() error is %T, want *Error", err)
			}
			if failure.Kind != KindRefused || !errors.Is(err, ErrRefused) {
				t.Fatalf("kind = %s (%v), want refused", failure.Kind, err)
			}
			if failure.Decision == nil || *failure.Decision != want {
				t.Fatalf("decision = %+v, want the gate's own %+v", failure.Decision, want)
			}
		})
	}

	_, err := e.Execute(context.Background(), "nowhere.2", []string{"GET", "k"})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != KindUnknownAlias || !errors.Is(err, ErrUnknownAlias) {
		t.Fatalf("Execute() on an unknown alias = %v, want unknown_alias", err)
	}
	_, err = e.Execute(context.Background(), "local", []string{"GET", "k"})
	if !errors.As(err, &failure) || failure.Kind != KindUnknownAlias {
		t.Fatalf("Execute() on the undivided alias = %v, want unknown_alias", err)
	}

	if n := listener.accepted.Load(); n != 0 {
		t.Fatalf("the listener accepted %d connections; a refusal must open none", n)
	}

	_, err = e.Execute(context.Background(), "local.2", []string{"GET", "k"})
	if err == nil {
		t.Fatal("an allowed GET against a silent listener succeeded")
	}
	if n := listener.accepted.Load(); n != 1 {
		t.Fatalf("an allowed command reached the listener %d times, want 1; the zero above proves nothing unless the alias reaches it", n)
	}
}

func TestExecuteStopsAtTheDeadlineWithoutRetrying(t *testing.T) {
	const timeout = 500 * time.Millisecond
	listener := startSilentListener(t)
	e, _ := newExecutor(t, listener.environment(t, timeout.String()))

	started := time.Now()
	result, err := e.Execute(context.Background(), "local.2", []string{"GET", "k"})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatalf("Execute() = %+v, want a deadline error", result)
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != KindDeadline || !errors.Is(err, ErrDeadline) {
		t.Fatalf("Execute() = %v, want kind deadline", err)
	}
	if elapsed > timeout+time.Second {
		t.Fatalf("Execute() returned after %s, want within %s", elapsed, timeout+time.Second)
	}
	if elapsed < timeout {
		t.Fatalf("Execute() returned after %s, before its %s deadline", elapsed, timeout)
	}
	if strings.Contains(err.Error(), knownPassword) {
		t.Fatalf("the error quotes the password: %v", err)
	}

	settle := time.NewTimer(timeout)
	<-settle.C
	if n := listener.accepted.Load(); n != 1 {
		t.Fatalf("the listener accepted %d connections, want exactly 1", n)
	}
}

func TestClientOptionsPerTLSMode(t *testing.T) {
	settings := Settings{
		CommandTimeout:  9 * time.Second,
		ConnectTimeout:  4 * time.Second,
		MaxConns:        3,
		ReplyByteBudget: 100,
		MaxElements:     10,
		MaxCount:        10,
		MaxArgs:         10,
		MaxArgvBytes:    100,
	}
	for _, mode := range tlsModes() {
		t.Run(string(mode), func(t *testing.T) {
			spec := AliasSpec{
				Alias:    "cache.7",
				Host:     "redis.internal.example",
				Port:     6380,
				Database: 7,
				User:     "svc_reader",
				Password: Secret(knownPassword),
				TLS:      mode,
			}
			opt := clientOptions(spec, settings)
			if opt.Addr != "redis.internal.example:6380" {
				t.Errorf("Addr = %q", opt.Addr)
			}
			if opt.Username != "svc_reader" || opt.Password != knownPassword {
				t.Errorf("credentials are not the alias's own")
			}
			if opt.DB != 7 {
				t.Errorf("DB = %d, want 7", opt.DB)
			}
			if opt.Protocol != 2 {
				t.Errorf("Protocol = %d, want 2", opt.Protocol)
			}
			if !opt.DisableIdentity {
				t.Error("DisableIdentity is false")
			}
			if opt.MaxRetries != -1 {
				t.Errorf("MaxRetries = %d, want -1", opt.MaxRetries)
			}
			if !opt.ContextTimeoutEnabled {
				t.Error("ContextTimeoutEnabled is false")
			}
			if opt.PoolSize != 3 {
				t.Errorf("PoolSize = %d, want 3", opt.PoolSize)
			}
			if opt.DialTimeout != 4*time.Second {
				t.Errorf("DialTimeout = %s, want 4s", opt.DialTimeout)
			}
			if opt.ReadTimeout < settings.CommandTimeout || opt.WriteTimeout < settings.CommandTimeout {
				t.Errorf("read and write timeouts %s and %s are shorter than the %s deadline", opt.ReadTimeout, opt.WriteTimeout, settings.CommandTimeout)
			}
			switch mode {
			case TLSDisable:
				if opt.TLSConfig != nil {
					t.Errorf("TLSConfig = %+v, want nil", opt.TLSConfig)
				}
			case TLSRequire:
				if opt.TLSConfig == nil {
					t.Fatal("TLSConfig is nil")
				}
				if opt.TLSConfig.ServerName != "redis.internal.example" {
					t.Errorf("ServerName = %q, want the host", opt.TLSConfig.ServerName)
				}
				if opt.TLSConfig.InsecureSkipVerify {
					t.Error("require skips verification")
				}
			case TLSRequireInsecure:
				if opt.TLSConfig == nil {
					t.Fatal("TLSConfig is nil")
				}
				if !opt.TLSConfig.InsecureSkipVerify {
					t.Error("require-insecure verifies the certificate")
				}
			}
		})
	}
}

func TestNewRefusesNilGateAndStrayVariables(t *testing.T) {
	setEnvironment(t, minimalEnvironment())
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() = %v", err)
	}
	if _, err := New(nil, cfg); !errors.Is(err, ErrNoGate) {
		t.Fatalf("New(nil) = %v, want ErrNoGate", err)
	}

	g, err := redisgate.New(cfg.Settings.GateLimits())
	if err != nil {
		t.Fatalf("redisgate.New() = %v", err)
	}
	e, err := New(g, cfg)
	if err != nil {
		t.Fatalf("New() with only recognised variables = %v", err)
	}
	_ = e.Close()

	for _, stray := range []string{
		"CERBERUS_REDIS_CACHE_DATABASE",
		"CERBERUS_REDIS_CACHE_ENGINE",
		"CERBERUS_REDIS_OTHER_HOST",
		"CERBERUS_REDIS_QUERY_TIMEOUT",
	} {
		t.Run(stray, func(t *testing.T) {
			const value = "stray-value-not-in-any-error"
			t.Setenv(stray, value)
			e, err := New(g, cfg)
			if err == nil {
				_ = e.Close()
				t.Fatalf("New() accepted %s", stray)
			}
			if !errors.Is(err, ErrUnsupportedVariable) {
				t.Fatalf("New() = %v, want ErrUnsupportedVariable", err)
			}
			if !strings.Contains(err.Error(), stray) {
				t.Errorf("the error does not name %s: %v", stray, err)
			}
			if strings.Contains(err.Error(), value) {
				t.Errorf("the error quotes the value: %v", err)
			}
		})
	}
}
