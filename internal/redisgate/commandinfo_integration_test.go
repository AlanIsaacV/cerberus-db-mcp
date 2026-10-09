//go:build integration

package redisgate

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const redisAddrVar = "CERBERUS_TEST_REDIS_ADDR"

var (
	refusedFlags      = []string{"write", "admin", "blocking"}
	refusedCategories = []string{"@write", "@admin", "@blocking", "@dangerous"}
)

type respConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *respConn) call(args ...string) (any, error) {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	if _, err := io.WriteString(c.conn, b.String()); err != nil {
		return nil, err
	}
	return c.read()
}

func (c *respConn) line() (string, error) {
	s, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	s, ok := strings.CutSuffix(s, "\r\n")
	if !ok || s == "" {
		return "", errors.New("malformed RESP line " + strconv.Quote(s))
	}
	return s, nil
}

func (c *respConn) read() (any, error) {
	s, err := c.line()
	if err != nil {
		return nil, err
	}
	switch s[0] {
	case '+':
		return s[1:], nil
	case '-':
		return nil, errors.New("redis replied with an error: " + s[1:])
	case ':':
		return strconv.ParseInt(s[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(s[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(s[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = c.read(); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, errors.New("unsupported RESP type in " + strconv.Quote(s))
	}
}

func dialRedis(t *testing.T) *respConn {
	t.Helper()
	addr := os.Getenv(redisAddrVar)
	if addr == "" {
		t.Skipf("%s is not set; set it to the host:port of a redis:7.4.2-alpine to check the allowlist against COMMAND INFO", redisAddrVar)
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("%s=%s is set but not reachable: %v", redisAddrVar, addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return &respConn{conn: conn, r: bufio.NewReader(conn)}
}

func stringItems(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func TestCommandInfoMarksEveryAllowlistedCommandReadOnly(t *testing.T) {
	c := dialRedis(t)

	reply, err := c.call("INFO", "server")
	if err != nil {
		t.Fatalf("INFO server against %s: %v", os.Getenv(redisAddrVar), err)
	}
	info, ok := reply.(string)
	if !ok {
		t.Fatalf("INFO server replied %T, want a bulk string", reply)
	}
	version := ""
	for line := range strings.SplitSeq(info, "\r\n") {
		if v, ok := strings.CutPrefix(line, "redis_version:"); ok {
			version = v
		}
	}
	t.Logf("%s answers as redis_version %s", os.Getenv(redisAddrVar), version)
	if !strings.HasPrefix(version, "7.4.") {
		t.Fatalf("the server reports redis_version %q; this check is about Redis 7.4.x", version)
	}

	checked := 0
	for _, cmd := range Allowlist() {
		name := strings.ToLower(cmd.Name)
		if cmd.Subcommand != "" {
			name += "|" + strings.ToLower(cmd.Subcommand)
		}
		t.Run(name, func(t *testing.T) {
			reply, err := c.call("COMMAND", "INFO", name)
			if err != nil {
				t.Fatalf("COMMAND INFO %s: %v", name, err)
			}
			entries, ok := reply.([]any)
			if !ok || len(entries) != 1 {
				t.Fatalf("COMMAND INFO %s replied %#v, want one entry", name, reply)
			}
			entry, ok := entries[0].([]any)
			if !ok || len(entry) < 7 {
				t.Fatalf("the server does not know %s: COMMAND INFO replied %#v", name, entries[0])
			}
			if got, _ := entry[0].(string); got != name {
				t.Fatalf("COMMAND INFO %s describes %q", name, got)
			}
			flags, ok := stringItems(entry[2])
			if !ok {
				t.Fatalf("COMMAND INFO %s flags are %#v", name, entry[2])
			}
			categories, ok := stringItems(entry[6])
			if !ok {
				t.Fatalf("COMMAND INFO %s ACL categories are %#v", name, entry[6])
			}
			t.Logf("%s flags %v categories %v", name, flags, categories)
			if !slices.Contains(flags, "readonly") {
				t.Errorf("%s is not flagged readonly: %v", name, flags)
			}
			for _, f := range refusedFlags {
				if slices.Contains(flags, f) {
					t.Errorf("%s is flagged %s: %v", name, f, flags)
				}
			}
			for _, cat := range refusedCategories {
				if slices.Contains(categories, cat) {
					t.Errorf("%s is in category %s: %v", name, cat, categories)
				}
			}
		})
		checked++
	}
	if want := len(transcribedAllowlist); checked != want {
		t.Fatalf("checked %d allowlist entries, want %d", checked, want)
	}
}
