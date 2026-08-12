package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/db"
	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// decodeOneEvent parses a stream that should hold exactly one record.
func decodeOneEvent(t *testing.T, stream string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stream), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d records, want exactly 1:\n%s", len(lines), stream)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("the audit record is not a JSON object: %v\n%s", err, lines[0])
	}
	return event
}

// TestAuditEventCarriesEveryFieldItPromises asserts the record whole rather than
// field by field, because the value of this stream is that a consumer can rely
// on its shape: a field silently renamed is a downstream query that returns
// nothing, and a field silently dropped is a question the log can no longer
// answer.
func TestAuditEventCarriesEveryFieldItPromises(t *testing.T) {
	var buf bytes.Buffer
	NewAuditor(&buf).Record(AuditEvent{
		Tool:      ToolExecuteQuery,
		Identity:  "analyst@example.com",
		Subject:   "104427392015467281503",
		Alias:     "warehouse",
		Engine:    gate.PostgreSQL,
		Statement: "SELECT * FROM invoices WHERE total > 100 -- and a comment",
		Outcome:   OutcomeRefused,
		Verdict:   gate.NeedsApproval,
		Reason:    gate.ReasonUnknownFunction,
		RuleID:    "function:calcular_saldo",
		Pending:   []string{"function:calcular_saldo", "function:otra"},
		ErrorKind: db.KindNeedsApproval,
		Rows:      0,
		Truncated: false,
		Elapsed:   1500 * time.Microsecond,
	})

	event := decodeOneEvent(t, buf.String())

	// The timestamp is present but not comparable, so it is checked and removed.
	if _, ok := event["time"].(string); !ok {
		t.Errorf("the record carries no timestamp: %v", event)
	}
	delete(event, "time")

	want := map[string]any{
		"level":      "info",
		"stream":     "audit",
		"tool":       ToolExecuteQuery,
		"identity":   "analyst@example.com",
		"subject":    "104427392015467281503",
		"alias":      "warehouse",
		"engine":     "postgresql",
		"statement":  "SELECT * FROM invoices WHERE total > 100 -- and a comment",
		"outcome":    "refused",
		"verdict":    "needs-approval",
		"reason":     "unknown-function",
		"rule_id":    "function:calcular_saldo",
		"pending":    []any{"function:calcular_saldo", "function:otra"},
		"error_kind": "needs-approval",
		"rows":       float64(0),
		"truncated":  false,
		"elapsed_ms": 1.5,
		"message":    "tool call",
	}
	if !reflect.DeepEqual(event, want) {
		got, _ := json.Marshal(event)
		wantJSON, _ := json.Marshal(want)
		t.Errorf("the audit record =\n%s\nwant\n%s", got, wantJSON)
	}
}

// TestTheCallerFieldsArePresentOnAnEventThatNamesNobody is what the field
// comment on [AuditEvent.Identity] promises a consumer: both caller fields are
// written on every record, whether or not there was a caller to name, so a
// reader can tell "this server identified nobody" from "this record predates the
// field" without knowing which version wrote it.
func TestTheCallerFieldsArePresentOnAnEventThatNamesNobody(t *testing.T) {
	var buf bytes.Buffer
	NewAuditor(&buf).Record(AuditEvent{Tool: ToolListConnections, Outcome: OutcomeAllowed})
	event := decodeOneEvent(t, buf.String())
	for _, field := range []string{"identity", "subject"} {
		value, present := event[field]
		if !present {
			t.Fatalf("the record has no %s field: %v", field, event)
		}
		if value != "" {
			t.Errorf("%s = %v, want it empty on an event whose caller was not identified", field, value)
		}
	}
}

// TestTheStatementIsRecordedVerbatimAndInFull. A summarised statement cannot
// answer the question this stream is for, which is what this process sent
// somebody else's server.
func TestTheStatementIsRecordedVerbatimAndInFull(t *testing.T) {
	statement := "SELECT " + strings.Repeat("a, ", 400) + "b FROM t /* ünïcödé ✓ */ WHERE x = 'a \"quoted\" value'"
	var buf bytes.Buffer
	NewAuditor(&buf).Record(AuditEvent{Tool: ToolExecuteQuery, Statement: statement})
	if got := decodeOneEvent(t, buf.String())["statement"]; got != statement {
		t.Errorf("the recorded statement is not the one submitted:\ngot  %v\nwant %v", got, statement)
	}
}

// TestTheAuditStreamIsSeparateFromTheApplicationLog. They are separate so that
// the audit record's completeness does not depend on the application log's
// level, and so the two can have different retention answers.
func TestTheAuditStreamIsSeparateFromTheApplicationLog(t *testing.T) {
	var auditBuf, appBuf bytes.Buffer
	app := zerolog.New(&appBuf)
	NewAuditor(&auditBuf).Record(AuditEvent{Tool: ToolExecuteQuery, Statement: "SELECT 1", Outcome: OutcomeAllowed})
	app.Error().Msg("something the operator needs")

	if appBuf.Len() == 0 {
		t.Fatal("the application log received nothing, so this test proves nothing")
	}
	if strings.Contains(appBuf.String(), "SELECT 1") {
		t.Errorf("the audit event was written to the application log: %s", appBuf.String())
	}
	if strings.Contains(auditBuf.String(), "something the operator needs") {
		t.Errorf("the application log was written to the audit stream: %s", auditBuf.String())
	}
}

// splittingWriter passes p to w in PIPE_BUF-sized pieces, yielding between
// them.
//
// It is not a stand-in for the destination: the pieces go to a real pipe below
// and are read back out of the kernel. What it stands in for is the io.Writer
// contract, which is what [NewAuditor] accepts and which promises nothing about
// two goroutines calling Write at once. A buffered writer, a rotating log file
// or a tee splits and interleaves exactly like this.
//
// The alternative — writing straight to os.Stdout or an os.Pipe and hoping for
// a split — proves nothing: internal/poll holds a per-file write lock across
// the whole of (*os.File).Write, so those destinations do not interleave within
// one process whatever [Auditor] does, and such a test passes with the mutex
// deleted.
type splittingWriter struct{ w io.Writer }

func (s splittingWriter) Write(p []byte) (int, error) {
	const piece = 4096
	written := 0
	for len(p) > 0 {
		n, err := s.w.Write(p[:min(piece, len(p))])
		written += n
		if err != nil {
			return written, err
		}
		p = p[n:]
		runtime.Gosched()
	}
	return written, nil
}

// TestConcurrentRecordsArriveWhole is the interleaving guarantee: every record
// reaches the destination as one contiguous run of bytes, whatever else is
// recording at the same time.
//
// -race does not cover this and no amount of it would: bytes laid down by two
// correctly synchronised Write calls in the wrong order are not a data race,
// they are two audit lines that parse as neither. So the assertion is on the
// bytes — every line valid JSON, every statement present exactly once — read
// back through a real pipe.
func TestConcurrentRecordsArriveWhole(t *testing.T) {
	// A statement large enough to be split several times over. Not a contrived
	// size: the statement is the agent's own SQL, recorded verbatim and in full.
	const writers, perWriter, statementSize = 16, 8, 20000

	statementFor := func(writer, n int) string {
		marker := fmt.Sprintf("SELECT %d, %d, ", writer, n)
		return marker + strings.Repeat("x", statementSize-len(marker))
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	auditor := NewAuditor(splittingWriter{w})

	// The reader drains unconditionally and asserts nothing, because a pipe holds
	// 64KiB and these records are more than that: a reader that stopped early on a
	// bad line would deadlock every writer still blocked on the full pipe, and the
	// test would time out instead of reporting what it found.
	lines := make(chan []string, 1)
	scanErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		// One record is larger than bufio's default token limit is comfortable
		// with, and a record that overran it would fail this test for the scanner's
		// reason rather than the writer's.
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		var got []string
		for scanner.Scan() {
			got = append(got, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			scanErr <- err
			return
		}
		lines <- got
	}()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for writer := range writers {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			for n := range perWriter {
				auditor.Record(AuditEvent{
					Tool:      ToolExecuteQuery,
					Alias:     "warehouse",
					Engine:    gate.PostgreSQL,
					Statement: statementFor(writer, n),
					Outcome:   OutcomeAllowed,
				})
			}
		}(writer)
	}
	close(start)
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("close the pipe: %v", err)
	}

	var got []string
	select {
	case got = <-lines:
	case err := <-scanErr:
		t.Fatalf("read the audit stream: %v", err)
	}

	if len(got) != writers*perWriter {
		t.Errorf("got %d records for %d calls; a record that split in two is two records that parse as neither", len(got), writers*perWriter)
	}

	seen := make(map[string]int, writers*perWriter)
	for i, line := range got {
		var event struct {
			Statement string `json:"statement"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("record %d is not a JSON object (%v); the writes interleaved: %.120q…", i, err, line)
		}
		seen[event.Statement]++
	}
	for writer := range writers {
		for n := range perWriter {
			if count := seen[statementFor(writer, n)]; count != 1 {
				t.Errorf("the statement from writer %d call %d appears %d times, want exactly once", writer, n, count)
			}
		}
	}
}

func TestOpenAuditWriter(t *testing.T) {
	t.Run("stdout and stderr are named, not paths", func(t *testing.T) {
		for name, want := range map[string]*os.File{AuditStdout: os.Stdout, AuditStderr: os.Stderr} {
			w, closeFn, err := OpenAuditWriter(name)
			if err != nil {
				t.Fatalf("OpenAuditWriter(%q) = %v", name, err)
			}
			if w != want {
				t.Errorf("OpenAuditWriter(%q) = %v, want %v", name, w, want)
			}
			if err := closeFn(); err != nil {
				t.Errorf("closing %q = %v; neither standard stream is ours to close", name, err)
			}
		}
	})

	t.Run("a path is appended to, not truncated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(path, []byte("earlier\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w, closeFn, err := OpenAuditWriter(path)
		if err != nil {
			t.Fatalf("OpenAuditWriter(%q) = %v", path, err)
		}
		NewAuditor(w).Record(AuditEvent{Tool: ToolExecuteQuery, Statement: "SELECT 1"})
		if err := closeFn(); err != nil {
			t.Fatalf("close: %v", err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(content), "earlier\n") {
			t.Errorf("the existing content was truncated: %s", content)
		}
		if !strings.Contains(string(content), "SELECT 1") {
			t.Errorf("the new record was not appended: %s", content)
		}
	})

	t.Run("a destination that cannot be opened is a startup failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "no-such-directory", "audit.jsonl")
		if _, _, err := OpenAuditWriter(path); err == nil {
			t.Errorf("OpenAuditWriter(%q) succeeded, so a server would start with nowhere to record calls", path)
		}
	})
}
