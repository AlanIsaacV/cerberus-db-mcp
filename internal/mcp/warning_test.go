package mcp

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTheNonLoopbackWarningSaysOnlyWhatIsTrueOfThisServer is here because the
// line it asserts on is read exactly once, by an operator who has just exposed
// this listener on purpose and wants to know what they have done.
//
// It said, unconditionally, that this process performs no authentication of its
// own. That is true of a Server built with no middleware and false of one built
// with one, and the false reading is the one an operator would have met in
// production — with .env.example, the other operator-facing surface, saying the
// opposite. A warning nothing asserts on goes stale again, which is what this is
// for; the two texts and the two states are the whole test.
func TestTheNonLoopbackWarningSaysOnlyWhatIsTrueOfThisServer(t *testing.T) {
	const exposed = "192.0.2.10:8080"
	const unauthenticated = "this process performs no authentication of its own"
	const authenticated = "authenticated by the configured middleware"

	for _, tt := range []struct {
		name       string
		middleware func(http.Handler) http.Handler
		want       string
		mustNotSay string
	}{
		{
			name:       "a server with no middleware warns that whatever reaches the address can read every database",
			want:       unauthenticated,
			mustNotSay: authenticated,
		},
		{
			name:       "a server with a middleware warns about the reach of the listener and not about an absence of authentication",
			middleware: func(next http.Handler) http.Handler { return next },
			want:       authenticated,
			mustNotSay: unauthenticated,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			appLog := &bytes.Buffer{}
			srv, err := New(Deps{
				Config:     Config{Address: exposed, Path: "/mcp", ShutdownTimeout: time.Second},
				Executor:   unreachableExecutor(t),
				Log:        NewLogger(appLog),
				Audit:      NewAuditor(&bytes.Buffer{}),
				Middleware: tt.middleware,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			// The method rather than Run: what is under test is what the line says, and
			// reaching it through Run would mean a test that binds a public interface.
			srv.warnIfReachableBeyondThisHost(exposed)

			logged := appLog.String()
			if !strings.Contains(logged, tt.want) {
				t.Errorf("the warning does not say %q: %s", tt.want, logged)
			}
			if strings.Contains(logged, tt.mustNotSay) {
				t.Errorf("the warning says %q, which is not true of this server: %s", tt.mustNotSay, logged)
			}
			// The address is what makes the line actionable: an operator reading it has
			// to be able to tell which listener it is about.
			if !strings.Contains(logged, exposed) {
				t.Errorf("the warning does not name the address it is about: %s", logged)
			}
			if !strings.Contains(logged, `"level":"warn"`) {
				t.Errorf("the exposure is not logged at warn level: %s", logged)
			}
		})
	}

	t.Run("a loopback listener says nothing at all", func(t *testing.T) {
		appLog := &bytes.Buffer{}
		srv, err := New(Deps{
			Config:   Config{Address: "127.0.0.1:0", Path: "/mcp", ShutdownTimeout: time.Second},
			Executor: unreachableExecutor(t),
			Log:      NewLogger(appLog),
			Audit:    NewAuditor(&bytes.Buffer{}),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		srv.warnIfReachableBeyondThisHost("127.0.0.1:41234")
		if logged := appLog.String(); logged != "" {
			t.Errorf("a loopback listener warned about its own reach: %s", logged)
		}
	})
}
