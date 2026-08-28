// Package httplog holds the HTTP layers that make responses written by handlers
// outside this repository observable without taking ownership of their wire
// behaviour.
package httplog

import (
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/refuse"
)

const (
	failureClassRecoveredPanic = "recovered_panic"
	authRefusalSDKHandler      = "sdk_handler"
)

// ResponseWriter records the final response status and bytes without changing
// how the wrapped writer handles headers or bodies. Unwrap is necessary because
// ResponseController follows that chain to find the original writer's flusher;
// embedding http.ResponseWriter is not enough to preserve streaming.
type ResponseWriter struct {
	http.ResponseWriter

	Status        int
	BytesWritten  int64
	HeaderWritten bool
	responseSent  bool
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		Status:         http.StatusOK,
	}
}

// Unwrap returns the original writer so ResponseController can reach optional
// capabilities such as flushing that http.ResponseWriter does not declare.
func (w *ResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// WriteHeader records final headers while preserving net/http's informational
// response handling: non-switching 1xx headers may precede the response that
// actually reaches the client.
func (w *ResponseWriter) WriteHeader(status int) {
	w.HeaderWritten = true
	if status >= http.StatusContinue && status < http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if !w.responseSent {
		w.Status = status
		w.responseSent = true
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records the implicit success header net/http sends before a body when no
// final header has been written, then preserves the wrapped writer's result.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	if !w.responseSent {
		w.Status = http.StatusOK
		w.responseSent = true
	}
	n, err := w.ResponseWriter.Write(p)
	w.BytesWritten += int64(n)
	return n, err
}

// WithStatusLine records one line for a dependency-owned handler after it has
// selected its response. It is deliberately not a general access log: this
// process's own refusals already carry a more useful line through refuse.
func WithStatusLine(next http.Handler, log zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorded := NewResponseWriter(w)
		next.ServeHTTP(recorded, r)

		var event *zerolog.Event
		switch recorded.Status / 100 {
		case 2, 3:
			event = log.Info()
		case 4, 5:
			event = log.Warn()
		default:
			event = log.Warn()
		}
		event = event.Int("status", recorded.Status)
		if recorded.Status == http.StatusForbidden {
			event = event.Str("auth_refusal", authRefusalSDKHandler)
		}
		if r.Method != "" {
			event = event.Str("method", r.Method)
		}
		if r.URL.Path != "" {
			event = event.Str("path", r.URL.Path)
		}
		if elapsed := time.Since(started); elapsed != 0 {
			event = event.Dur("elapsed_ms", elapsed)
		}
		event.Msg("handler response")
	})
}

// WithPanicRecovery makes an unexpected handler panic visible in the
// application stream and gives the client the ordinary refusal response when no
// response has started. It never records the recovered value: a panic may carry
// a credential, while the stack identifies where the failure occurred without
// exposing request data.
func WithPanicRecovery(next http.Handler, log zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded := NewResponseWriter(w)
		defer func() {
			panicValue := recover()
			if panicValue == nil {
				return
			}
			if panicValue == http.ErrAbortHandler {
				panic(panicValue)
			}

			params := refuse.Params{
				Level:        zerolog.ErrorLevel,
				Status:       recorded.Status,
				FailureClass: failureClassRecoveredPanic,
				Message:      "recovered handler panic",
				Fields: func(event *zerolog.Event) *zerolog.Event {
					return event.Bytes("stack", debug.Stack())
				},
			}
			if !recorded.responseSent {
				params.Status = http.StatusInternalServerError
				params.OAuth = false
				params.Body = http.StatusText(http.StatusInternalServerError)
				refuse.Write(recorded, r, log, params)
				return
			}

			refuse.Log(r, log, params)
			panic(http.ErrAbortHandler)
		}()

		next.ServeHTTP(recorded, r)
	})
}

// ServerErrorLog adapts net/http's standard-library diagnostics into the
// application stream at a real level. Passing zerolog.Logger directly would use
// NoLevel, bypass the configured threshold, and leave the event without a level.
type ServerErrorLog struct {
	log zerolog.Logger
}

// NewServerErrorLog builds the standard-library logger http.Server expects for
// ErrorLog, while keeping its output inside the application's levelled stream.
func NewServerErrorLog(logger zerolog.Logger) *log.Logger {
	return log.New(NewServerErrorLogWriter(logger), "", 0)
}

// NewServerErrorLogWriter exposes the adapter itself for callers that need to
// exercise net/http's diagnostic output without constructing an HTTP server.
func NewServerErrorLogWriter(logger zerolog.Logger) ServerErrorLog {
	return ServerErrorLog{log: logger}
}

// Write always reports full consumption because net/http's logger has no error
// path: its diagnostics must not be retried or sent elsewhere.
func (l ServerErrorLog) Write(p []byte) (int, error) {
	if len(p) != 0 {
		l.log.Error().Str("source", "net/http").Msg(strings.TrimSuffix(string(p), "\n"))
	}
	return len(p), nil
}

var _ io.Writer = ServerErrorLog{}
