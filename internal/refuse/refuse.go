package refuse

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

type Params struct {
	Status       int
	OAuth        bool
	Body         string
	Challenge    string
	FailureClass string
	AuthRefusal  string
	Message      string
	Fields       func(*zerolog.Event) *zerolog.Event
}

// Log records a refusal whose response bytes may be written by net/http itself,
// so it still leaves this repository's application log line. Building a second
// zerolog event at that site would duplicate the shape this package exists to
// keep in one place.
func Log(r *http.Request, log zerolog.Logger, p Params) {
	event := log.Warn().
		Str("failure_class", p.FailureClass).
		Int("status", p.Status).
		Str("method", r.Method).
		Str("path", r.URL.Path)
	if p.AuthRefusal != "" {
		event = event.Str("auth_refusal", p.AuthRefusal)
	}
	if p.Fields != nil {
		event = p.Fields(event)
	}
	event.Msg(p.Message)
}

func Write(w http.ResponseWriter, r *http.Request, log zerolog.Logger, p Params) {
	Log(r, log, p)

	if p.Challenge != "" {
		w.Header().Set("WWW-Authenticate", p.Challenge)
	}
	if !p.OAuth {
		http.Error(w, p.Body, p.Status)
		return
	}
	body, err := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: p.Body})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	if err == nil {
		_, _ = w.Write(body)
	}
}
