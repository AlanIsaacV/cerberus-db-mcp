package authflow

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/rs/zerolog"
)

// stringOrBool is a boolean that may arrive as a JSON boolean or as the JSON
// string "true" or "false". Anything else — absent, null, 1, "TRUE" — is false,
// which is what makes "email_verified must be true, not merely present" a
// property of the decoder rather than of a check somebody has to remember.
type stringOrBool bool

func (b *stringOrBool) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	*b = stringOrBool(text == "true")
	return nil
}

// googleFailure carries the facts an operator needs to distinguish failures in
// calls to Google without carrying any of the values those calls authenticate.
// It is assembled in the credential files and rendered only here, on the side of
// the package that can write a log line.
type googleFailure struct {
	call        string
	stage       string
	status      int
	oauth       string
	description string
}

// googleOAuthRefusal is the safe part of a refusal body: it is sufficient for
// an operator to correlate an upstream refusal without preserving its request.
type googleOAuthRefusal struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (f *googleFailure) Error() string {
	return fmt.Sprintf("Google %s failed during %s", f.call, f.stage)
}

type flowFailure struct {
	stage string
}

func (f *flowFailure) Error() string {
	return fmt.Sprintf("authorization flow failed during %s", f.stage)
}

// googleFailureFields keeps the response independent from Google's wording:
// those facts help an operator diagnose an outbound call, but giving them to a
// client would disclose what an upstream service said about its request.
func googleFailureFields(event *zerolog.Event, err error) *zerolog.Event {
	var failure *googleFailure
	if !errors.As(err, &failure) {
		return event
	}
	event = event.
		Str("google_call", failure.call).
		Str("google_stage", failure.stage)
	if failure.status != 0 {
		event = event.Int("google_status", failure.status)
	}
	if failure.oauth != "" {
		event = event.Str("google_error", failure.oauth)
	}
	if failure.description != "" {
		event = event.Str("google_error_description", failure.description)
	}
	return event
}

func flowFailureFields(event *zerolog.Event, err error) *zerolog.Event {
	var failure *flowFailure
	if !errors.As(err, &failure) {
		return event
	}
	return event.Str("flow_stage", failure.stage)
}
