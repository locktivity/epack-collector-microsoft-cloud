package microsoft

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}`)
var azureResourceIDPattern = regexp.MustCompile(`(?i)/subscriptions/[^"'\s<>{}]+`)

func Redact(text string, secrets ...string) string {
	redacted := text
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, "[REDACTED]")
	}
	redacted = jwtPattern.ReplaceAllString(redacted, "[REDACTED_JWT]")
	redacted = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`).ReplaceAllString(redacted, "Bearer [REDACTED]")
	return redacted
}

// RedactError returns err with secrets removed from its message. The result
// still unwraps to err, so the error's status and code stay classifiable.
func RedactError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return &redactedError{message: Redact(err.Error(), secrets...), err: err}
}

type redactedError struct {
	message string
	err     error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.err }

// RequestError is a call that got no usable response: the connection
// failed, the body could not be read, or the HTTP client refused the
// request. Its message names the sanitized route and the cause, never the
// full URL, whose query can carry tokens.
type RequestError struct {
	Service string
	Route   string
	Err     error
}

func (e *RequestError) Error() string {
	cause := e.Err
	var urlErr *url.Error
	if errors.As(cause, &urlErr) && urlErr.Err != nil {
		cause = urlErr.Err
	}
	if e.Route == "" {
		return fmt.Sprintf("%s request failed: %s", e.Service, SanitizeErrorText(cause.Error()))
	}
	return fmt.Sprintf("%s request %s failed: %s", e.Service, SanitizeRoute(e.Route), SanitizeErrorText(cause.Error()))
}

func (e *RequestError) Unwrap() error { return e.Err }

func SanitizeRoute(route string) string {
	if route == "" {
		return ""
	}
	parsed, err := url.Parse(route)
	if err != nil {
		return SanitizeErrorText(route)
	}
	path := parsed.Path
	if path == "" {
		path = route
	}
	safe := sanitizePath(path)
	if parsed.RawQuery == "" {
		return safe
	}
	return safe + "?" + sanitizedQueryKeys(parsed.RawQuery)
}

// TemplateRoute is the route template for the SDK's per-request rows. It
// replaces the subscription ID, resource group name, and resource names in an
// ARM path with placeholders, then applies the SDK's default for IDs such as
// the tenant in a token path.
func TemplateRoute(path string) string {
	segments := strings.Split(path, "/")
	for i := 0; i < len(segments); i++ {
		switch {
		case strings.EqualFold(segments[i], "subscriptions") && i+1 < len(segments):
			i++
			segments[i] = "{id}"
		case strings.EqualFold(segments[i], "resourceGroups") && i+1 < len(segments):
			i++
			segments[i] = "{name}"
		case strings.EqualFold(segments[i], "providers"):
			i++
			for i+2 < len(segments) && !strings.EqualFold(segments[i+1], "providers") {
				segments[i+2] = "{name}"
				i += 2
			}
		}
	}
	return componentsdk.TemplateRoute(strings.Join(segments, "/"))
}

func SanitizeErrorText(text string) string {
	text = Redact(text)
	return azureResourceIDPattern.ReplaceAllStringFunc(text, sanitizePath)
}

func sanitizePath(path string) string {
	if path == "" {
		return path
	}
	segments := strings.Split(path, "/")
	for i := 0; i < len(segments); i++ {
		switch strings.ToLower(segments[i]) {
		case "subscriptions":
			if i+1 < len(segments) {
				segments[i+1] = "[subscription_id]"
			}
		case "resourcegroups":
			if i+1 < len(segments) {
				segments[i+1] = "[resource_group]"
			}
		case "providers":
			i = sanitizeProviderSegments(segments, i+1)
		}
	}
	return strings.Join(segments, "/")
}

func sanitizeProviderSegments(segments []string, start int) int {
	if start >= len(segments) {
		return start
	}
	i := start + 1
	for i+1 < len(segments) {
		segments[i+1] = "[" + strings.ToLower(segments[i]) + "]"
		i += 2
	}
	return i
}

func sanitizedQueryKeys(rawQuery string) string {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[query]"
	}
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "&")
}
