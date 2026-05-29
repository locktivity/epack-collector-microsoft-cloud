package microsoft

import (
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
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

func RedactError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(Redact(err.Error(), secrets...))
}

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
