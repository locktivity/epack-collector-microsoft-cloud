package microsoft

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// resolveServiceURL joins a route to the service's base URL. A next-page
// link must keep the base URL's scheme and host. The SDK's credential host
// list allows any of the collector's hosts, so this check also stops a
// downgrade to http and a link to another Microsoft service.
func resolveServiceURL(baseURL, route string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(route, "http://") || strings.HasPrefix(route, "https://") {
		parsed, err := url.Parse(route)
		if err != nil {
			return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("invalid pagination URL"))
		}
		if !sameOrigin(base, parsed) {
			return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("refusing cross-origin pagination URL"))
		}
		return parsed.String(), nil
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	return strings.TrimRight(baseURL, "/") + route, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// tooLarge is the error for a response page longer than maxResponseBytes,
// which the collector does not read.
func tooLarge(service, route string) error {
	return componentsdk.CodeError(componentsdk.CodeTooLarge, fmt.Errorf("%s response for %s is longer than %d bytes", service, SanitizeRoute(route), maxResponseBytes))
}

func invalidResponse(service, route, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s response for %s %s", service, SanitizeRoute(route), problem))
}
