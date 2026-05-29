package microsoft

import (
	"fmt"
	"net/url"
	"strings"
)

func resolveServiceURL(baseURL, route string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(route, "http://") || strings.HasPrefix(route, "https://") {
		parsed, err := url.Parse(route)
		if err != nil {
			return "", err
		}
		if !sameOrigin(base, parsed) {
			return "", fmt.Errorf("refusing cross-origin pagination URL")
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
