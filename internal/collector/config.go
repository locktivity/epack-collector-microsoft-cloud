package collector

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

type StatusFunc func(message string)
type ProgressFunc func(current, total int64, message string)

type Config struct {
	TenantID         string
	ClientID         string
	AuthMode         string
	SubscriptionIDs  []string
	AzureEnvironment string

	ClientSecret       string
	OIDCRequestURL     string
	OIDCRequestToken   string
	FederatedTokenFile string

	TokenEndpointBase string
	GraphBaseURL      string
	ARMBaseURL        string
	HTTPClient        *http.Client
	GraphClient       GraphAPI
	ARMClient         ARMAPI

	Recorder *componentsdk.Recorder

	OnStatus   StatusFunc
	OnProgress ProgressFunc
	Clock      Clock
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (c Config) Validate() error {
	if c.TenantID == "" {
		return componentsdk.NewConfigError("tenant_id is required")
	}
	tenant := strings.ToLower(c.TenantID)
	if tenant == "common" || tenant == "organizations" {
		return componentsdk.NewConfigError("tenant_id must be a concrete tenant ID, not %q", c.TenantID)
	}
	if !uuidPattern.MatchString(c.TenantID) {
		return componentsdk.NewConfigError("tenant_id must be a GUID")
	}
	if c.ClientID == "" {
		return componentsdk.NewConfigError("client_id is required")
	}
	if !uuidPattern.MatchString(c.ClientID) {
		return componentsdk.NewConfigError("client_id must be a GUID")
	}
	switch c.AuthMode {
	case "oidc", "client_secret":
	default:
		if c.AuthMode == "" {
			return componentsdk.NewConfigError("auth_mode is required")
		}
		return componentsdk.NewConfigError("auth_mode must be oidc or client_secret")
	}
	if len(c.SubscriptionIDs) == 0 {
		return componentsdk.NewConfigError("subscription_ids is required")
	}
	for _, subscriptionID := range c.SubscriptionIDs {
		if !uuidPattern.MatchString(subscriptionID) {
			return componentsdk.NewConfigError("subscription_ids must contain only GUIDs")
		}
	}
	return nil
}

// CredentialHosts lists the hosts the collector sends credentials to: the
// token endpoint, Microsoft Graph, Azure Resource Manager, and in oidc mode
// the host GitHub Actions serves the run's identity token from.
func (c Config) CredentialHosts() []string {
	bases := []string{
		orDefault(c.TokenEndpointBase, microsoft.DefaultTokenEndpointBase),
		orDefault(c.GraphBaseURL, microsoft.DefaultGraphBaseURL),
		orDefault(c.ARMBaseURL, microsoft.DefaultARMBaseURL),
	}
	if c.AuthMode == "oidc" && c.OIDCRequestURL != "" {
		bases = append(bases, c.OIDCRequestURL)
	}
	hosts := make([]string, 0, len(bases))
	for _, base := range bases {
		if parsed, err := url.Parse(base); err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return hosts
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (c Config) tokenSource(scope string) (*microsoft.TokenSource, error) {
	return microsoft.NewTokenSource(microsoft.Credentials{
		TenantID:           c.TenantID,
		ClientID:           c.ClientID,
		AuthMode:           c.AuthMode,
		ClientSecret:       c.ClientSecret,
		OIDCRequestURL:     c.OIDCRequestURL,
		OIDCRequestToken:   c.OIDCRequestToken,
		FederatedTokenFile: c.FederatedTokenFile,
		Scope:              scope,
		TokenEndpointBase:  c.TokenEndpointBase,
		HTTPClient:         c.HTTPClient,
	})
}

func (c Config) graphClient(tokenSource microsoft.AccessTokenSource) GraphAPI {
	opts := []microsoft.GraphOption{}
	if c.GraphBaseURL != "" {
		opts = append(opts, microsoft.WithGraphBaseURL(c.GraphBaseURL))
	}
	if c.HTTPClient != nil {
		opts = append(opts, microsoft.WithGraphHTTPClient(c.HTTPClient))
	}
	return microsoft.NewGraphClient(tokenSource, opts...)
}

func (c Config) armClient(tokenSource microsoft.AccessTokenSource) ARMAPI {
	opts := []microsoft.ARMOption{}
	if c.ARMBaseURL != "" {
		opts = append(opts, microsoft.WithARMBaseURL(c.ARMBaseURL))
	}
	if c.HTTPClient != nil {
		opts = append(opts, microsoft.WithARMHTTPClient(c.HTTPClient))
	}
	return microsoft.NewARMClient(tokenSource, opts...)
}
