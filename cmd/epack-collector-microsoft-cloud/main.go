// epack-collector-microsoft-cloud collects Microsoft Cloud security posture.
package main

import (
	"errors"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/collector"
	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "microsoft-cloud",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects Microsoft Entra ID and Azure security posture metrics",
		Timeout:     30 * time.Minute,
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := collector.Config{
		TenantID:         getString(cfg, "tenant_id"),
		ClientID:         getString(cfg, "client_id"),
		AuthMode:         getString(cfg, "auth_mode"),
		SubscriptionIDs:  getStringSlice(cfg, "subscription_ids"),
		AzureEnvironment: getString(cfg, "azure_environment"),
		ClientSecret:     ctx.Secret("AZURE_CLIENT_SECRET"),
		OIDCRequestURL:   ctx.Secret("ACTIONS_ID_TOKEN_REQUEST_URL"),
		OIDCRequestToken: ctx.Secret("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		OnStatus:         ctx.Status,
		OnProgress:       ctx.Progress,
	}

	c, err := collector.New(config)
	if err != nil {
		var configErr componentsdk.ConfigError
		if errors.As(err, &configErr) {
			return err
		}
		return classifyError(err)
	}

	result, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return classifyError(err)
	}

	return ctx.Emit(result.Artifacts())
}

func classifyError(err error) error {
	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 400, 404:
			return componentsdk.NewConfigError("collecting posture: %v", err)
		case 401, 403:
			return componentsdk.NewAuthError("collecting posture: %v", err)
		case 429, 500, 502, 503, 504:
			return componentsdk.NewNetworkError("collecting posture: %v", err)
		}
	}

	var authErr microsoft.AuthError
	if errors.As(err, &authErr) {
		return componentsdk.NewAuthError("collecting posture: %v", err)
	}

	return componentsdk.NewNetworkError("collecting posture: %v", err)
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}

	raw, ok := cfg[key].([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
