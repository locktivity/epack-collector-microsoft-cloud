package collector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type credentialWindow struct {
	kind  string
	start time.Time
	end   time.Time
}

func (c *Collector) collectApps(ctx context.Context, diagnostics *Diagnostics) (*Apps, error) {
	servicePrincipals, spAvailable, err := c.servicePrincipals(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	applications, appAvailable, err := c.applications(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	if !spAvailable && !appAvailable {
		return nil, nil
	}

	out := &Apps{}
	if spAvailable {
		populateEnterpriseAppMetrics(out, servicePrincipals)
	}
	if appAvailable || spAvailable {
		populateCredentialMetrics(out, applications, servicePrincipals, c.clock.Now())
	}
	return out, nil
}

func (c *Collector) servicePrincipals(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.ServicePrincipal, bool, error) {
	servicePrincipals, err := c.graph.ServicePrincipals(ctx)
	if err == nil {
		return servicePrincipals, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		diagnostics.Warn("graph permission Application.Read.All not granted, enterprise apps skipped")
		diagnostics.MarkCapabilityUnavailable("enterprise_apps")
		return nil, false, nil
	}
	return nil, false, err
}

func (c *Collector) applications(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.Application, bool, error) {
	applications, err := c.graph.Applications(ctx)
	if err == nil {
		return applications, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		diagnostics.Warn("graph permission Application.Read.All not granted, application credentials skipped")
		diagnostics.MarkCapabilityUnavailable("application_credentials")
		return nil, false, nil
	}
	return nil, false, err
}

func populateEnterpriseAppMetrics(out *Apps, servicePrincipals []microsoft.ServicePrincipal) {
	enabled := 0
	assignmentRequired := 0
	ssoConfigured := 0
	for _, sp := range servicePrincipals {
		if !sp.EnabledEnterpriseApp() {
			continue
		}
		enabled++
		if sp.AppRoleAssignmentRequired != nil && *sp.AppRoleAssignmentRequired {
			assignmentRequired++
		}
		if hasFederatedSSO(sp.PreferredSingleSignOnMode) {
			ssoConfigured++
		}
	}
	out.EnabledEnterpriseAppsCount = enabled
	out.AssignmentRequiredPct = PercentInt(assignmentRequired, enabled)
	out.SSOCoveragePct = PercentInt(ssoConfigured, enabled)
}

func populateCredentialMetrics(out *Apps, applications []microsoft.Application, servicePrincipals []microsoft.ServicePrincipal, now time.Time) {
	credentials := credentialWindows(applications, servicePrincipals)
	expiringBefore := now.AddDate(0, 0, 30)
	activeCredentials := 0
	activePasswordCredentials := 0

	for _, credential := range credentials {
		if !credential.end.IsZero() && !credential.end.After(now) {
			out.CredentialsExpiredCount++
			continue
		}
		activeCredentials++
		if credential.kind == "password" {
			activePasswordCredentials++
		}
		if !credential.end.IsZero() && credential.end.After(now) && !credential.end.After(expiringBefore) {
			out.CredentialsExpiringCount++
		}
		if !credential.start.IsZero() && !credential.end.IsZero() && credential.end.Sub(credential.start) > 365*24*time.Hour {
			out.CredentialsOver365dCount++
		}
	}
	out.PasswordCredentialsPct = PercentInt(activePasswordCredentials, activeCredentials)
}

func credentialWindows(applications []microsoft.Application, servicePrincipals []microsoft.ServicePrincipal) []credentialWindow {
	var out []credentialWindow
	for _, app := range applications {
		out = append(out, passwordCredentialWindows(app.PasswordCredentials)...)
		out = append(out, keyCredentialWindows(app.KeyCredentials)...)
	}
	for _, sp := range servicePrincipals {
		out = append(out, passwordCredentialWindows(sp.PasswordCredentials)...)
		out = append(out, keyCredentialWindows(sp.KeyCredentials)...)
	}
	return out
}

func passwordCredentialWindows(credentials []microsoft.PasswordCredential) []credentialWindow {
	out := make([]credentialWindow, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, credentialWindow{
			kind:  "password",
			start: parseGraphTime(credential.StartDateTime),
			end:   parseGraphTime(credential.EndDateTime),
		})
	}
	return out
}

func keyCredentialWindows(credentials []microsoft.KeyCredential) []credentialWindow {
	out := make([]credentialWindow, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, credentialWindow{
			kind:  "key",
			start: parseGraphTime(credential.StartDateTime),
			end:   parseGraphTime(credential.EndDateTime),
		})
	}
	return out
}

func hasFederatedSSO(mode string) bool {
	switch strings.ToLower(mode) {
	case "saml", "oidc":
		return true
	default:
		return false
	}
}

func parseGraphTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
