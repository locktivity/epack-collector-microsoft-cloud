package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type credentialWindow struct {
	kind  string
	start time.Time
	end   time.Time
}

// collectApps returns the enterprise app metrics and the app credentials
// they are taken from, which the access posture reads too.
func (c *Collector) collectApps(ctx context.Context, diagnostics *Diagnostics) (*Apps, appCredentials) {
	servicePrincipals, servicePrincipalsMiss := c.servicePrincipals(ctx, diagnostics)
	applications, applicationsMiss := c.applications(ctx, diagnostics)
	creds := newAppCredentials(servicePrincipals, servicePrincipalsMiss, applications, applicationsMiss)
	if servicePrincipalsMiss != nil {
		c.gaps.leaveOut(entraPath, servicePrincipalsMiss, "/apps", "/posture/sso_coverage")
		return nil, creds
	}

	out := &Apps{}
	populateEnterpriseAppMetrics(out, servicePrincipals)
	if applicationsMiss == nil {
		populateCredentialMetrics(out, applications, servicePrincipals, c.clock.Now())
	}
	c.gaps.leaveOut(entraPath, applicationsMiss,
		"/apps/credentials_expiring_count", "/apps/credentials_expired_count",
		"/apps/credentials_over_365d_count", "/apps/password_credentials_pct")
	return out, creds
}

// appCredentials holds the tenant's Application service principals by object
// ID and its applications by appId, with why each list could not be read.
type appCredentials struct {
	servicePrincipals     map[string]microsoft.ServicePrincipal
	servicePrincipalsMiss *missing
	applications          map[string]microsoft.Application
	applicationsMiss      *missing
}

func newAppCredentials(servicePrincipals []microsoft.ServicePrincipal, servicePrincipalsMiss *missing, applications []microsoft.Application, applicationsMiss *missing) appCredentials {
	out := appCredentials{
		servicePrincipals:     map[string]microsoft.ServicePrincipal{},
		servicePrincipalsMiss: servicePrincipalsMiss,
		applications:          map[string]microsoft.Application{},
		applicationsMiss:      applicationsMiss,
	}
	for _, sp := range servicePrincipals {
		if sp.ID != "" {
			out.servicePrincipals[sp.ID] = sp
		}
	}
	for _, app := range applications {
		if app.AppID != "" {
			out.applications[app.AppID] = app
		}
	}
	return out
}

func (c *Collector) servicePrincipals(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.ServicePrincipal, *missing) {
	servicePrincipals, err := c.graph.ServicePrincipals(ctx)
	switch {
	case err == nil:
		return servicePrincipals, nil
	case permissionDenied(err):
		diagnostics.Warn("graph permission Application.Read.All not granted, enterprise apps skipped")
		diagnostics.MarkCapabilityUnavailable("enterprise_apps")
	default:
		diagnostics.warnNotCollected("Enterprise applications", err)
	}
	return nil, failed(err)
}

func (c *Collector) applications(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.Application, *missing) {
	applications, err := c.graph.Applications(ctx)
	switch {
	case err == nil:
		return applications, nil
	case permissionDenied(err):
		diagnostics.Warn("graph permission Application.Read.All not granted, application credentials skipped")
		diagnostics.MarkCapabilityUnavailable("application_credentials")
	default:
		diagnostics.warnNotCollected("Application credentials", err)
	}
	return nil, failed(err)
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
	out.ssoAppCount = ssoConfigured
}

func populateCredentialMetrics(out *Apps, applications []microsoft.Application, servicePrincipals []microsoft.ServicePrincipal, now time.Time) {
	credentials := credentialWindows(applications, servicePrincipals)
	expiringBefore := now.AddDate(0, 0, 30)
	activeCredentials := 0
	activePasswordCredentials := 0
	expiring := 0
	expired := 0
	over365d := 0

	for _, credential := range credentials {
		if !credential.end.IsZero() && !credential.end.After(now) {
			expired++
			continue
		}
		activeCredentials++
		if credential.kind == "password" {
			activePasswordCredentials++
		}
		if !credential.end.IsZero() && credential.end.After(now) && !credential.end.After(expiringBefore) {
			expiring++
		}
		if !credential.start.IsZero() && !credential.end.IsZero() && credential.end.Sub(credential.start) > 365*24*time.Hour {
			over365d++
		}
	}
	out.CredentialsExpiringCount = intPtr(expiring)
	out.CredentialsExpiredCount = intPtr(expired)
	out.CredentialsOver365dCount = intPtr(over365d)
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
