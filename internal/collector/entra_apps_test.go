package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func TestEnterpriseApps(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	if artifact.Apps == nil {
		t.Fatal("expected app metrics")
	}
	if artifact.Apps.EnabledEnterpriseAppsCount != 2 {
		t.Fatalf("expected 2 enabled enterprise apps, got %d", artifact.Apps.EnabledEnterpriseAppsCount)
	}
	if artifact.Apps.AssignmentRequiredPct == nil || *artifact.Apps.AssignmentRequiredPct != 50 {
		t.Fatalf("unexpected assignment-required pct: %#v", artifact.Apps.AssignmentRequiredPct)
	}
	if artifact.Posture.SSOCoverage == nil || *artifact.Posture.SSOCoverage != 100 {
		t.Fatalf("unexpected SSO coverage: %#v", artifact.Posture.SSOCoverage)
	}

	graph := fakeGraphClient()
	graph.servicePrincipalsErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/servicePrincipals"}
	cfg := testConfig()
	cfg.GraphClient = graph
	artifact = collectTestArtifact(t, cfg)
	if artifact.Posture.SSOCoverage != nil {
		t.Fatalf("expected null SSO coverage without service principals, got %#v", artifact.Posture.SSOCoverage)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "enterprise_apps") {
		t.Fatalf("expected enterprise_apps unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}

func TestAppCredentialHygiene(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	apps := artifact.Apps
	if apps.CredentialsExpiringCount != 2 {
		t.Fatalf("expected 2 expiring credentials, got %d", apps.CredentialsExpiringCount)
	}
	if apps.CredentialsExpiredCount != 2 {
		t.Fatalf("expected 2 expired credentials, got %d", apps.CredentialsExpiredCount)
	}
	if apps.CredentialsOver365dCount != 3 {
		t.Fatalf("expected 3 long-lived credentials, got %d", apps.CredentialsOver365dCount)
	}
	if apps.PasswordCredentialsPct == nil || *apps.PasswordCredentialsPct != 67 {
		t.Fatalf("unexpected password credential pct: %#v", apps.PasswordCredentialsPct)
	}
}
