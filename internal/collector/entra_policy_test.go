package collector

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestCaPolicies(t *testing.T) {
	graph := fakeGraphClient()
	graph.policies = []microsoft.ConditionalAccessPolicy{
		mfaAllUsersPolicy("enabled"),
		{ID: "disabled", State: "disabled"},
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy == nil || artifact.Policy.PolicyCount == nil || *artifact.Policy.PolicyCount != 1 {
		t.Fatalf("unexpected policy_count: %#v", artifact.Policy)
	}
}

func TestCaPoliciesMissingPermission(t *testing.T) {
	graph := fakeGraphClient()
	graph.policiesErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/identity/conditionalAccess/policies"}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy == nil || artifact.Policy.MFARequired != nil {
		t.Fatalf("expected null CA metrics, got %#v", artifact.Policy)
	}
	if artifact.Policy.MFARequiredCoveragePct == nil || *artifact.Policy.MFARequiredCoveragePct != 0 {
		t.Fatalf("expected security-defaults coverage fallback, got %#v", artifact.Policy)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "conditional_access") {
		t.Fatalf("expected conditional_access unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}

func TestCaPoliciesPremiumLicenseFailure(t *testing.T) {
	graph := fakeGraphClient()
	graph.securityDefaults = &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true}
	graph.policiesErr = &microsoft.APIError{
		StatusCode: http.StatusForbidden,
		Route:      "/identity/conditionalAccess/policies",
		Code:       "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
		Message:    "The tenant does not have a Premium license.",
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy == nil || artifact.Policy.MFARequired != nil {
		t.Fatalf("expected null CA metrics, got %#v", artifact.Policy)
	}
	if artifact.Policy.MFARequiredCoveragePct == nil || *artifact.Policy.MFARequiredCoveragePct != 100 {
		t.Fatalf("expected security-defaults coverage fallback, got %#v", artifact.Policy)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "conditional_access") {
		t.Fatalf("expected conditional_access unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}

func TestSecurityDefaults(t *testing.T) {
	graph := fakeGraphClient()
	graph.securityDefaults = &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.SecurityDefaults == nil || !artifact.SecurityDefaults.Enabled {
		t.Fatalf("expected enabled security defaults, got %#v", artifact.SecurityDefaults)
	}
}

func TestSecurityDefaultsMissingPermission(t *testing.T) {
	graph := fakeGraphClient()
	graph.securityDefErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/policies/identitySecurityDefaultsEnforcementPolicy"}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.SecurityDefaults != nil {
		t.Fatalf("expected security defaults unset, got %#v", artifact.SecurityDefaults)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "security_defaults") {
		t.Fatalf("expected security_defaults unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}

func TestMfaRequired(t *testing.T) {
	enabled := true
	graph := fakeGraphClient()
	graph.users = []microsoft.User{
		{ID: "u1", AccountEnabled: &enabled, UserType: "Member"},
	}
	graph.policies = []microsoft.ConditionalAccessPolicy{
		{
			ID:    "group-only",
			State: "enabled",
			Conditions: microsoft.ConditionalAccessConditionSet{
				Users: &microsoft.ConditionalAccessUsers{IncludeGroups: []string{"group-1"}},
			},
			GrantControls: &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"mfa"}},
		},
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy == nil || artifact.Policy.MFARequired == nil || *artifact.Policy.MFARequired {
		t.Fatalf("expected mfa_required false for group-only policy, got %#v", artifact.Policy)
	}

	graph.policies = append(graph.policies, mfaAllUsersPolicy("all-users"))
	artifact = collectTestArtifact(t, cfg)
	if artifact.Policy.MFARequired == nil || !*artifact.Policy.MFARequired {
		t.Fatalf("expected mfa_required true, got %#v", artifact.Policy.MFARequired)
	}
}

func TestMfaRequiredCoverage(t *testing.T) {
	graph := fakeGraphClient()
	graph.policies = []microsoft.ConditionalAccessPolicy{
		{
			ID:    "all-except-u2",
			State: "enabled",
			Conditions: microsoft.ConditionalAccessConditionSet{
				Users:        &microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}, ExcludeUsers: []string{"u2"}},
				Applications: &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"All"}},
			},
			GrantControls: &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"mfa"}},
		},
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy.MFARequiredCoveragePct == nil || *artifact.Policy.MFARequiredCoveragePct != 50 {
		t.Fatalf("expected 50 percent coverage, got %#v", artifact.Policy.MFARequiredCoveragePct)
	}

	graph.policiesErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/identity/conditionalAccess/policies"}
	graph.securityDefaults = &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true}
	artifact = collectTestArtifact(t, cfg)
	if artifact.Policy.MFARequiredCoveragePct == nil || *artifact.Policy.MFARequiredCoveragePct != 100 {
		t.Fatalf("expected 100 percent security-defaults fallback, got %#v", artifact.Policy.MFARequiredCoveragePct)
	}
}

func TestCaFlags(t *testing.T) {
	graph := fakeGraphClient()
	graph.policies = []microsoft.ConditionalAccessPolicy{
		mfaAdminPortalPolicy("admin"),
		mfaAllCloudAppsPolicy("all-cloud-apps"),
		compliantDeviceAdminPolicy("device"),
		legacyAuthBlockPolicy("legacy"),
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy.AdminPortalsMFARequired == nil || !*artifact.Policy.AdminPortalsMFARequired {
		t.Fatalf("expected admin portal MFA, got %#v", artifact.Policy.AdminPortalsMFARequired)
	}
	if artifact.Policy.AllCloudAppsMFARequired == nil || !*artifact.Policy.AllCloudAppsMFARequired {
		t.Fatalf("expected all-cloud-app MFA, got %#v", artifact.Policy.AllCloudAppsMFARequired)
	}
	if artifact.Policy.CompliantDeviceRequired == nil || !*artifact.Policy.CompliantDeviceRequired {
		t.Fatalf("expected compliant device required, got %#v", artifact.Policy.CompliantDeviceRequired)
	}
	if artifact.Policy.LegacyAuthBlocked == nil || !*artifact.Policy.LegacyAuthBlocked {
		t.Fatalf("expected legacy auth blocked, got %#v", artifact.Policy.LegacyAuthBlocked)
	}
}

func TestPolicyCount(t *testing.T) {
	graph := fakeGraphClient()
	graph.policies = []microsoft.ConditionalAccessPolicy{
		{ID: "one", State: "enabled"},
		{ID: "two", State: "enabled"},
		{ID: "report-only", State: "enabledForReportingButNotEnforced"},
		{ID: "disabled", State: "disabled"},
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy.PolicyCount == nil || *artifact.Policy.PolicyCount != 2 {
		t.Fatalf("expected 2 enabled policies, got %#v", artifact.Policy.PolicyCount)
	}
}

func TestNormalizedIdpPolicy(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	idp := artifact.ToIDPPosture()
	if idp == nil || idp.Policy == nil {
		t.Fatalf("expected normalized policy, got %#v", idp)
	}
	if idp.Policy.MFARequired == nil || !*idp.Policy.MFARequired {
		t.Fatalf("expected normalized mfa_required true, got %#v", idp.Policy)
	}
	if idp.Policy.MFARequiredCoveragePct == nil || *idp.Policy.MFARequiredCoveragePct != 100 {
		t.Fatalf("expected normalized coverage 100, got %#v", idp.Policy)
	}
	if idp.Policy.LegacyAuthBlocked == nil || *idp.Policy.LegacyAuthBlocked {
		t.Fatalf("expected normalized legacy_auth_blocked false, got %#v", idp.Policy)
	}

	artifact.Posture.MFACoverage = nil
	if idp := artifact.ToIDPPosture(); idp == nil || idp.Policy == nil {
		t.Fatal("expected policy-only normalized artifact")
	}
}

func TestSliceB1Golden(t *testing.T) {
	graph := fakeGraphClient()
	graph.policies = []microsoft.ConditionalAccessPolicy{
		mfaAdminPortalPolicy("admin"),
		mfaAllCloudAppsPolicy("all-cloud-apps"),
		compliantDeviceAdminPolicy("device"),
		legacyAuthBlockPolicy("legacy"),
	}
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	cfg.GraphClient = graph
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	assertGoldenJSON(t, "../../testdata/golden/slice_b1/entra.json", result.Entra)
	assertGoldenJSON(t, "../../testdata/golden/slice_b1/idp-posture.json", result.EntraIDPPosture)
}

func TestSliceB2Golden(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	assertGoldenJSON(t, "../../testdata/golden/slice_b2/entra.json", result.Entra)
	assertGoldenJSON(t, "../../testdata/golden/slice_b2/idp-posture.json", result.EntraIDPPosture)
}

var goldenTime = time.Date(2026, 5, 26, 14, 12, 9, 0, time.UTC)

func mfaAllUsersPolicy(id string) microsoft.ConditionalAccessPolicy {
	return microsoft.ConditionalAccessPolicy{
		ID:    id,
		State: "enabled",
		Conditions: microsoft.ConditionalAccessConditionSet{
			Users:          &microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}},
			Applications:   &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"All"}},
			ClientAppTypes: []string{"all"},
		},
		GrantControls: &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"mfa"}},
	}
}

func mfaAdminPortalPolicy(id string) microsoft.ConditionalAccessPolicy {
	policy := mfaAllUsersPolicy(id)
	policy.Conditions.Applications = &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"MicrosoftAdminPortals"}}
	return policy
}

func mfaAllCloudAppsPolicy(id string) microsoft.ConditionalAccessPolicy {
	return mfaAllUsersPolicy(id)
}

func compliantDeviceAdminPolicy(id string) microsoft.ConditionalAccessPolicy {
	return microsoft.ConditionalAccessPolicy{
		ID:    id,
		State: "enabled",
		Conditions: microsoft.ConditionalAccessConditionSet{
			Users:        &microsoft.ConditionalAccessUsers{IncludeRoles: []string{"62e90394-69f5-4237-9190-012177145e10"}},
			Applications: &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"MicrosoftAdminPortals"}},
		},
		GrantControls: &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"compliantDevice"}},
	}
}

func legacyAuthBlockPolicy(id string) microsoft.ConditionalAccessPolicy {
	return microsoft.ConditionalAccessPolicy{
		ID:    id,
		State: "enabled",
		Conditions: microsoft.ConditionalAccessConditionSet{
			ClientAppTypes: []string{"exchangeActiveSync", "other"},
		},
		GrantControls: &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"block"}},
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
