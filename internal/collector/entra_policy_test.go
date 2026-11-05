package collector

import (
	"context"
	"encoding/json"
	"fmt"
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
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.GraphClient = graph
	cfg.Recorder = rec

	artifact := collectTestArtifact(t, cfg)
	if artifact.Policy == nil || artifact.Policy.MFARequired != nil {
		t.Fatalf("expected null CA metrics, got %#v", artifact.Policy)
	}
	if artifact.Policy.MFARequiredCoveragePct != nil {
		t.Fatalf("expected null coverage while security defaults are off and policies are unreadable, got %#v", artifact.Policy)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "conditional_access") {
		t.Fatalf("expected conditional_access unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
	assertGap(t, rec, entraPath, "/policy/mfa_required_coverage_pct", componentsdk.CodePermissionDenied)
	assertGap(t, rec, idpPosturePath, "/policy/mfa_required", componentsdk.CodePermissionDenied)
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

func TestMfaRequiredHonorsTheGrantOperator(t *testing.T) {
	cases := []struct {
		name     string
		operator string
		controls []string
		mfa      bool
		device   bool
	}{
		// With OR, a compliant device alone gets a user in.
		{"MFA or a compliant device", "OR", []string{"mfa", "compliantDevice"}, false, false},
		{"MFA and a compliant device", "AND", []string{"mfa", "compliantDevice"}, true, true},
		{"MFA alone", "OR", []string{"mfa"}, true, false},
		{"a compliant or hybrid joined device", "OR", []string{"compliantDevice", "domainJoinedDevice"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			policy := mfaAllUsersPolicy("grant")
			policy.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: tc.operator, BuiltInControls: tc.controls}
			graph.policies = []microsoft.ConditionalAccessPolicy{policy}
			cfg := testConfig()
			cfg.GraphClient = graph

			p := collectTestArtifact(t, cfg).Policy
			for _, flag := range []struct {
				name string
				got  *bool
				want bool
			}{
				{"mfa_required", p.MFARequired, tc.mfa},
				{"all_cloud_apps_mfa_required", p.AllCloudAppsMFARequired, tc.mfa},
				{"admin_portals_mfa_required", p.AdminPortalsMFARequired, tc.mfa},
				{"compliant_device_required", p.CompliantDeviceRequired, tc.device},
			} {
				if flag.got == nil || *flag.got != flag.want {
					t.Errorf("%s = %s, want %v", flag.name, showBool(flag.got), flag.want)
				}
			}
			want := 0
			if tc.mfa {
				want = 100
			}
			assertPtrInt(t, "mfa_required_coverage_pct", p.MFARequiredCoveragePct, want)
		})
	}
}

// The authentication strength a policy requires is inline in its grant
// controls, with an empty builtInControls.
func TestAuthenticationStrengthCountsAsMFA(t *testing.T) {
	cases := []struct {
		name, strength string
		want           bool
	}{
		{"built-in Multifactor authentication", `{"id":"00000000-0000-0000-0000-000000000002","displayName":"Multifactor authentication","policyType":"builtIn","requirementsSatisfied":"mfa"}`, true},
		{"built-in Phishing-resistant MFA", `{"id":"00000000-0000-0000-0000-000000000004","displayName":"Phishing-resistant MFA","policyType":"builtIn","requirementsSatisfied":"mfa"}`, true},
		{"custom strength that grants the MFA claim", `{"id":"c1","displayName":"Hardware keys","policyType":"custom","requirementsSatisfied":"mfa"}`, true},
		{"custom strength that does not grant the MFA claim", `{"id":"c2","displayName":"SMS sign-in","policyType":"custom","requirementsSatisfied":"none"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var policies []microsoft.ConditionalAccessPolicy
			raw := `[{"id":"p1","state":"enabled",
				"conditions":{"clientAppTypes":["all"],"applications":{"includeApplications":["All"]},"users":{"includeUsers":["All"]}},
				"grantControls":{"operator":"OR","builtInControls":[],"customAuthenticationFactors":[],"termsOfUse":[],"authenticationStrength":` + tc.strength + `}}]`
			if err := json.Unmarshal([]byte(raw), &policies); err != nil {
				t.Fatal(err)
			}
			graph := fakeGraphClient()
			graph.policies = policies
			cfg := testConfig()
			cfg.GraphClient = graph

			p := collectTestArtifact(t, cfg).Policy
			if p.MFARequired == nil || *p.MFARequired != tc.want {
				t.Fatalf("mfa_required = %s, want %v", showBool(p.MFARequired), tc.want)
			}
			if p.AllCloudAppsMFARequired == nil || *p.AllCloudAppsMFARequired != tc.want {
				t.Fatalf("all_cloud_apps_mfa_required = %s, want %v", showBool(p.AllCloudAppsMFARequired), tc.want)
			}
			want := 0
			if tc.want {
				want = 100
			}
			assertPtrInt(t, "mfa_required_coverage_pct", p.MFARequiredCoveragePct, want)
		})
	}
}

// A policy applies only to the sign-ins that meet its conditions. A policy
// that requires MFA only at some risk levels, locations, platforms or devices
// does not require MFA on every sign-in. Neither does a policy for a user
// action.
func TestMfaRequiredNeedsAPolicyForEverySignIn(t *testing.T) {
	const allApps = `{"includeApplications":["All"]}`
	cases := []struct {
		name, applications, conditions string
		want                           bool
	}{
		{"no other condition", allApps, ``, true},
		{"every location and platform", allApps, `,"locations":{"includeLocations":["All"],"excludeLocations":[]},"platforms":{"includePlatforms":["all"],"excludePlatforms":[]}`, true},
		{"empty risk levels", allApps, `,"signInRiskLevels":[],"userRiskLevels":[],"servicePrincipalRiskLevels":[]`, true},
		{"sign-in risk", allApps, `,"signInRiskLevels":["high","medium"]`, false},
		{"user risk", allApps, `,"userRiskLevels":["high"]`, false},
		{"insider risk", allApps, `,"insiderRiskLevels":"elevated"`, false},
		{"untrusted locations", allApps, `,"locations":{"includeLocations":["All"],"excludeLocations":["AllTrusted"]}`, false},
		{"some platforms", allApps, `,"platforms":{"includePlatforms":["android","iOS"]}`, false},
		{"device filter", allApps, `,"devices":{"deviceFilter":{"mode":"exclude","rule":"device.trustType -eq \"ServerAD\""}}`, false},
		{"device code flow", allApps, `,"authenticationFlows":{"transferMethods":"deviceCodeFlow"}`, false},
		{"registering security information", `{"includeApplications":[],"includeUserActions":["urn:user:registersecurityinfo"]}`, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var policies []microsoft.ConditionalAccessPolicy
			raw := `[{"id":"p1","state":"enabled",
				"conditions":{"clientAppTypes":["all"],"applications":` + tc.applications + `,"users":{"includeUsers":["All"]}` + tc.conditions + `},
				"grantControls":{"operator":"OR","builtInControls":["mfa"]}}]`
			if err := json.Unmarshal([]byte(raw), &policies); err != nil {
				t.Fatal(err)
			}
			graph := fakeGraphClient()
			graph.policies = policies
			cfg := testConfig()
			cfg.GraphClient = graph

			p := collectTestArtifact(t, cfg).Policy
			for _, flag := range []struct {
				name string
				got  *bool
				want bool
			}{
				{"mfa_required", p.MFARequired, tc.want},
				{"all_cloud_apps_mfa_required", p.AllCloudAppsMFARequired, tc.want && tc.applications == allApps},
				{"admin_portals_mfa_required", p.AdminPortalsMFARequired, tc.want && tc.applications == allApps},
			} {
				if flag.got == nil || *flag.got != flag.want {
					t.Errorf("%s = %s, want %v", flag.name, showBool(flag.got), flag.want)
				}
			}
			want := 0
			if tc.want {
				want = 100
			}
			assertPtrInt(t, "mfa_required_coverage_pct", p.MFARequiredCoveragePct, want)
		})
	}
}

// Group members and role holders are not read, so a policy that includes or
// excludes a group or a role covers an unknown share of members.
func TestMfaCoverageLeftOutWhenAPolicyIncludesOrExcludesGroupsOrRoles(t *testing.T) {
	cases := []struct {
		name  string
		users microsoft.ConditionalAccessUsers
	}{
		{"included group", microsoft.ConditionalAccessUsers{IncludeGroups: []string{"g1"}}},
		{"included role", microsoft.ConditionalAccessUsers{IncludeRoles: []string{globalAdministratorTemplateID}}},
		{"named user and included group", microsoft.ConditionalAccessUsers{IncludeUsers: []string{"u1"}, IncludeGroups: []string{"g1"}}},
		{"excluded group", microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}, ExcludeGroups: []string{"g1"}}},
		{"excluded role", microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}, ExcludeRoles: []string{globalAdministratorTemplateID}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			policy := mfaAllUsersPolicy("exclusions")
			policy.Conditions.Users = &tc.users
			graph.policies = []microsoft.ConditionalAccessPolicy{policy}
			rec := &componentsdk.Recorder{}
			cfg := testConfig()
			cfg.GraphClient = graph
			cfg.Recorder = rec

			artifact := collectTestArtifact(t, cfg)
			if artifact.Policy.MFARequiredCoveragePct != nil {
				t.Fatalf("mfa_required_coverage_pct = %d, want it left out", *artifact.Policy.MFARequiredCoveragePct)
			}
			assertGap(t, rec, entraPath, "/policy/mfa_required_coverage_pct", componentsdk.CodeNotRead)
			assertGap(t, rec, idpPosturePath, "/policy/mfa_required_coverage_pct", componentsdk.CodeNotRead)
		})
	}

	t.Run("another policy covers every member", func(t *testing.T) {
		graph := fakeGraphClient()
		excluding := mfaAllUsersPolicy("excludes-a-group")
		excluding.Conditions.Users = &microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}, ExcludeGroups: []string{"g1"}}
		including := mfaAllUsersPolicy("includes-a-group")
		including.Conditions.Users = &microsoft.ConditionalAccessUsers{IncludeGroups: []string{"g1"}}
		graph.policies = []microsoft.ConditionalAccessPolicy{excluding, including, mfaAllUsersPolicy("all-users")}
		cfg := testConfig()
		cfg.GraphClient = graph

		assertPtrInt(t, "mfa_required_coverage_pct", collectTestArtifact(t, cfg).Policy.MFARequiredCoveragePct, 100)
	})
}

// Microsoft's policy blocks legacy authentication for all users and all
// resources, on Exchange ActiveSync clients and other clients. It excludes no
// app and has no condition besides the client apps.
func TestLegacyAuthBlockedNeedsAllUsersResourcesAndLegacyClients(t *testing.T) {
	cases := []struct {
		name   string
		change func(*microsoft.ConditionalAccessPolicy)
		want   bool
	}{
		{"Microsoft's policy", func(*microsoft.ConditionalAccessPolicy) {}, true},
		{"every client app type", func(p *microsoft.ConditionalAccessPolicy) { p.Conditions.ClientAppTypes = []string{"all"} }, true},
		{"one user", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Users = &microsoft.ConditionalAccessUsers{IncludeUsers: []string{"u1"}}
		}, false},
		{"one app", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Applications = &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"00000002-0000-0ff1-ce00-000000000000"}}
		}, false},
		{"Exchange ActiveSync only", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.ClientAppTypes = []string{"exchangeActiveSync"}
		}, false},
		{"other clients only", func(p *microsoft.ConditionalAccessPolicy) { p.Conditions.ClientAppTypes = []string{"other"} }, false},
		{"Exchange Online excluded", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Applications.ExcludeApplications = []string{"00000002-0000-0ff1-ce00-000000000000"}
		}, false},
		{"apps excluded by a filter", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Applications.ApplicationFilter = &microsoft.ConditionalAccessFilter{Mode: "exclude", Rule: `CustomSecurityAttribute.Engineering_Project -eq "Legacy"`}
		}, false},
		{"user risk", func(p *microsoft.ConditionalAccessPolicy) { p.Conditions.UserRiskLevels = []string{"high"} }, false},
		{"sign-in risk", func(p *microsoft.ConditionalAccessPolicy) { p.Conditions.SignInRiskLevels = []string{"high"} }, false},
		{"every location", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{"All"}}
		}, true},
		{"untrusted locations", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{"All"}, ExcludeLocations: []string{"AllTrusted"}}
		}, false},
		{"some platforms", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Platforms = &microsoft.ConditionalAccessPlatforms{IncludePlatforms: []string{"android", "iOS"}}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := legacyAuthBlockPolicy("legacy")
			tc.change(&policy)
			graph := fakeGraphClient()
			graph.policies = []microsoft.ConditionalAccessPolicy{policy}
			cfg := testConfig()
			cfg.GraphClient = graph

			got := collectTestArtifact(t, cfg).Policy.LegacyAuthBlocked
			if got == nil || *got != tc.want {
				t.Fatalf("legacy_auth_blocked = %s, want %v", showBool(got), tc.want)
			}
		})
	}
}

// Security defaults and enabled Conditional Access policies cannot both be in
// use. With no enabled policy, security defaults set the MFA policy coverage.
func TestMfaCoverageFromSecurityDefaultsWithNoEnabledPolicy(t *testing.T) {
	cases := []struct {
		name     string
		defaults *microsoft.IdentitySecurityDefaultsEnforcementPolicy
		want     int
	}{
		{"security defaults on", &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true}, 100},
		{"security defaults off", &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: false}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.policies = []microsoft.ConditionalAccessPolicy{{ID: "off", State: "disabled"}}
			graph.securityDefaults = tc.defaults
			cfg := testConfig()
			cfg.GraphClient = graph

			assertPtrInt(t, "mfa_required_coverage_pct", collectTestArtifact(t, cfg).Policy.MFARequiredCoveragePct, tc.want)
		})
	}

	t.Run("security defaults unread", func(t *testing.T) {
		graph := fakeGraphClient()
		graph.policies = nil
		graph.securityDefErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/policies/identitySecurityDefaultsEnforcementPolicy"}
		rec := &componentsdk.Recorder{}
		cfg := testConfig()
		cfg.GraphClient = graph
		cfg.Recorder = rec

		if got := collectTestArtifact(t, cfg).Policy.MFARequiredCoveragePct; got != nil {
			t.Fatalf("mfa_required_coverage_pct = %d, want it left out", *got)
		}
		assertGap(t, rec, entraPath, "/policy/mfa_required_coverage_pct", componentsdk.CodePermissionDenied)
	})
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
	if got := idp.Policy.MFARequiredCoveragePct.Value; got == nil || *got != 100 {
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

// legacyAuthBlockPolicy is Microsoft's policy that blocks legacy
// authentication for all users and all resources.
func legacyAuthBlockPolicy(id string) microsoft.ConditionalAccessPolicy {
	return microsoft.ConditionalAccessPolicy{
		ID:    id,
		State: "enabled",
		Conditions: microsoft.ConditionalAccessConditionSet{
			Users:          &microsoft.ConditionalAccessUsers{IncludeUsers: []string{"All"}, ExcludeUsers: []string{"break-glass"}},
			Applications:   &microsoft.ConditionalAccessApplications{IncludeApplications: []string{"All"}},
			ClientAppTypes: []string{"exchangeActiveSync", "other"},
		},
		GrantControls: &microsoft.ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"block"}},
	}
}

func showBool(value *bool) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprint(*value)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
