package collector

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestNormalizedIdpComplete(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	artifact.CollectedAtLevel = string(componentsdk.LevelAudit)
	idp := artifact.ToIDPPosture()
	if idp == nil {
		t.Fatal("expected normalized artifact")
	}
	if got := idp.UserSecurity.MFAPhishingResistantPct.Value; got == nil || *got != 50 {
		t.Fatalf("unexpected phishing-resistant MFA: %#v", idp.UserSecurity)
	}
	// u1 signed in recently and u2 hasn't. The guest u3 isn't a user.
	if got := idp.UserSecurity.InactivePct.Value; got == nil || *got != 50 {
		t.Fatalf("unexpected inactive pct: %#v", idp.UserSecurity)
	}
	assertPtrInt(t, "inactive_user_count", idp.UserSecurity.InactiveUserCount, 1)
	if idp.AppSecurity == nil || idp.AppSecurity.SSOCoveragePct.Value == nil || *idp.AppSecurity.SSOCoveragePct.Value != 100 {
		t.Fatalf("unexpected app security: %#v", idp.AppSecurity)
	}
	if idp.PrivilegedAccess == nil || idp.PrivilegedAccess.PrivilegedUsersPresent == nil || !*idp.PrivilegedAccess.PrivilegedUsersPresent {
		t.Fatalf("unexpected privileged access: %#v", idp.PrivilegedAccess)
	}
	if idp.PrivilegedAccess.PrivilegedUsersCount == nil || *idp.PrivilegedAccess.PrivilegedUsersCount != 3 {
		t.Fatalf("unexpected privileged access: %#v", idp.PrivilegedAccess)
	}
	if idp.PrivilegedAccess.SuperAdminCount == nil || *idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Fatalf("unexpected super admin count: %#v", idp.PrivilegedAccess)
	}
	// Two of the three privileged users are registered, which rounds down.
	if got := idp.PrivilegedAccess.PrivilegedMFACoveragePct.Value; got == nil || *got != 66 {
		t.Fatalf("unexpected privileged MFA coverage: %#v", idp.PrivilegedAccess)
	}
	if idp.Lifecycle == nil || idp.Lifecycle.SuspendedPct.Value == nil || *idp.Lifecycle.SuspendedPct.Value != 25 {
		t.Fatalf("unexpected lifecycle: %#v", idp.Lifecycle)
	}
}

func TestNormalizedIdpLeavesCountsOutBelowAudit(t *testing.T) {
	idp := collectTestArtifact(t, testConfig()).ToIDPPosture()
	if idp == nil || idp.PrivilegedAccess == nil || idp.UserSecurity == nil {
		t.Fatalf("expected normalized artifact, got %#v", idp)
	}
	if idp.PrivilegedAccess.PrivilegedUsersCount != nil || idp.PrivilegedAccess.SuperAdminCount != nil || idp.UserSecurity.UserCount != nil {
		t.Fatalf("expected no counts at trust, got %#v and %#v", idp.PrivilegedAccess, idp.UserSecurity)
	}
	if idp.UserSecurity.UsersPresent == nil || !*idp.UserSecurity.UsersPresent {
		t.Fatalf("expected users_present at trust, got %#v", idp.UserSecurity)
	}
}

func TestNormalizedIdpWritesTheMFACountsWhenTheReportListsEveryMember(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	artifact.CollectedAtLevel = string(componentsdk.LevelAudit)
	members := *artifact.Users.EnabledMemberUsersCount
	artifact.Posture.DenominatorEnabledMemberUsers = intPtr(members)
	artifact.Posture.mfaRegisteredCount = intPtr(members - 1)
	artifact.Posture.phishingResistantCount = intPtr(1)
	idp := artifact.ToIDPPosture()
	assertPtrInt(t, "mfa_user_count", idp.UserSecurity.MFAUserCount, members-1)
	assertPtrInt(t, "phishing_resistant_user_count", idp.UserSecurity.PhishingResistantUserCount, 1)

	// With a member the report doesn't list, the percentages are taken over
	// fewer users than user_count, so the counts are left out.
	artifact.Posture.DenominatorEnabledMemberUsers = intPtr(members - 1)
	idp = artifact.ToIDPPosture()
	if idp.UserSecurity.MFAUserCount != nil || idp.UserSecurity.PhishingResistantUserCount != nil {
		t.Fatalf("counts = %v and %v, want both left out", idp.UserSecurity.MFAUserCount, idp.UserSecurity.PhishingResistantUserCount)
	}
}

func TestStandingPrivilegedUsersLeaveOutJustInTimeActivations(t *testing.T) {
	const securityAdministrator = "194ae4cb-b126-40b2-bd5b-6091b380977d"
	roles := func(ids ...string) map[string]struct{} {
		set := map[string]struct{}{}
		for _, id := range ids {
			set[id] = struct{}{}
		}
		return set
	}
	eligible := func(user, role string) microsoft.UnifiedRoleEligibilitySchedule {
		return microsoft.UnifiedRoleEligibilitySchedule{PrincipalID: user, RoleDefinitionID: role}
	}
	got := standingPrivilegedUsers(map[string]map[string]struct{}{
		"permanent": roles(globalAdministratorTemplateID),
		"activated": roles(securityAdministrator),
		"both":      roles(globalAdministratorTemplateID, securityAdministrator),
	}, []microsoft.UnifiedRoleEligibilitySchedule{
		eligible("activated", securityAdministrator),
		eligible("both", globalAdministratorTemplateID),
	}, classifyRoles(testRoleDefinitions()))
	// "activated" holds only the role PIM lists them as eligible for, so
	// they activated it just in time. "both" holds Security Administrator
	// at all times.
	if got != 2 {
		t.Fatalf("standing privileged users = %d, want 2", got)
	}
}

// Role template IDs of the fixture tenant's admins: u1 holds Global
// Administrator, u2 Security Administrator, and the guest u3 Application
// Administrator.
const (
	securityAdministratorTemplateID    = "194ae4cb-b126-40b2-bd5b-6091b380977d"
	applicationAdministratorTemplateID = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
)

func strengthOf(combinations ...string) *microsoft.AuthenticationStrengthPolicy {
	return &microsoft.AuthenticationStrengthPolicy{ID: "custom", PolicyType: "custom", RequirementsSatisfied: "mfa", AllowedCombinations: combinations}
}

func TestNormalizedIdpDeviceAndPhishingResistantPolicies(t *testing.T) {
	phishingResistant := strengthOf("windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor")
	only := func(change func(*microsoft.ConditionalAccessPolicy)) []microsoft.ConditionalAccessPolicy {
		policy := mfaAllUsersPolicy("p1")
		change(&policy)
		return []microsoft.ConditionalAccessPolicy{policy}
	}
	grant := func(operator string, strength *microsoft.AuthenticationStrengthPolicy, builtIn ...string) func(*microsoft.ConditionalAccessPolicy) {
		return func(p *microsoft.ConditionalAccessPolicy) {
			p.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: operator, BuiltInControls: builtIn, AuthenticationStrength: strength}
		}
	}
	both := func(changes ...func(*microsoft.ConditionalAccessPolicy)) func(*microsoft.ConditionalAccessPolicy) {
		return func(p *microsoft.ConditionalAccessPolicy) {
			for _, change := range changes {
				change(p)
			}
		}
	}
	roles := func(ids ...string) func(*microsoft.ConditionalAccessPolicy) {
		return func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Users = &microsoft.ConditionalAccessUsers{IncludeRoles: ids}
		}
	}
	legacyBlock := mfaAllUsersPolicy("block-legacy")
	legacyBlock.Conditions.ClientAppTypes = []string{"exchangeActiveSync", "other"}
	legacyBlock.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"block"}}

	cases := []struct {
		name                                    string
		policies                                []microsoft.ConditionalAccessPolicy
		phishingResistant, device, deviceAdmins bool
	}{
		{"MFA for all users", only(func(*microsoft.ConditionalAccessPolicy) {}), false, false, false},
		{"phishing-resistant strength for all users", only(grant("OR", phishingResistant)), true, false, false},
		{"custom strength of security keys alone", only(grant("OR", strengthOf("fido2"))), true, false, false},
		{"passwordless strength, which allows phone sign-in", only(grant("OR", strengthOf("windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "deviceBasedPush"))), false, false, false},
		{"phishing-resistant strength for every admin role", only(both(grant("OR", phishingResistant),
			roles(globalAdministratorTemplateID, securityAdministratorTemplateID, applicationAdministratorTemplateID))), true, false, false},
		{"phishing-resistant strength for two of the three admin roles", only(both(grant("OR", phishingResistant),
			roles(globalAdministratorTemplateID, securityAdministratorTemplateID))), false, false, false},
		{"compliant device for all users", only(grant("OR", nil, "compliantDevice")), false, true, true},
		{"compliant device for all users but one", only(both(grant("OR", nil, "compliantDevice"), func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Users.ExcludeUsers = []string{"u1"}
		})), false, true, true},
		{"hybrid joined device for every admin role", only(both(grant("OR", nil, "domainJoinedDevice"),
			roles(applicationAdministratorTemplateID, securityAdministratorTemplateID, globalAdministratorTemplateID))), false, false, true},
		{"MFA and a compliant device", only(grant("AND", nil, "mfa", "compliantDevice")), false, true, true},
		{"MFA or a compliant device", only(grant("OR", nil, "mfa", "compliantDevice")), false, false, false},
		{"compliant or hybrid joined device", only(grant("OR", nil, "compliantDevice", "domainJoinedDevice")), false, true, true},
		{"report-only compliant device", only(both(grant("OR", nil, "compliantDevice"), func(p *microsoft.ConditionalAccessPolicy) {
			p.State = "enabledForReportingButNotEnforced"
		})), false, false, false},
		{"compliant device for one app", only(both(grant("OR", nil, "compliantDevice"), func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Applications.IncludeApplications = []string{"Office365"}
		})), false, false, false},
		{"compliant device on risky sign-ins", only(both(grant("OR", nil, "compliantDevice"), func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.SignInRiskLevels = []string{"high"}
		})), false, false, false},
		// Derive's applies has no condition at all, so a policy for modern
		// clients doesn't count even where legacy authentication is blocked.
		{"compliant device for browsers and apps beside a legacy block", append(only(both(grant("OR", nil, "compliantDevice"), func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.ClientAppTypes = []string{"browser", "mobileAppsAndDesktopClients"}
		})), legacyBlock), false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.policies = tc.policies
			cfg := testConfig()
			cfg.GraphClient = graph

			idp := collectTestArtifact(t, cfg).ToIDPPosture()
			assertPtrBool(t, "phishing_resistant_required_for_privileged", idp.Policy.PhishingResistantRequiredForPrivileged, tc.phishingResistant)
			assertPtrBool(t, "managed_device_required", idp.DeviceAccess.ManagedDeviceRequired, tc.device)
			assertPtrBool(t, "managed_device_required_for_admins", idp.DeviceAccess.ManagedDeviceRequiredForAdmins, tc.deviceAdmins)
		})
	}
}

// Graph gives a policy's authentication strength with its allowed
// combinations, as for the built-in Phishing-resistant MFA strength.
func TestNormalizedIdpReadsTheBuiltInPhishingResistantStrength(t *testing.T) {
	var policies []microsoft.ConditionalAccessPolicy
	raw := `[{"id":"p1","state":"enabled",
		"conditions":{"clientAppTypes":["all"],"applications":{"includeApplications":["All"]},"users":{"includeUsers":["All"]}},
		"grantControls":{"operator":"OR","builtInControls":[],"customAuthenticationFactors":[],"termsOfUse":[],"authenticationStrength":{
			"id":"00000000-0000-0000-0000-000000000004","displayName":"Phishing-resistant MFA","policyType":"builtIn","requirementsSatisfied":"mfa",
			"allowedCombinations":["windowsHelloForBusiness","fido2","x509CertificateMultiFactor"]}}}]`
	if err := json.Unmarshal([]byte(raw), &policies); err != nil {
		t.Fatal(err)
	}
	graph := fakeGraphClient()
	graph.policies = policies
	cfg := testConfig()
	cfg.GraphClient = graph

	idp := collectTestArtifact(t, cfg).ToIDPPosture()
	assertPtrBool(t, "phishing_resistant_required_for_privileged", idp.Policy.PhishingResistantRequiredForPrivileged, true)
}

var deviceAndPhishingResistantValues = []string{
	"/policy/phishing_resistant_required_for_privileged", "/device_access/managed_device_required", "/device_access/managed_device_required_for_admins",
}

func TestNormalizedIdpDeviceValuesTakeTheConditionalAccessGap(t *testing.T) {
	graph := fakeGraphClient()
	graph.policiesErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/identity/conditionalAccess/policies"}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.GraphClient = graph
	cfg.Recorder = rec

	idp := collectTestArtifact(t, cfg).ToIDPPosture()
	if idp.Policy != nil || idp.DeviceAccess != nil {
		t.Fatalf("expected the policy values left out, got %#v and %#v", idp.Policy, idp.DeviceAccess)
	}
	for _, pointer := range deviceAndPhishingResistantValues {
		assertGap(t, rec, idpPosturePath, pointer, componentsdk.CodePermissionDenied)
	}
}

// Security defaults require no managed device and no phishing-resistant
// MFA, and no policy can be enabled beside them, so the values are false
// without a Conditional Access license.
func TestNormalizedIdpDeviceValuesUnderSecurityDefaults(t *testing.T) {
	graph := fakeGraphClient()
	graph.securityDefaults = &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true}
	graph.policiesErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/identity/conditionalAccess/policies",
		Code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", Message: "The tenant does not have a Premium license."}
	cfg := testConfig()
	cfg.GraphClient = graph

	idp := collectTestArtifact(t, cfg).ToIDPPosture()
	assertPtrBool(t, "phishing_resistant_required_for_privileged", idp.Policy.PhishingResistantRequiredForPrivileged, false)
	assertPtrBool(t, "managed_device_required", idp.DeviceAccess.ManagedDeviceRequired, false)
	assertPtrBool(t, "managed_device_required_for_admins", idp.DeviceAccess.ManagedDeviceRequiredForAdmins, false)
}

func TestNormalizedIdpAdminValuesNeedTheAdmins(t *testing.T) {
	compliantDevice := mfaAllUsersPolicy("p1")
	compliantDevice.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"compliantDevice"}}
	adminValues := []string{"/policy/phishing_resistant_required_for_privileged", "/device_access/managed_device_required_for_admins"}
	cases := []struct {
		name   string
		change func(*fakeGraph)
		code   componentsdk.Code
	}{
		{"a group holds a privileged role", func(g *fakeGraph) {
			g.roleAssignments = append(g.roleAssignments, microsoft.UnifiedRoleAssignment{ID: "ra-group", PrincipalID: "g1", RoleDefinitionID: securityAdministratorTemplateID,
				Principal: &microsoft.DirectoryPrincipal{ODataType: "#microsoft.graph.group", ID: "g1"}})
		}, componentsdk.CodeNotRead},
		{"role assignments can't be read", func(g *fakeGraph) {
			g.roleAssignmentsErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/roleManagement/directory/roleAssignments"}
		}, componentsdk.CodePermissionDenied},
		{"no one holds a privileged role", func(g *fakeGraph) { g.roleAssignments = nil }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.policies = []microsoft.ConditionalAccessPolicy{compliantDevice}
			tc.change(graph)
			rec := &componentsdk.Recorder{}
			cfg := testConfig()
			cfg.GraphClient = graph
			cfg.Recorder = rec

			idp := collectTestArtifact(t, cfg).ToIDPPosture()
			assertPtrBool(t, "managed_device_required", idp.DeviceAccess.ManagedDeviceRequired, true)
			if idp.Policy.PhishingResistantRequiredForPrivileged != nil || idp.DeviceAccess.ManagedDeviceRequiredForAdmins != nil {
				t.Fatalf("expected the admin values left out, got %v and %v",
					idp.Policy.PhishingResistantRequiredForPrivileged, idp.DeviceAccess.ManagedDeviceRequiredForAdmins)
			}
			for _, pointer := range adminValues {
				if tc.code == "" {
					assertNoGap(t, rec, idpPosturePath, pointer)
				} else {
					assertGap(t, rec, idpPosturePath, pointer, tc.code)
				}
			}
		})
	}
}
