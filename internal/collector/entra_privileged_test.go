package collector

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// A role is privileged when Microsoft marks it so and some directory action
// it allows does more than read. A custom role is classified the same way,
// and one Microsoft hasn't classified is unknown.
func TestClassifyRoles(t *testing.T) {
	roles := classifyRoles(append(testRoleDefinitions(),
		roleDefinition("custom-writer", boolPtr(true), "microsoft.directory/users/password/update"),
		roleDefinition("custom-reader", boolPtr(true), "microsoft.directory/users/standard/read", "microsoft.directory/serviceAction/getAvailableExtentionProperties"),
		roleDefinition("unclassified", nil, "microsoft.directory/users/password/update")))
	for _, tc := range []struct {
		id                   string
		privileged, classify bool
	}{
		{globalAdministratorTemplateID, true, true},
		{"729827e3-9c14-49f7-bb1b-9608f156bbb8", true, true},
		{"f2ef992c-3afb-46b9-b7cf-a126ee74c451", false, true},
		{"29232cdf-9323-42fd-ade2-1d097af3e4de", false, true},
		{"custom-writer", true, true},
		{"custom-reader", false, true},
		{"unclassified", false, false},
		{"not-listed", false, false},
	} {
		privileged, classified := roles.classify(tc.id)
		if privileged != tc.privileged || classified != tc.classify {
			t.Errorf("classify(%s) = %v, %v, want %v, %v", tc.id, privileged, classified, tc.privileged, tc.classify)
		}
	}
}

// A user who holds only a role Microsoft hasn't classified may or may not be
// privileged, so the values over privileged users are left out.
func TestPrivilegedValuesLeftOutForAnUnclassifiedRole(t *testing.T) {
	graph := fakeGraphClient()
	graph.roleDefinitions = append(graph.roleDefinitions, roleDefinition("custom", nil, "microsoft.directory/users/password/update"))
	graph.roleAssignments = append(graph.roleAssignments, microsoft.UnifiedRoleAssignment{ID: "ra-custom", PrincipalID: "u2", RoleDefinitionID: "custom"})
	graph.roleAssignments = slices.DeleteFunc(graph.roleAssignments, func(a microsoft.UnifiedRoleAssignment) bool { return a.ID == "ra2" })
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.GraphClient = graph
	cfg.Recorder = rec

	pa := collectTestArtifact(t, cfg).PrivilegedAccess
	if pa.PrivilegedUsersCount != nil {
		t.Fatalf("privileged_users_count = %d, want it left out", *pa.PrivilegedUsersCount)
	}
	assertGap(t, rec, entraPath, "/privileged_access/privileged_users_count", componentsdk.CodeNotRead)
	assertGap(t, rec, entraPath, "/privileged_access/standing_assignment_count", componentsdk.CodeNotRead)
}

func TestPrivilegedCounts(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	privileged := artifact.PrivilegedAccess
	if privileged == nil {
		t.Fatal("expected privileged access metrics")
	}
	assertPtrInt(t, "super admins", privileged.SuperAdminCount, 1)
	assertPtrInt(t, "privileged users", privileged.PrivilegedUsersCount, 3)
	assertPtrInt(t, "privileged guests", privileged.PrivilegedGuestCount, 1)
	if privileged.PrivilegedMFACoveragePct == nil || *privileged.PrivilegedMFACoveragePct != 67 {
		t.Fatalf("unexpected privileged MFA coverage: %#v", privileged.PrivilegedMFACoveragePct)
	}
	if privileged.PrivilegedPhishingResistantPct == nil || *privileged.PrivilegedPhishingResistantPct != 33 {
		t.Fatalf("unexpected privileged phishing-resistant coverage: %#v", privileged.PrivilegedPhishingResistantPct)
	}
	if privileged.InactivePrivilegedUsersCount == nil || *privileged.InactivePrivilegedUsersCount != 2 {
		t.Fatalf("unexpected inactive privileged count: %#v", privileged.InactivePrivilegedUsersCount)
	}

	graph := fakeGraphClient()
	graph.regErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/reports/authenticationMethods/userRegistrationDetails"}
	cfg := testConfig()
	cfg.GraphClient = graph
	artifact = collectTestArtifact(t, cfg)
	if artifact.PrivilegedAccess.PrivilegedMFACoveragePct != nil || artifact.PrivilegedAccess.PrivilegedPhishingResistantPct != nil {
		t.Fatalf("expected null privileged MFA metrics without registration report, got %#v", artifact.PrivilegedAccess)
	}
}

func TestPimMetrics(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	privileged := artifact.PrivilegedAccess
	if privileged.PIMEligiblePct == nil || *privileged.PIMEligiblePct != 25 {
		t.Fatalf("unexpected PIM eligible pct: %#v", privileged.PIMEligiblePct)
	}
	if privileged.StandingAssignmentCount == nil || *privileged.StandingAssignmentCount != 3 {
		t.Fatalf("unexpected standing assignment count: %#v", privileged.StandingAssignmentCount)
	}

	graph := fakeGraphClient()
	graph.roleSchedulesErr = &microsoft.APIError{
		StatusCode: http.StatusForbidden,
		Route:      "/roleManagement/directory/roleEligibilitySchedules",
		Code:       "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
		Message:    "The tenant does not have a Premium license.",
	}
	cfg := testConfig()
	cfg.GraphClient = graph
	artifact = collectTestArtifact(t, cfg)
	if artifact.PrivilegedAccess.PIMEligiblePct != nil || artifact.PrivilegedAccess.StandingAssignmentCount != nil {
		t.Fatalf("expected null PIM metrics without P2, got %#v", artifact.PrivilegedAccess)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "pim") {
		t.Fatalf("expected pim unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}

	graph = fakeGraphClient()
	graph.roleSchedulesErr = &microsoft.APIError{
		StatusCode: http.StatusBadRequest,
		Route:      "/roleManagement/directory/roleEligibilitySchedules",
		Code:       "AadPremiumLicenseRequired",
		Message:    "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
	}
	cfg = testConfig()
	cfg.GraphClient = graph
	artifact = collectTestArtifact(t, cfg)
	if artifact.PrivilegedAccess.PIMEligiblePct != nil || artifact.PrivilegedAccess.StandingAssignmentCount != nil {
		t.Fatalf("expected null PIM metrics for AadPremiumLicenseRequired, got %#v", artifact.PrivilegedAccess)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "pim") {
		t.Fatalf("expected pim unavailable for AadPremiumLicenseRequired, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}

// A role assigned to a role-assignable group is held by every member of the
// group. Group members are not read, so the values over privileged users are
// left out.
func TestPrivilegedValuesLeftOutWhenARoleIsHeldThroughAGroup(t *testing.T) {
	group := &microsoft.DirectoryPrincipal{ODataType: "#microsoft.graph.group", ID: "g1"}
	overPrivilegedUsers := []string{
		"/privileged_access/privileged_users_count",
		"/privileged_access/privileged_guest_count",
		"/privileged_access/privileged_mfa_coverage_pct",
		"/privileged_access/privileged_phishing_resistant_pct",
		"/privileged_access/inactive_privileged_users_count",
	}
	cases := []struct {
		name         string
		role         string
		superAdmins  bool
		normalizedTo []string
	}{
		{"Global Administrator", globalAdministratorTemplateID, false, []string{"/privileged_access/super_admin_count", "/privileged_access/privileged_users_count", "/privileged_access/privileged_mfa_coverage_pct"}},
		{"Security Administrator", "194ae4cb-b126-40b2-bd5b-6091b380977d", true, []string{"/privileged_access/privileged_users_count", "/privileged_access/privileged_mfa_coverage_pct"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.roleAssignments = append(graph.roleAssignments, microsoft.UnifiedRoleAssignment{ID: "ra-group", PrincipalID: "g1", RoleDefinitionID: tc.role, Principal: group})
			rec := &componentsdk.Recorder{}
			cfg := testConfig()
			cfg.GraphClient = graph
			cfg.Recorder = rec

			result := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit)
			pa := result.Entra.PrivilegedAccess
			if pa.PrivilegedUsersCount != nil || pa.PrivilegedGuestCount != nil || pa.PrivilegedMFACoveragePct != nil ||
				pa.PrivilegedPhishingResistantPct != nil || pa.InactivePrivilegedUsersCount != nil {
				t.Fatalf("expected the values over privileged users left out, got %#v", pa)
			}
			for _, pointer := range overPrivilegedUsers {
				assertGap(t, rec, entraPath, pointer, componentsdk.CodeNotRead)
			}
			if tc.superAdmins {
				assertPtrInt(t, "super_admin_count", pa.SuperAdminCount, 1)
			} else {
				if pa.SuperAdminCount != nil {
					t.Fatalf("super_admin_count = %d, want it left out", *pa.SuperAdminCount)
				}
				assertGap(t, rec, entraPath, "/privileged_access/super_admin_count", componentsdk.CodeNotRead)
			}
			for _, pointer := range tc.normalizedTo {
				assertGap(t, rec, idpPosturePath, pointer, componentsdk.CodeNotRead)
			}
			// u1, u2 and u3 hold privileged roles directly, so there are
			// privileged users whoever is in the group.
			present := result.EntraIDPPosture.PrivilegedAccess.PrivilegedUsersPresent
			assertPtrBool(t, "privileged_users_present", present, true)
			assertNoGap(t, rec, idpPosturePath, "/privileged_access/privileged_users_present")
			// The PIM values count assignments to users, so the group's
			// assignment does not change them.
			assertPtrInt(t, "standing_assignment_count", pa.StandingAssignmentCount, 3)
		})
	}
}

// With only the group holding a privileged role, whether anyone holds one
// depends on the group's members, which are not read.
func TestPrivilegedUsersPresentUnknownWhenOnlyAGroupHoldsARole(t *testing.T) {
	graph := fakeGraphClient()
	graph.roleAssignments = []microsoft.UnifiedRoleAssignment{{
		ID: "ra-group", PrincipalID: "g1", RoleDefinitionID: globalAdministratorTemplateID,
		Principal: &microsoft.DirectoryPrincipal{ODataType: "#microsoft.graph.group", ID: "g1"},
	}}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.GraphClient = graph
	cfg.Recorder = rec

	posture := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit).EntraIDPPosture
	if present := posture.PrivilegedAccess.PrivilegedUsersPresent; present != nil {
		t.Fatalf("privileged_users_present = %v, want it left out", *present)
	}
	assertGap(t, rec, idpPosturePath, "/privileged_access/privileged_users_present", componentsdk.CodeNotRead)
}

// Microsoft labels these roles privileged. Each can reset other users'
// credentials or change how they sign in.
func TestRolesThatResetCredentialsArePrivileged(t *testing.T) {
	for name, id := range map[string]string{
		"Helpdesk Administrator":        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
		"Hybrid Identity Administrator": "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
		"Partner Tier2 Support":         "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
		"Password Administrator":        "966707d0-3269-4727-9be2-8c3a10f19b9d",
		"Intune Administrator":          "3a2c62db-5318-420d-8d74-23affee5d9d5",
	} {
		t.Run(name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.roleAssignments = []microsoft.UnifiedRoleAssignment{{ID: "ra-u2", PrincipalID: "u2", RoleDefinitionID: id}}
			cfg := testConfig()
			cfg.GraphClient = graph

			assertPtrInt(t, "privileged_users_count", collectTestArtifact(t, cfg).PrivilegedAccess.PrivilegedUsersCount, 1)
		})
	}
}

// Microsoft labels Global Reader privileged, but it only reads. Exchange
// Administrator isn't labeled privileged.
func TestReadOnlyAndUnlabeledRolesAreNotPrivileged(t *testing.T) {
	for name, id := range map[string]string{
		"Global Reader":          "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
		"Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
	} {
		t.Run(name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.roleAssignments = []microsoft.UnifiedRoleAssignment{{ID: "ra-u2", PrincipalID: "u2", RoleDefinitionID: id}}
			cfg := testConfig()
			cfg.GraphClient = graph

			assertPtrInt(t, "privileged_users_count", collectTestArtifact(t, cfg).PrivilegedAccess.PrivilegedUsersCount, 0)
		})
	}
}

// u2 is privileged and missing from the registration report, so whether the
// privileged users have MFA isn't known.
func TestPrivilegedMFALeftOutWhenTheReportMissesAnAdmin(t *testing.T) {
	graph := fakeGraphClient()
	graph.registrations = slices.DeleteFunc(graph.registrations, func(r microsoft.UserRegistrationDetail) bool { return r.ID == "u2" })
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.GraphClient = graph
	cfg.Recorder = rec

	pa := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit).Entra.PrivilegedAccess
	if pa.PrivilegedMFACoveragePct != nil || pa.PrivilegedPhishingResistantPct != nil {
		t.Fatalf("expected the privileged MFA values left out, got %#v", pa)
	}
	for _, pointer := range []string{"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct"} {
		assertGap(t, rec, entraPath, pointer, componentsdk.CodeVendorError)
		assertGap(t, rec, idpPosturePath, pointer, componentsdk.CodeVendorError)
	}
	assertGap(t, rec, idpPosturePath, "/privileged_access/privileged_mfa_user_count", componentsdk.CodeVendorError)
}

// A disabled account cannot sign in, so it is not a privileged user. u4 is
// disabled and missing from the registration report. As a Global
// Administrator it would lower the MFA values.
func TestDisabledAccountsAreNotPrivilegedUsers(t *testing.T) {
	graph := fakeGraphClient()
	graph.roleAssignments = append(graph.roleAssignments,
		microsoft.UnifiedRoleAssignment{ID: "ra-u4", PrincipalID: "u4", RoleDefinitionID: globalAdministratorTemplateID})
	cfg := testConfig()
	cfg.GraphClient = graph
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	pa := result.Entra.PrivilegedAccess
	assertPtrInt(t, "super_admin_count", pa.SuperAdminCount, 1)
	assertPtrInt(t, "privileged_users_count", pa.PrivilegedUsersCount, 3)
	assertPtrInt(t, "privileged_mfa_coverage_pct", pa.PrivilegedMFACoveragePct, 67)
	assertPtrInt(t, "inactive_privileged_users_count", pa.InactivePrivilegedUsersCount, 2)
	// The assignment is still a standing one.
	assertPtrInt(t, "standing_assignment_count", pa.StandingAssignmentCount, 4)
	assertPtrInt(t, "pim_eligible_pct", pa.PIMEligiblePct, 20)
}
