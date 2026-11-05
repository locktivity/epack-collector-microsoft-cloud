package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestPrivilegedSet(t *testing.T) {
	if len(privilegedRoleTemplateIDs) != 11 {
		t.Fatalf("expected 11 privileged roles, got %d", len(privilegedRoleTemplateIDs))
	}
	if !isPrivilegedRoleTemplateID(globalAdministratorTemplateID) {
		t.Fatal("global administrator missing from privileged role set")
	}
	if isPrivilegedRoleTemplateID("not-privileged") {
		t.Fatal("unexpected role classified as privileged")
	}
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

			pa := collectTestArtifact(t, cfg).PrivilegedAccess
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
			// The PIM values count assignments to users, so the group's
			// assignment does not change them.
			assertPtrInt(t, "standing_assignment_count", pa.StandingAssignmentCount, 3)
		})
	}
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
