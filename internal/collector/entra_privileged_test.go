package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
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
	if privileged.SuperAdminCount != 1 {
		t.Fatalf("expected one super admin, got %d", privileged.SuperAdminCount)
	}
	if privileged.PrivilegedUsersCount != 3 {
		t.Fatalf("expected three privileged users, got %d", privileged.PrivilegedUsersCount)
	}
	if privileged.PrivilegedGuestCount != 1 {
		t.Fatalf("expected one privileged guest, got %d", privileged.PrivilegedGuestCount)
	}
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
