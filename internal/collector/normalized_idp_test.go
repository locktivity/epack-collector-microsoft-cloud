package collector

import (
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
