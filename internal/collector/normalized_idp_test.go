package collector

import (
	"testing"

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
	if got := idp.UserSecurity.InactivePct.Value; got == nil || *got != 67 {
		t.Fatalf("unexpected inactive pct: %#v", idp.UserSecurity)
	}
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
