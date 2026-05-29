package collector

import "testing"

func TestNormalizedIdpComplete(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	idp := artifact.ToIDPPosture()
	if idp == nil {
		t.Fatal("expected normalized artifact")
	}
	if idp.UserSecurity.MFAPhishingResistantPct == nil || *idp.UserSecurity.MFAPhishingResistantPct != 50 {
		t.Fatalf("unexpected phishing-resistant MFA: %#v", idp.UserSecurity)
	}
	if idp.UserSecurity.InactivePct == nil || *idp.UserSecurity.InactivePct != 67 {
		t.Fatalf("unexpected inactive pct: %#v", idp.UserSecurity)
	}
	if idp.AppSecurity == nil || idp.AppSecurity.SSOCoveragePct == nil || *idp.AppSecurity.SSOCoveragePct != 100 {
		t.Fatalf("unexpected app security: %#v", idp.AppSecurity)
	}
	if idp.PrivilegedAccess == nil || idp.PrivilegedAccess.PrivilegedUsersCount == nil || *idp.PrivilegedAccess.PrivilegedUsersCount != 3 {
		t.Fatalf("unexpected privileged access: %#v", idp.PrivilegedAccess)
	}
	if idp.PrivilegedAccess.SuperAdminCount == nil || *idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Fatalf("unexpected super admin count: %#v", idp.PrivilegedAccess)
	}
	if idp.PrivilegedAccess.PrivilegedMFACoveragePct == nil || *idp.PrivilegedAccess.PrivilegedMFACoveragePct != 67 {
		t.Fatalf("unexpected privileged MFA coverage: %#v", idp.PrivilegedAccess)
	}
	if idp.Lifecycle == nil || idp.Lifecycle.SuspendedPct == nil || *idp.Lifecycle.SuspendedPct != 25 {
		t.Fatalf("unexpected lifecycle: %#v", idp.Lifecycle)
	}
}
