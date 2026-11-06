package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// Each subscription's deprecated iam block holds the tenant's MFA coverage
// and whether every Global Administrator is registered for MFA.
func TestAddDeprecatedIAMWritesTheTenantsValuesInEachSubscription(t *testing.T) {
	c := &Collector{gaps: newGapLog(&componentsdk.Recorder{})}
	posture := &CloudPosture{Accounts: []CloudPostureAccount{{}, {}}}
	entra := &EntraArtifact{
		Posture:          Posture{MFACoverage: intPtr(80)},
		PrivilegedAccess: &PrivilegedAccess{globalAdminsMFA: boolPtr(false)},
	}

	c.addDeprecatedIAM(posture, entra)

	for i, account := range posture.Accounts {
		iam := account.IAM
		if iam == nil || iam.MFACoveragePct == nil || *iam.MFACoveragePct != 80 ||
			iam.RootMFAEnabled == nil || *iam.RootMFAEnabled || iam.RootAccessProtected == nil || *iam.RootAccessProtected {
			t.Errorf("account %d iam = %+v, want 80%% coverage and both root values false", i, iam)
		}
	}
}

// A Global Administrator value that was not read is left out with the gap
// of that read, and the coverage is still written.
func TestAddDeprecatedIAMLeavesOutAnUnreadGlobalAdministratorValue(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := &Collector{gaps: newGapLog(rec)}
	posture := &CloudPosture{Accounts: []CloudPostureAccount{{}}}
	entra := &EntraArtifact{
		Posture:          Posture{MFACoverage: intPtr(80)},
		PrivilegedAccess: &PrivilegedAccess{globalAdminsMFAUnread: notRead(groupRoleMembersUnread)},
	}

	c.addDeprecatedIAM(posture, entra)

	iam := posture.Accounts[0].IAM
	if iam == nil || iam.RootMFAEnabled != nil || iam.RootAccessProtected != nil {
		t.Fatalf("iam = %+v, want the root values left out", iam)
	}
	for _, pointer := range []string{"/accounts/0/iam/root_mfa_enabled", "/accounts/0/iam/root_access_protected"} {
		found := false
		for _, g := range rec.Gaps() {
			if g.Path == cloudPosturePath && g.Pointer == pointer && g.Code == componentsdk.CodeNotRead {
				found = true
			}
		}
		if !found {
			t.Errorf("%s has no not_read gap: %+v", pointer, rec.Gaps())
		}
	}
}

func TestGlobalAdminsMFARegistered(t *testing.T) {
	registrations := []microsoft.UserRegistrationDetail{{ID: "a", IsMFARegistered: true}, {ID: "b"}}
	for _, tc := range []struct {
		name   string
		admins map[string]struct{}
		want   bool
	}{
		{"every admin registered", map[string]struct{}{"a": {}}, true},
		{"one admin not registered", map[string]struct{}{"a": {}, "b": {}}, false},
		{"an admin missing from the report", map[string]struct{}{"c": {}}, false},
		{"no admins", map[string]struct{}{}, true},
	} {
		if got := globalAdminsMFARegistered(tc.admins, registrations); got == nil || *got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
