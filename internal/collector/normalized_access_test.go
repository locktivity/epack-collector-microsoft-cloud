package collector

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

const secondSubscriptionID = "bbbbbbbb-1111-2222-3333-cccccccccccc"

// usersGraph answers the user lists with errors, for a tenant whose users
// cannot be read.
type usersGraph struct {
	*fakeGraph
	usersErr  error
	signInErr error
}

func (g usersGraph) Users(ctx context.Context) ([]microsoft.User, error) {
	if g.usersErr != nil {
		return nil, g.usersErr
	}
	return g.fakeGraph.Users(ctx)
}

func (g usersGraph) UsersWithSignInActivity(ctx context.Context) ([]microsoft.User, error) {
	if g.signInErr != nil {
		return nil, g.signInErr
	}
	return g.fakeGraph.UsersWithSignInActivity(ctx)
}

func collectAccess(t *testing.T, cfg Config, level componentsdk.Level) (*AccessPosture, *componentsdk.Recorder) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	cfg.Recorder = rec
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatal(err)
	}
	if result.AzureAccessPosture == nil {
		t.Fatal("expected an access posture")
	}
	return result.AzureAccessPosture, rec
}

func assertPtrBool(t *testing.T, label string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}

func assertPct(t *testing.T, label string, got Percentage, want int) {
	t.Helper()
	if !got.Read || got.Value == nil || *got.Value != want {
		t.Fatalf("%s = %+v, want %d", label, got, want)
	}
}

func assertNullPct(t *testing.T, label string, got Percentage) {
	t.Helper()
	if !got.Read || got.Value != nil {
		t.Fatalf("%s = %+v, want null", label, got)
	}
}

func assertNoGap(t *testing.T, rec *componentsdk.Recorder, path, pointer string) {
	t.Helper()
	for _, gap := range rec.Gaps() {
		if gap.Path == path && gap.Pointer == pointer {
			t.Fatalf("unexpected gap at %s %s: %#v", path, pointer, gap)
		}
	}
}

// Everyone signs in to Azure through Entra ID, so SSO is required.
func TestAccessPostureSignInRequiresSSO(t *testing.T) {
	access, rec := collectAccess(t, testConfig(), componentsdk.LevelTrust)
	assertPtrBool(t, "sso_configured", access.SignIn.SSOConfigured, true)
	assertPtrBool(t, "sso_required", access.SignIn.SSORequired, true)
	assertGap(t, rec, accessPosturePath, "/sign_in/mfa_required", componentsdk.CodeUnsupported)
	assertGap(t, rec, accessPosturePath, "/sign_in/scim_enabled", componentsdk.CodeUnsupported)
	assertGap(t, rec, accessPosturePath, "/root", componentsdk.CodeUnsupported)
	assertGap(t, rec, accessPosturePath, "/connected_apps", componentsdk.CodeNotRead)
	if access.Provider != "azure" || access.SystemType != "cloud" {
		t.Fatalf("provider = %q, system_type = %q", access.Provider, access.SystemType)
	}
}

// u1, u2 and the guest u3 hold roles. The disabled u4 and u9, who is not in
// the user list, do not count.
func TestAccessPostureMembersAreEnabledUsersWithARole(t *testing.T) {
	access, _ := collectAccess(t, testConfig(), componentsdk.LevelAudit)
	members := access.Members
	assertPtrBool(t, "members_present", members.MembersPresent, true)
	assertPtrInt(t, "member_count", members.MemberCount, 3)
	assertPtrBool(t, "external_members_present", members.ExternalMembersPresent, true)
	assertPtrInt(t, "external_member_count", members.ExternalMemberCount, 1)
	assertPtrInt(t, "sso_member_count", members.SSOMemberCount, 3)
	assertPct(t, "sso_coverage_pct", members.SSOCoveragePct, 100)
	assertPtrBool(t, "local_members_present", members.LocalMembersPresent, false)
	assertPtrInt(t, "local_member_count", members.LocalMemberCount, 0)
	assertNullPct(t, "local_mfa_coverage_pct", members.LocalMFACoveragePct)
}

// u2 and u3 last signed in on 2026-01-01, more than 90 days before the run.
// u1 signed in on 2026-05-20.
func TestAccessPostureInactiveMembersOver90Days(t *testing.T) {
	access, _ := collectAccess(t, testConfig(), componentsdk.LevelAudit)
	assertPtrInt(t, "inactive_member_count", access.Members.InactiveMemberCount, 2)
	assertPct(t, "inactive_pct", access.Members.InactivePct, 67)
}

func TestAccessPostureInactiveCutoffIsNinetyDays(t *testing.T) {
	cases := []struct {
		name     string
		lastSeen string
		inactive int
	}{
		{"signed in exactly 90 days ago", "2026-02-25T14:12:09Z", 0},
		{"signed in a second before that", "2026-02-25T14:12:08Z", 1},
		{"never signed in", "", 1},
	}
	enabled := true
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.signInUsers = []microsoft.User{{ID: "u1", AccountEnabled: &enabled, UserType: "Member", SignInActivity: &microsoft.SignInActivity{LastSuccessfulSignInDateTime: tc.lastSeen}}}
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
				fakeRoleAssignment("owner-user", kitSubscriptionID, azureOwnerRoleDefinitionID, "User", "u1"),
			}
			cfg := testConfig()
			cfg.GraphClient, cfg.ARMClient = graph, arm
			access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
			assertPtrInt(t, "inactive_member_count", access.Members.InactiveMemberCount, tc.inactive)
			assertPct(t, "inactive_pct", access.Members.InactivePct, tc.inactive*100)
		})
	}
}

// A member the sign-in activity list does not hold counts as inactive.
func TestAccessPostureMemberMissingFromSignInsIsInactive(t *testing.T) {
	graph := fakeGraphClient()
	graph.signInUsers = graph.signInUsers[:1]
	cfg := testConfig()
	cfg.GraphClient = graph
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrInt(t, "inactive_member_count", access.Members.InactiveMemberCount, 2)
}

func TestAccessPostureInactiveLeftOutWithoutSignInActivity(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code componentsdk.Code
	}{
		{"not licensed", &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitNonPremiumCode}, componentsdk.CodeNotLicensed},
		{"permission denied", &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitRequestDeniedCode}, componentsdk.CodePermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.GraphClient = usersGraph{fakeGraph: fakeGraphClient(), signInErr: tc.err}
			access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
			if access.Members.InactivePct.Read || access.Members.InactiveMemberCount != nil {
				t.Fatalf("inactive values = %+v, want them left out", access.Members)
			}
			assertGap(t, rec, accessPosturePath, "/members/inactive_pct", tc.code)
			assertGap(t, rec, accessPosturePath, "/members/inactive_member_count", tc.code)
			assertPtrInt(t, "member_count", access.Members.MemberCount, 3)
		})
	}
}

// Owner and User Access Administrator holders are admins. Nobody signs in
// without Entra ID, so there are no admins to check for local MFA.
func TestAccessPostureAdmins(t *testing.T) {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
		fakeRoleAssignment("access-admin-u2", kitSubscriptionID, azureUserAccessAdministratorRoleDefinitionID, "User", "u2"))
	cfg := testConfig()
	cfg.ARMClient = arm
	access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
	admins := access.Admins
	assertPtrBool(t, "admins_present", admins.AdminsPresent, true)
	assertPtrInt(t, "admin_count", admins.AdminCount, 2)
	assertPct(t, "admin_share_pct", admins.AdminSharePct, 67)
	assertPtrBool(t, "local_admins_present", admins.LocalAdminsPresent, false)
	assertPtrInt(t, "local_admin_count", admins.LocalAdminCount, 0)
	assertNullPct(t, "local_admin_mfa_coverage_pct", admins.LocalAdminMFACoveragePct)
	assertNoGap(t, rec, accessPosturePath, "/admins/local_admin_mfa_coverage_pct")
}

func TestAccessPostureDisabledOwnerIsNotAnAdmin(t *testing.T) {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
		fakeRoleAssignment("owner-disabled", kitSubscriptionID, azureOwnerRoleDefinitionID, "User", "u4"),
		fakeRoleAssignment("reader-user", kitSubscriptionID, azureReaderRoleDefinitionID, "User", "u2"),
	}
	cfg := testConfig()
	cfg.ARMClient = arm
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrBool(t, "admins_present", access.Admins.AdminsPresent, false)
	assertPtrInt(t, "admin_count", access.Admins.AdminCount, 0)
	assertPct(t, "admin_share_pct", access.Admins.AdminSharePct, 0)
}

// sp1 is an Owner and sp2 a Reader. Every credential of theirs, and of their
// applications, ends within two years. Each has an active credential that
// became valid more than 90 days before the run.
func TestAccessPostureCredentials(t *testing.T) {
	access, rec := collectAccess(t, testConfig(), componentsdk.LevelAudit)
	credentials := access.Credentials
	assertPtrBool(t, "credentials_present", credentials.CredentialsPresent, true)
	assertPtrInt(t, "credential_count", credentials.CredentialCount, 2)
	assertPtrInt(t, "never_expiring_credential_count", credentials.NeverExpiringCredentialCount, 0)
	assertPct(t, "never_expiring_pct", credentials.NeverExpiringPct, 0)
	assertPtrInt(t, "write_access_credential_count", credentials.WriteAccessCredentialCount, 1)
	assertPct(t, "write_access_pct", credentials.WriteAccessPct, 50)
	assertPtrInt(t, "rotation_overdue_credential_count", credentials.RotationOverdueCredentialCount, 2)
	assertPct(t, "rotation_overdue_pct", credentials.RotationOverduePct, 100)
	assertNoGap(t, rec, accessPosturePath, "/credentials/rotation_overdue_pct")
	// The Owner sp1 may hold full access, and its sign-in location limits
	// are not read.
	for _, pointer := range []string{
		"/credentials/unused_pct", "/credentials/unused_credential_count",
		"/credentials/unrestricted_pct", "/credentials/unrestricted_credential_count",
	} {
		assertGap(t, rec, accessPosturePath, pointer, componentsdk.CodeNotRead)
	}
	if credentials.UnusedPct.Read || credentials.UnrestrictedPct.Read {
		t.Fatalf("credentials = %+v, want the unused and unrestricted values left out", credentials)
	}
}

// sp1 belongs to app1. Each case gives sp1 or app1 its only credential, and
// sp2 stays overdue through its application's certificate.
func TestAccessPostureRotationOverdue(t *testing.T) {
	cases := []struct {
		name          string
		onApplication bool
		certificate   bool
		start, end    string
		overdue       int
	}{
		{"secret added 91 days before the run", false, false, "2026-02-24T14:12:09Z", "2027-01-01T00:00:00Z", 2},
		{"secret added exactly 90 days before the run", false, false, "2026-02-25T14:12:09Z", "2027-01-01T00:00:00Z", 1},
		{"secret added last month", false, false, "2026-04-26T00:00:00Z", "2027-01-01T00:00:00Z", 1},
		{"old secret that expired", false, false, "2024-01-01T00:00:00Z", "2026-05-01T00:00:00Z", 1},
		{"old secret with no end date", false, false, "2024-01-01T00:00:00Z", "", 2},
		{"secret with no start date", false, false, "", "2027-01-01T00:00:00Z", 1},
		{"old application secret", true, false, "2024-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 2},
		{"old application certificate", true, true, "2024-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			graph.servicePrincipals[0].PasswordCredentials = nil
			graph.servicePrincipals[0].KeyCredentials = nil
			graph.applications[0].PasswordCredentials = nil
			graph.applications[0].KeyCredentials = nil
			switch {
			case tc.certificate:
				graph.applications[0].KeyCredentials = []microsoft.KeyCredential{{KeyID: "added", StartDateTime: tc.start, EndDateTime: tc.end}}
			case tc.onApplication:
				graph.applications[0].PasswordCredentials = []microsoft.PasswordCredential{{KeyID: "added", StartDateTime: tc.start, EndDateTime: tc.end}}
			default:
				graph.servicePrincipals[0].PasswordCredentials = []microsoft.PasswordCredential{{KeyID: "added", StartDateTime: tc.start, EndDateTime: tc.end}}
			}
			cfg := testConfig()
			cfg.GraphClient = graph
			access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
			assertPtrInt(t, "rotation_overdue_credential_count", access.Credentials.RotationOverdueCredentialCount, tc.overdue)
			assertPct(t, "rotation_overdue_pct", access.Credentials.RotationOverduePct, tc.overdue*50)
		})
	}
}

// A managed identity has no client secret or certificate in Entra ID, so it
// is never overdue. The application list is not needed for it.
func TestAccessPostureManagedIdentityIsNotOverdue(t *testing.T) {
	graph := fakeGraphClient()
	graph.applicationsErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitRequestDeniedCode}
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
		fakeRoleAssignment("identity", kitSubscriptionID, azureContributorRoleDefinitionID, "ServicePrincipal", "mi1"),
	}
	cfg := testConfig()
	cfg.GraphClient, cfg.ARMClient = graph, arm
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrInt(t, "rotation_overdue_credential_count", access.Credentials.RotationOverdueCredentialCount, 0)
	assertPct(t, "rotation_overdue_pct", access.Credentials.RotationOverduePct, 0)
}

// When the credentials of a service principal with a role cannot be read,
// the rotation values are left out with that read's gap.
func TestAccessPostureRotationLeftOutWhenCredentialsAreUnread(t *testing.T) {
	graph := fakeGraphClient()
	graph.applicationsErr = &microsoft.APIError{StatusCode: http.StatusServiceUnavailable}
	cfg := testConfig()
	cfg.GraphClient = graph
	access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
	if access.Credentials.RotationOverdueCredentialCount != nil || access.Credentials.RotationOverduePct.Read {
		t.Fatalf("credentials = %+v, want the rotation values left out", access.Credentials)
	}
	assertGap(t, rec, accessPosturePath, "/credentials/rotation_overdue_pct", componentsdk.CodeVendorError)
	assertGap(t, rec, accessPosturePath, "/credentials/rotation_overdue_credential_count", componentsdk.CodeVendorError)
}

// A service principal with only read-only roles is narrower than full
// access. Any other role may be a custom role with full access, and custom
// role definitions are not read.
func TestAccessPostureUnrestrictedByRole(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		read  bool
	}{
		{"Reader", []string{azureReaderRoleDefinitionID}, true},
		{"Security Reader and Monitoring Reader", []string{"39bc4728-0917-49c7-9d2c-d95423bc2eb4", "43d0d8ad-25c7-4714-9337-8ba259a9fe05"}, true},
		{"Owner", []string{azureOwnerRoleDefinitionID}, false},
		{"Contributor", []string{azureContributorRoleDefinitionID}, false},
		{"Reader and a custom role", []string{azureReaderRoleDefinitionID, "11111111-0000-0000-0000-000000000000"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = nil
			for i, role := range tc.roles {
				arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
					fakeRoleAssignment("sp-role-"+string(rune('a'+i)), kitSubscriptionID, role, "ServicePrincipal", "sp1"))
			}
			cfg := testConfig()
			cfg.ARMClient = arm
			access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
			if !tc.read {
				if access.Credentials.UnrestrictedCredentialCount != nil || access.Credentials.UnrestrictedPct.Read {
					t.Fatalf("credentials = %+v, want the unrestricted values left out", access.Credentials)
				}
				assertGap(t, rec, accessPosturePath, "/credentials/unrestricted_pct", componentsdk.CodeNotRead)
				assertGap(t, rec, accessPosturePath, "/credentials/unrestricted_credential_count", componentsdk.CodeNotRead)
				return
			}
			assertPtrInt(t, "unrestricted_credential_count", access.Credentials.UnrestrictedCredentialCount, 0)
			assertPct(t, "unrestricted_pct", access.Credentials.UnrestrictedPct, 0)
			assertNoGap(t, rec, accessPosturePath, "/credentials/unrestricted_pct")
		})
	}
}

func TestAccessPostureWriteAccessByRole(t *testing.T) {
	cases := []struct {
		name   string
		roles  []string
		writer bool
	}{
		{"Reader", []string{azureReaderRoleDefinitionID}, false},
		{"Security Reader and Monitoring Reader", []string{"39bc4728-0917-49c7-9d2c-d95423bc2eb4", "43d0d8ad-25c7-4714-9337-8ba259a9fe05"}, false},
		{"Reader in upper case", []string{strings.ToUpper(azureReaderRoleDefinitionID)}, false},
		{"Contributor", []string{azureContributorRoleDefinitionID}, true},
		{"Reader and a custom role", []string{azureReaderRoleDefinitionID, "11111111-0000-0000-0000-000000000000"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = nil
			for i, role := range tc.roles {
				arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
					fakeRoleAssignment("sp-role-"+string(rune('a'+i)), kitSubscriptionID, role, "ServicePrincipal", "sp1"))
			}
			cfg := testConfig()
			cfg.ARMClient = arm
			access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
			assertPtrInt(t, "credential_count", access.Credentials.CredentialCount, 1)
			want := 0
			if tc.writer {
				want = 1
			}
			assertPtrInt(t, "write_access_credential_count", access.Credentials.WriteAccessCredentialCount, want)
		})
	}
}

// A disabled service principal cannot get a token, so its role grants no
// write access. sp3 is disabled and sp1 is enabled.
func TestAccessPostureDisabledServicePrincipalHasNoWriteAccess(t *testing.T) {
	cases := []struct {
		name, principal string
		want            int
	}{
		{"disabled", "sp3", 0},
		{"enabled", "sp1", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
				fakeRoleAssignment("contributor", kitSubscriptionID, azureContributorRoleDefinitionID, "ServicePrincipal", tc.principal),
			}
			cfg := testConfig()
			cfg.ARMClient = arm
			access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
			assertPtrInt(t, "credential_count", access.Credentials.CredentialCount, 1)
			assertPtrInt(t, "write_access_credential_count", access.Credentials.WriteAccessCredentialCount, tc.want)
			assertPct(t, "write_access_pct", access.Credentials.WriteAccessPct, tc.want*100)
		})
	}
}

// With no role assignments, every percentage is null over an empty
// population and every present flag is false.
func TestAccessPostureEmptySubscription(t *testing.T) {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = nil
	cfg := testConfig()
	cfg.ARMClient = arm
	access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrBool(t, "members_present", access.Members.MembersPresent, false)
	assertNullPct(t, "inactive_pct", access.Members.InactivePct)
	assertNullPct(t, "sso_coverage_pct", access.Members.SSOCoveragePct)
	assertPtrBool(t, "admins_present", access.Admins.AdminsPresent, false)
	assertNullPct(t, "admin_share_pct", access.Admins.AdminSharePct)
	assertPtrBool(t, "credentials_present", access.Credentials.CredentialsPresent, false)
	for label, pct := range map[string]Percentage{
		"never_expiring_pct":   access.Credentials.NeverExpiringPct,
		"write_access_pct":     access.Credentials.WriteAccessPct,
		"unused_pct":           access.Credentials.UnusedPct,
		"unrestricted_pct":     access.Credentials.UnrestrictedPct,
		"rotation_overdue_pct": access.Credentials.RotationOverduePct,
	} {
		assertNullPct(t, label, pct)
	}
	assertNoGap(t, rec, accessPosturePath, "/credentials/unused_pct")
}

// A role assigned to a group is held by its members, which are not read.
// The values over everyone with a role are then left out.
func TestAccessPostureGroupHeldRoles(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		kind       string
		adminsRead bool
	}{
		{"Reader held by a group", azureReaderRoleDefinitionID, "Group", true},
		{"Owner held by a group", azureOwnerRoleDefinitionID, "Group", false},
		{"Owner held by a group from another tenant", azureOwnerRoleDefinitionID, "ForeignGroup", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
				fakeRoleAssignment("group", kitSubscriptionID, tc.role, tc.kind, "g1"))
			cfg := testConfig()
			cfg.ARMClient = arm
			access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)

			assertPtrBool(t, "members_present", access.Members.MembersPresent, true)
			if access.Members.MemberCount != nil || access.Members.InactivePct.Read {
				t.Fatalf("members = %+v, want the counts and percentages left out", access.Members)
			}
			assertGap(t, rec, accessPosturePath, "/members/member_count", componentsdk.CodeNotRead)
			assertGap(t, rec, accessPosturePath, "/members/inactive_pct", componentsdk.CodeNotRead)
			assertGap(t, rec, accessPosturePath, "/admins/admin_share_pct", componentsdk.CodeNotRead)
			assertGap(t, rec, accessPosturePath, "/credentials/write_access_pct", componentsdk.CodeNotRead)
			assertPtrBool(t, "credentials_present", access.Credentials.CredentialsPresent, true)
			assertPtrBool(t, "admins_present", access.Admins.AdminsPresent, true)
			if tc.adminsRead {
				assertPtrInt(t, "admin_count", access.Admins.AdminCount, 1)
			} else {
				assertGap(t, rec, accessPosturePath, "/admins/admin_count", componentsdk.CodeNotRead)
			}
		})
	}
}

// The present flags are unknown when only a group holds a role.
func TestAccessPostureGroupOnlyLeavesPresenceUnknown(t *testing.T) {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
		fakeRoleAssignment("group", kitSubscriptionID, azureContributorRoleDefinitionID, "Group", "g1"),
	}
	cfg := testConfig()
	cfg.ARMClient = arm
	access, rec := collectAccess(t, cfg, componentsdk.LevelTrust)
	if access.Members.MembersPresent != nil || access.Credentials != nil {
		t.Fatalf("members_present = %v, credentials = %+v, want both left out", access.Members.MembersPresent, access.Credentials)
	}
	assertGap(t, rec, accessPosturePath, "/members/members_present", componentsdk.CodeNotRead)
	assertGap(t, rec, accessPosturePath, "/credentials", componentsdk.CodeNotRead)
	assertPtrBool(t, "admins_present", access.Admins.AdminsPresent, false)
}

// Role assignments also list agent identities and devices as principal
// types. They are not counted as members or service principals, so a role
// one of them holds leaves the present flags unknown.
func TestAccessPostureOtherPrincipalTypesLeavePresenceUnknown(t *testing.T) {
	cases := []struct {
		name, principalType, role, pointer string
		present                            func(*AccessPosture) *bool
	}{
		{"agent service principal with Contributor", "AgentServicePrincipal", azureContributorRoleDefinitionID, "/credentials",
			func(a *AccessPosture) *bool {
				if a.Credentials == nil {
					return nil
				}
				return a.Credentials.CredentialsPresent
			}},
		{"agent user with Owner", "AgentUser", azureOwnerRoleDefinitionID, "/admins/admins_present",
			func(a *AccessPosture) *bool { return a.Admins.AdminsPresent }},
		{"agent user with Reader", "AgentUser", azureReaderRoleDefinitionID, "/members/members_present",
			func(a *AccessPosture) *bool { return a.Members.MembersPresent }},
		{"device with Reader", "Device", azureReaderRoleDefinitionID, "/members/members_present",
			func(a *AccessPosture) *bool { return a.Members.MembersPresent }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
				fakeRoleAssignment("other", kitSubscriptionID, tc.role, tc.principalType, "agent1"),
			}
			cfg := testConfig()
			cfg.ARMClient = arm
			access, rec := collectAccess(t, cfg, componentsdk.LevelTrust)
			if got := tc.present(access); got != nil {
				t.Fatalf("%s = %v, want it left out", tc.pointer, *got)
			}
			assertGap(t, rec, accessPosturePath, tc.pointer, componentsdk.CodeNotRead)
		})
	}

	t.Run("no principal type is a user", func(t *testing.T) {
		arm := fakeARMClient()
		arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
			fakeRoleAssignment("owner", kitSubscriptionID, azureOwnerRoleDefinitionID, "", "u1"),
		}
		cfg := testConfig()
		cfg.ARMClient = arm
		access, _ := collectAccess(t, cfg, componentsdk.LevelTrust)
		assertPtrBool(t, "members_present", access.Members.MembersPresent, true)
		assertPtrBool(t, "admins_present", access.Admins.AdminsPresent, true)
	})
}

func TestAccessPostureUserListDenied(t *testing.T) {
	cfg := testConfig()
	cfg.GraphClient = usersGraph{fakeGraph: fakeGraphClient(), usersErr: &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitRequestDeniedCode}}
	access, rec := collectAccess(t, cfg, componentsdk.LevelTrust)
	if access.Members.MembersPresent != nil || access.Admins.AdminsPresent != nil {
		t.Fatalf("members = %+v, admins = %+v, want presence left out", access.Members, access.Admins)
	}
	assertGap(t, rec, accessPosturePath, "/members/members_present", componentsdk.CodePermissionDenied)
	assertGap(t, rec, accessPosturePath, "/admins/admins_present", componentsdk.CodePermissionDenied)
	// Service principals need no user lookup.
	assertPtrBool(t, "credentials_present", access.Credentials.CredentialsPresent, true)
	assertPct(t, "write_access_pct", access.Credentials.WriteAccessPct, 50)
}

// The totals count each principal once across subscriptions.
func TestAccessPostureTotalsAcrossSubscriptions(t *testing.T) {
	arm := fakeARMClient()
	arm.subscriptions[secondSubscriptionID] = &microsoft.Subscription{SubscriptionID: secondSubscriptionID, State: "Enabled"}
	arm.roleAssignments[secondSubscriptionID] = []microsoft.ARMRoleAssignment{
		fakeRoleAssignment("owner-u1", secondSubscriptionID, azureOwnerRoleDefinitionID, "User", "u1"),
		fakeRoleAssignment("contributor-u2", secondSubscriptionID, azureContributorRoleDefinitionID, "User", "u2"),
		fakeRoleAssignment("contributor-sp2", secondSubscriptionID, azureContributorRoleDefinitionID, "ServicePrincipal", "sp2"),
	}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.SubscriptionIDs = []string{kitSubscriptionID, secondSubscriptionID}
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)

	assertPtrInt(t, "member_count", access.Members.MemberCount, 3)
	assertPtrInt(t, "admin_count", access.Admins.AdminCount, 1)
	assertPtrInt(t, "credential_count", access.Credentials.CredentialCount, 2)
	// sp2 is a Reader in the first subscription and a Contributor in the
	// second.
	assertPtrInt(t, "write_access_credential_count", access.Credentials.WriteAccessCredentialCount, 2)
	if len(access.Scopes) != 2 {
		t.Fatalf("scopes = %d, want 2", len(access.Scopes))
	}
	second := access.Scopes[1]
	if second.ID != secondSubscriptionID || second.Kind != "subscription" {
		t.Fatalf("second scope = %q %q", second.ID, second.Kind)
	}
	assertPtrInt(t, "second scope member_count", second.Members.MemberCount, 2)
	assertPtrInt(t, "second scope credential_count", second.Credentials.CredentialCount, 1)
}

// When a subscription cannot be read, the totals' counts are left out and
// its scope holds only its ID and sign_in.
func TestAccessPostureUnreadableSubscription(t *testing.T) {
	arm := fakeARMClient()
	arm.subscriptionErrs[secondSubscriptionID] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/subscriptions/" + secondSubscriptionID}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.SubscriptionIDs = []string{kitSubscriptionID, secondSubscriptionID}
	access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)

	assertPtrBool(t, "members_present", access.Members.MembersPresent, true)
	if access.Members.MemberCount != nil || access.Credentials.CredentialCount != nil {
		t.Fatalf("totals = %+v %+v, want the counts left out", access.Members, access.Credentials)
	}
	assertGap(t, rec, accessPosturePath, "/members/member_count", componentsdk.CodePermissionDenied)
	assertGap(t, rec, accessPosturePath, "/credentials/write_access_pct", componentsdk.CodePermissionDenied)
	unreadable := access.Scopes[1]
	if unreadable.ID != secondSubscriptionID || unreadable.Members != nil || unreadable.Admins != nil || unreadable.Credentials != nil {
		t.Fatalf("unreadable scope = %+v, want only its ID and sign_in", unreadable)
	}
	assertGap(t, rec, accessPosturePath, "/scopes/1/members", componentsdk.CodePermissionDenied)
	assertNoGap(t, rec, accessPosturePath, "/scopes/1/sign_in")
	assertPtrInt(t, "first scope member_count", access.Scopes[0].Members.MemberCount, 3)
	assertSignInRollsUp(t, access)
}

// assertSignInRollsUp checks each top-level sign_in value against the
// scopes'. It is false when any scope's is false, null when any other is
// null, and true otherwise.
func assertSignInRollsUp(t *testing.T, access *AccessPosture) {
	t.Helper()
	rollUp := func(value func(*AccessSignIn) *bool) *bool {
		var unknown bool
		for _, scope := range access.Scopes {
			var v *bool
			if scope.SignIn != nil {
				v = value(scope.SignIn)
			}
			switch {
			case v == nil:
				unknown = true
			case !*v:
				return boolPtr(false)
			}
		}
		if unknown {
			return nil
		}
		return boolPtr(true)
	}
	for name, value := range map[string]func(*AccessSignIn) *bool{
		"sso_configured": func(s *AccessSignIn) *bool { return s.SSOConfigured },
		"sso_required":   func(s *AccessSignIn) *bool { return s.SSORequired },
	} {
		want := rollUp(value)
		var got *bool
		if access.SignIn != nil {
			got = value(access.SignIn)
		}
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Fatalf("sign_in.%s = %v, want %v from the scopes", name, got, want)
		}
	}
}

// The top-level sign_in values roll up the scopes' when every subscription
// is read.
func TestAccessPostureSignInRollsUpTheScopes(t *testing.T) {
	arm := fakeARMClient()
	arm.subscriptions[secondSubscriptionID] = &microsoft.Subscription{SubscriptionID: secondSubscriptionID, State: "Enabled"}
	arm.roleAssignments[secondSubscriptionID] = nil
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.SubscriptionIDs = []string{kitSubscriptionID, secondSubscriptionID}
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	if len(access.Scopes) != 2 {
		t.Fatalf("scopes = %d, want 2", len(access.Scopes))
	}
	assertSignInRollsUp(t, access)
	assertPtrBool(t, "sso_required", access.SignIn.SSORequired, true)
}

// Below the audit level, the access posture has no counts and no scopes, and
// no gaps on counts.
func TestAccessPostureTrustLeavesOutCountsAndScopes(t *testing.T) {
	access, rec := collectAccess(t, testConfig(), componentsdk.LevelTrust)
	if access.Scopes != nil {
		t.Fatalf("scopes = %+v, want none at trust", access.Scopes)
	}
	if access.Members.MemberCount != nil || access.Admins.AdminCount != nil || access.Credentials.CredentialCount != nil ||
		access.Members.LocalMemberCount != nil || access.Credentials.NeverExpiringCredentialCount != nil {
		t.Fatalf("counts written at trust: %+v %+v %+v", access.Members, access.Admins, access.Credentials)
	}
	assertPct(t, "inactive_pct", access.Members.InactivePct, 67)
	assertPct(t, "never_expiring_pct", access.Credentials.NeverExpiringPct, 0)
	for _, gap := range rec.Gaps() {
		if gap.Path == accessPosturePath && (strings.HasSuffix(gap.Pointer, "_count") || strings.HasPrefix(gap.Pointer, "/scopes")) {
			t.Fatalf("gap on an audit-level value at trust: %#v", gap)
		}
	}
}

func TestAccessPostureRoleAssignmentsDenied(t *testing.T) {
	arm := fakeARMClient()
	arm.roleAssignmentErrs[kitSubscriptionID] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Code: "AuthorizationFailed"}
	cfg := testConfig()
	cfg.ARMClient = arm
	access, rec := collectAccess(t, cfg, componentsdk.LevelTrust)
	if access.Members.MembersPresent != nil || access.Admins.AdminsPresent != nil || access.Credentials != nil {
		t.Fatalf("access = %+v, want the role holders left out", access.AccessSections)
	}
	assertGap(t, rec, accessPosturePath, "/members/members_present", componentsdk.CodePermissionDenied)
	assertGap(t, rec, accessPosturePath, "/credentials", componentsdk.CodePermissionDenied)
	assertPtrBool(t, "sso_required", access.SignIn.SSORequired, true)
}

// sp1 belongs to app1 and sp2 to app2. Each case adds one credential, on the
// application or on the service principal object.
func TestAccessPostureNeverExpiringCredentials(t *testing.T) {
	cases := []struct {
		name          string
		onApplication bool
		end           string
		neverExpiring int
	}{
		{"application secret from the former Never option", true, "2299-12-31T00:00:00Z", 1},
		{"application secret ending 51 years after the run", true, "2077-06-01T00:00:00Z", 1},
		{"application secret ending 49 years after the run", true, "2075-06-01T00:00:00Z", 0},
		{"service principal secret with no end date", false, "", 1},
		{"service principal secret that expired", false, "2026-01-01T00:00:00Z", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			credential := microsoft.PasswordCredential{KeyID: "added", StartDateTime: "2025-01-01T00:00:00Z", EndDateTime: tc.end}
			if tc.onApplication {
				graph.applications[0].PasswordCredentials = append(graph.applications[0].PasswordCredentials, credential)
			} else {
				graph.servicePrincipals[0].PasswordCredentials = append(graph.servicePrincipals[0].PasswordCredentials, credential)
			}
			cfg := testConfig()
			cfg.GraphClient = graph
			access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
			assertPtrInt(t, "never_expiring_credential_count", access.Credentials.NeverExpiringCredentialCount, tc.neverExpiring)
			assertPct(t, "never_expiring_pct", access.Credentials.NeverExpiringPct, tc.neverExpiring*50)
		})
	}
}

// A certificate counts the same way as a secret.
func TestAccessPostureNeverExpiringCertificate(t *testing.T) {
	graph := fakeGraphClient()
	graph.applications[1].KeyCredentials = append(graph.applications[1].KeyCredentials,
		microsoft.KeyCredential{KeyID: "cert-never", StartDateTime: "2020-01-01T00:00:00Z", EndDateTime: "2299-12-31T00:00:00Z"})
	cfg := testConfig()
	cfg.GraphClient = graph
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrInt(t, "never_expiring_credential_count", access.Credentials.NeverExpiringCredentialCount, 1)
}

// A managed identity is not in the Application service principal list and
// has no client secret or certificate to check. An application registered
// in another tenant leaves only the service principal's own credentials.
func TestAccessPostureServicePrincipalsWithoutApplicationCredentials(t *testing.T) {
	graph := fakeGraphClient()
	graph.servicePrincipals[0].AppID = "aaaaaaaa-0000-4000-8000-0000000000ff"
	graph.applications[0].PasswordCredentials = append(graph.applications[0].PasswordCredentials,
		microsoft.PasswordCredential{KeyID: "app-p-never", EndDateTime: "2299-12-31T00:00:00Z"})
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
		fakeRoleAssignment("identity", kitSubscriptionID, azureReaderRoleDefinitionID, "ServicePrincipal", "mi1"))
	cfg := testConfig()
	cfg.GraphClient, cfg.ARMClient = graph, arm
	access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrInt(t, "credential_count", access.Credentials.CredentialCount, 3)
	assertPtrInt(t, "never_expiring_credential_count", access.Credentials.NeverExpiringCredentialCount, 0)
	assertPct(t, "never_expiring_pct", access.Credentials.NeverExpiringPct, 0)
	assertNoGap(t, rec, accessPosturePath, "/credentials/never_expiring_pct")
}

// When the credentials of a service principal with a role cannot be read,
// the never-expiring values are left out with that read's gap. Whether a
// service principal is disabled comes from the service principal list.
// Without that list the write access values are left out too.
func TestAccessPostureNeverExpiringLeftOutWhenCredentialsAreUnread(t *testing.T) {
	denied := &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitRequestDeniedCode}
	down := &microsoft.APIError{StatusCode: http.StatusServiceUnavailable}
	cases := []struct {
		name            string
		graph           func(*fakeGraph)
		code            componentsdk.Code
		writeAccessRead bool
	}{
		{"application list denied", func(g *fakeGraph) { g.applicationsErr = denied }, componentsdk.CodePermissionDenied, true},
		{"application list down", func(g *fakeGraph) { g.applicationsErr = down }, componentsdk.CodeVendorError, true},
		{"service principal list denied", func(g *fakeGraph) { g.servicePrincipalsErr = denied }, componentsdk.CodePermissionDenied, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := fakeGraphClient()
			tc.graph(graph)
			cfg := testConfig()
			cfg.GraphClient = graph
			access, rec := collectAccess(t, cfg, componentsdk.LevelAudit)
			if access.Credentials.NeverExpiringCredentialCount != nil || access.Credentials.NeverExpiringPct.Read {
				t.Fatalf("credentials = %+v, want the never-expiring values left out", access.Credentials)
			}
			assertGap(t, rec, accessPosturePath, "/credentials/never_expiring_pct", tc.code)
			assertGap(t, rec, accessPosturePath, "/credentials/never_expiring_credential_count", tc.code)
			assertPtrInt(t, "credential_count", access.Credentials.CredentialCount, 2)
			if tc.writeAccessRead {
				assertPct(t, "write_access_pct", access.Credentials.WriteAccessPct, 50)
				return
			}
			if access.Credentials.WriteAccessCredentialCount != nil || access.Credentials.WriteAccessPct.Read {
				t.Fatalf("credentials = %+v, want the write access values left out", access.Credentials)
			}
			assertGap(t, rec, accessPosturePath, "/credentials/write_access_pct", tc.code)
			assertGap(t, rec, accessPosturePath, "/credentials/write_access_credential_count", tc.code)
		})
	}
}

// Only managed identities hold roles, so the application list is not needed.
func TestAccessPostureManagedIdentitiesNeedNoApplications(t *testing.T) {
	graph := fakeGraphClient()
	graph.applicationsErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Code: kitRequestDeniedCode}
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = []microsoft.ARMRoleAssignment{
		fakeRoleAssignment("identity", kitSubscriptionID, azureContributorRoleDefinitionID, "ServicePrincipal", "mi1"),
	}
	cfg := testConfig()
	cfg.GraphClient, cfg.ARMClient = graph, arm
	access, _ := collectAccess(t, cfg, componentsdk.LevelAudit)
	assertPtrInt(t, "never_expiring_credential_count", access.Credentials.NeverExpiringCredentialCount, 0)
	assertPct(t, "never_expiring_pct", access.Credentials.NeverExpiringPct, 0)
}
