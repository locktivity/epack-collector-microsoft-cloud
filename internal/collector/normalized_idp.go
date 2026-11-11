package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// IDPPosture is the normalized evidencepack/idp-posture@v1 artifact. A value
// the Entra artifact left out is absent here too, with the same gap. A
// percentage over an empty population is null. The counts behind the
// percentages are written from the audit level, as the schema marks them,
// and the present flags at every level.
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     *IDPPostureUserSecurity     `json:"user_security,omitempty"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
}

// Percentage is a normalized percentage. It is left out when Read is false.
// Otherwise it is written as Value, which is nil over an empty population.
type Percentage struct {
	Value *int
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p Percentage) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p Percentage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

// IDPPostureUserSecurity counts the tenant's enabled member users, guests
// left out. The MFA percentages cover the members the registration report
// lists, so the MFA counts are written only when it lists every enabled
// member. Entra has no data on locked-out users or password strength, and
// those values are left out with an unsupported gap.
type IDPPostureUserSecurity struct {
	UsersPresent               *bool      `json:"users_present,omitempty"`
	UserCount                  *int       `json:"user_count,omitempty"`
	MFAUserCount               *int       `json:"mfa_user_count,omitempty"`
	PhishingResistantUserCount *int       `json:"phishing_resistant_user_count,omitempty"`
	MFACoveragePct             Percentage `json:"mfa_coverage_pct,omitzero"`
	MFAPhishingResistantPct    Percentage `json:"mfa_phishing_resistant_pct,omitzero"`
	InactiveUserCount          *int       `json:"inactive_user_count,omitempty"`
	InactivePct                Percentage `json:"inactive_pct,omitzero"`
}

// IDPPostureAppSecurity counts the tenant's enabled enterprise apps. The
// collector does not read provisioning. Those percentages are null when the
// tenant has no enabled enterprise apps, and absent otherwise.
type IDPPostureAppSecurity struct {
	AppsPresent              *bool      `json:"apps_present,omitempty"`
	AppCount                 *int       `json:"app_count,omitempty"`
	SSOAppCount              *int       `json:"sso_app_count,omitempty"`
	SSOCoveragePct           Percentage `json:"sso_coverage_pct,omitzero"`
	ProvisioningEnabledPct   Percentage `json:"provisioning_enabled_pct,omitzero"`
	DeprovisioningEnabledPct Percentage `json:"deprovisioning_enabled_pct,omitzero"`
}

type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersPresent               *bool      `json:"privileged_users_present,omitempty"`
	PrivilegedUsersCount                 *int       `json:"privileged_users_count,omitempty"`
	SuperAdminCount                      *int       `json:"super_admin_count,omitempty"`
	PrivilegedMFAUserCount               *int       `json:"privileged_mfa_user_count,omitempty"`
	PrivilegedPhishingResistantUserCount *int       `json:"privileged_phishing_resistant_user_count,omitempty"`
	PrivilegedMFACoveragePct             Percentage `json:"privileged_mfa_coverage_pct,omitzero"`
	PrivilegedPhishingResistantPct       Percentage `json:"privileged_phishing_resistant_pct,omitzero"`
	StandingPrivilegedUsersPresent       *bool      `json:"standing_privileged_users_present,omitempty"`
	StandingPrivilegedUsersCount         *int       `json:"standing_privileged_users_count,omitempty"`
}

// IDPPostureLifecycle counts every user in the directory. The collector does
// not read deleted users. archived_pct is null when the directory has no
// users, and absent otherwise.
type IDPPostureLifecycle struct {
	AccountsPresent       *bool      `json:"accounts_present,omitempty"`
	AccountCount          *int       `json:"account_count,omitempty"`
	SuspendedAccountCount *int       `json:"suspended_account_count,omitempty"`
	SuspendedPct          Percentage `json:"suspended_pct,omitzero"`
	ArchivedPct           Percentage `json:"archived_pct,omitzero"`
}

type IDPPosturePolicy struct {
	MFARequired            *bool      `json:"mfa_required,omitempty"`
	MFARequiredUserCount   *int       `json:"mfa_required_user_count,omitempty"`
	MFARequiredCoveragePct Percentage `json:"mfa_required_coverage_pct,omitzero"`
	LegacyAuthBlocked      *bool      `json:"legacy_auth_blocked,omitempty"`
}

// ToIDPPosture returns the normalized identity posture, or nil when the
// Entra artifact holds none of the values it copies. Each percentage is
// taken from its counts and rounded as the idp-posture schema says.
func (e *EntraArtifact) ToIDPPosture() *IDPPosture {
	if e == nil {
		return nil
	}
	audit := componentsdk.Level(e.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	atAudit := func(count *int) *int {
		if audit {
			return count
		}
		return nil
	}
	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.CollectedAt,
		Provider:      "entra",
		OrgDomain:     e.OrgDomain,
	}

	members := e.Users.EnabledMemberUsersCount
	userSecurity := IDPPostureUserSecurity{
		UsersPresent: present(members),
		UserCount:    atAudit(members),
	}
	if members != nil {
		userSecurity.MFACoveragePct = registrationShare(e.Posture.mfaRegisteredCount, e.Posture.DenominatorEnabledMemberUsers, *members)
		userSecurity.MFAPhishingResistantPct = registrationShare(e.Posture.phishingResistantCount, e.Posture.DenominatorEnabledMemberUsers, *members)
		userSecurity.InactiveUserCount = atAudit(e.Users.inactiveMemberCount)
		userSecurity.InactivePct = share(e.Users.inactiveMemberCount, members, componentsdk.RoundUp)
		// The percentages are taken over the members the report lists. When
		// it lists every enabled member, that is user_count, and the counts
		// behind the percentages hold.
		if listed := e.Posture.DenominatorEnabledMemberUsers; listed != nil && *listed == *members {
			userSecurity.MFAUserCount = atAudit(e.Posture.mfaRegisteredCount)
			userSecurity.PhishingResistantUserCount = atAudit(e.Posture.phishingResistantCount)
		}
	}
	if userSecurity != (IDPPostureUserSecurity{}) {
		posture.UserSecurity = &userSecurity
	}

	if apps := e.Apps; apps != nil {
		count := intPtr(apps.EnabledEnterpriseAppsCount)
		posture.AppSecurity = &IDPPostureAppSecurity{
			AppsPresent:              present(count),
			AppCount:                 atAudit(count),
			SSOAppCount:              atAudit(intPtr(apps.ssoAppCount)),
			SSOCoveragePct:           share(intPtr(apps.ssoAppCount), count, componentsdk.RoundDown),
			ProvisioningEnabledPct:   nullWhenEmpty(count),
			DeprovisioningEnabledPct: nullWhenEmpty(count),
		}
	}

	if pa := e.PrivilegedAccess; pa != nil {
		privileged := pa.PrivilegedUsersCount
		posture.PrivilegedAccess = &IDPPosturePrivilegedAccess{
			PrivilegedUsersPresent:               pa.privilegedUsersPresent,
			PrivilegedUsersCount:                 atAudit(privileged),
			SuperAdminCount:                      atAudit(pa.SuperAdminCount),
			PrivilegedMFAUserCount:               atAudit(pa.mfaRegisteredCount),
			PrivilegedPhishingResistantUserCount: atAudit(pa.phishingResistantCount),
			PrivilegedMFACoveragePct:             share(pa.mfaRegisteredCount, privileged, componentsdk.RoundDown),
			PrivilegedPhishingResistantPct:       share(pa.phishingResistantCount, privileged, componentsdk.RoundDown),
			StandingPrivilegedUsersPresent:       pa.standingPrivilegedUsersPresent,
			StandingPrivilegedUsersCount:         atAudit(pa.standingPrivilegedUsersCount),
		}
	}

	accounts := e.Users.TotalCount
	lifecycle := IDPPostureLifecycle{
		AccountsPresent:       present(accounts),
		AccountCount:          atAudit(accounts),
		SuspendedAccountCount: atAudit(e.Users.disabledCount),
		SuspendedPct:          share(e.Users.disabledCount, accounts, componentsdk.RoundUp),
		ArchivedPct:           nullWhenEmpty(accounts),
	}
	if lifecycle != (IDPPostureLifecycle{}) {
		posture.Lifecycle = &lifecycle
	}

	if p := e.Policy; p != nil {
		policy := IDPPosturePolicy{
			MFARequired:       p.MFARequired,
			LegacyAuthBlocked: p.LegacyAuthBlocked,
		}
		// The coverage is taken over the enabled members, so it is left out
		// when they were not read.
		if members != nil {
			policy.MFARequiredUserCount = atAudit(p.mfaRequiredUserCount)
			policy.MFARequiredCoveragePct = share(p.mfaRequiredUserCount, members, componentsdk.RoundDown)
		}
		if policy != (IDPPosturePolicy{}) {
			posture.Policy = &policy
		}
	}

	if posture.UserSecurity == nil && posture.AppSecurity == nil && posture.PrivilegedAccess == nil &&
		posture.Lifecycle == nil && posture.Policy == nil {
		return nil
	}
	return posture
}

// share returns count as a percentage of total, rounded as rounding says.
// It is null when total is 0, and left out when count or total was not read.
func share(count, total *int, rounding componentsdk.Rounding) Percentage {
	if total != nil && *total == 0 {
		return Percentage{Read: true}
	}
	if count == nil || total == nil {
		return Percentage{}
	}
	return Percentage{Value: componentsdk.Percent(*count, *total, rounding), Read: true}
}

// registrationShare returns an MFA registration percentage over the members
// in the registration report, rounded down. It is null when the tenant has
// no enabled members. When none of the tenant's members are in the report,
// their registration is unknown and the percentage is left out. See
// markUnlistedMembers.
func registrationShare(count, listed *int, members int) Percentage {
	if members == 0 {
		return Percentage{Read: true}
	}
	if listed != nil && *listed == 0 {
		return Percentage{}
	}
	return share(count, listed, componentsdk.RoundDown)
}

// nullWhenEmpty is a percentage the collector does not measure. It is null
// over an empty population, which needs no reading, and left out otherwise.
func nullWhenEmpty(total *int) Percentage {
	return Percentage{Read: total != nil && *total == 0}
}

// present returns whether a population of count has any members, or nil when
// count could not be read.
func present(count *int) *bool {
	if count == nil {
		return nil
	}
	return boolPtr(*count > 0)
}

// idpPostureSources maps each normalized identity value to the Entra values
// it is taken from, so a gap on any of them carries over. The first source a
// gap covers gives the gap.
var idpPostureSources = []struct {
	normalized string
	detailed   []string
}{
	{"/user_security/users_present", []string{"/users/enabled_member_users_count"}},
	{"/user_security/user_count", []string{"/users/enabled_member_users_count"}},
	{"/user_security/mfa_user_count", []string{"/posture/mfa_coverage"}},
	{"/user_security/phishing_resistant_user_count", []string{"/posture/mfa_phishing_resistant"}},
	{"/user_security/mfa_coverage_pct", []string{"/posture/mfa_coverage"}},
	{"/user_security/mfa_phishing_resistant_pct", []string{"/posture/mfa_phishing_resistant"}},
	{"/user_security/inactive_user_count", []string{"/users/enabled_member_users_count", "/users/inactive_pct"}},
	{"/user_security/inactive_pct", []string{"/users/enabled_member_users_count", "/users/inactive_pct"}},
	{"/app_security/apps_present", []string{"/apps/enabled_enterprise_apps_count"}},
	{"/app_security/app_count", []string{"/apps/enabled_enterprise_apps_count"}},
	{"/app_security/sso_app_count", []string{"/posture/sso_coverage"}},
	{"/app_security/sso_coverage_pct", []string{"/posture/sso_coverage"}},
	{"/privileged_access/privileged_users_present", []string{"/privileged_access/privileged_users_count"}},
	{"/privileged_access/privileged_users_count", []string{"/privileged_access/privileged_users_count"}},
	{"/privileged_access/super_admin_count", []string{"/privileged_access/super_admin_count"}},
	{"/privileged_access/privileged_mfa_user_count", []string{"/privileged_access/privileged_mfa_coverage_pct"}},
	{"/privileged_access/privileged_phishing_resistant_user_count", []string{"/privileged_access/privileged_phishing_resistant_pct"}},
	{"/privileged_access/privileged_mfa_coverage_pct", []string{"/privileged_access/privileged_mfa_coverage_pct"}},
	{"/privileged_access/privileged_phishing_resistant_pct", []string{"/privileged_access/privileged_phishing_resistant_pct"}},
	{"/privileged_access/standing_privileged_users_present", []string{"/privileged_access/privileged_users_count", "/privileged_access/standing_assignment_count"}},
	{"/privileged_access/standing_privileged_users_count", []string{"/privileged_access/privileged_users_count", "/privileged_access/standing_assignment_count"}},
	{"/lifecycle/accounts_present", []string{"/users/total_count"}},
	{"/lifecycle/account_count", []string{"/users/total_count"}},
	{"/lifecycle/suspended_account_count", []string{"/users/disabled_pct"}},
	{"/lifecycle/suspended_pct", []string{"/users/disabled_pct"}},
	{"/policy/mfa_required", []string{"/policy/mfa_required"}},
	{"/policy/mfa_required_user_count", []string{"/users/enabled_member_users_count", "/policy/mfa_required_coverage_pct"}},
	{"/policy/mfa_required_coverage_pct", []string{"/users/enabled_member_users_count", "/policy/mfa_required_coverage_pct"}},
	{"/policy/legacy_auth_blocked", []string{"/policy/legacy_auth_blocked"}},
}

func (c *Collector) mirrorIDPPostureGaps(posture *IDPPosture) {
	for _, source := range idpPostureSources {
		if presenceKnown(posture, source.normalized) {
			continue
		}
		for _, detailed := range source.detailed {
			c.gaps.rec.Mirror(
				componentsdk.Location{Path: entraPath, Pointer: detailed},
				componentsdk.Location{Path: idpPosturePath, Pointer: source.normalized})
		}
	}
}

// presenceKnown reports whether the posture writes the present flag at
// pointer although the count it comes from may be left out, so no gap on the
// count carries over to it.
func presenceKnown(posture *IDPPosture, pointer string) bool {
	pa := posture.PrivilegedAccess
	switch {
	case pa == nil:
		return false
	case pointer == "/privileged_access/privileged_users_present":
		return pa.PrivilegedUsersPresent != nil
	case pointer == "/privileged_access/standing_privileged_users_present":
		return pa.StandingPrivilegedUsersPresent != nil
	}
	return false
}

// idpPostureUnsupported lists the normalized values Entra has no data for,
// with the reason. The counts are audit-level fields.
var idpPostureUnsupported = []struct {
	pointer, reason string
	audit           bool
}{
	{"/user_security/locked_out_pct", lockedOutUsers, false},
	{"/user_security/locked_out_user_count", lockedOutUsers, true},
	{"/user_security/password_policy_noncompliant_pct", policyCompliance, false},
	{"/user_security/password_policy_noncompliant_user_count", policyCompliance, true},
	{"/user_security/weak_password_pct", weakPasswords, false},
	{"/user_security/weak_password_user_count", weakPasswords, true},
}

const (
	lockedOutUsers   = "Microsoft does not report whether a user is currently locked out."
	policyCompliance = "Microsoft does not report whether each user's password meets the password policy."
	weakPasswords    = "Microsoft does not report how strong each user's password is."
)

// markIDPPostureUnsupported gives each value Entra has no data for an
// unsupported gap. The counts get one only at the audit level and above,
// where the artifact has counts.
func (c *Collector) markIDPPostureUnsupported(level componentsdk.Level) {
	for _, u := range idpPostureUnsupported {
		if u.audit && !level.AtLeast(componentsdk.LevelAudit) {
			continue
		}
		c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: u.pointer}, componentsdk.CodeUnsupported, u.reason)
	}
}

// partlyListedMembers is the detail of the gap on the MFA counts when the
// registration report lists some of the tenant's enabled members but not all.
const partlyListedMembers = "Microsoft's MFA registration report doesn't list every enabled member yet, so how many of them have MFA isn't known. The MFA percentages are taken over the members it lists."

// markPartlyListedMembers records why the normalized MFA counts are left out
// when the registration report lists some enabled members but not all. The
// percentages stay, taken over the members it lists. Only audit and higher
// runs write the counts.
func (c *Collector) markPartlyListedMembers(entra *EntraArtifact, level componentsdk.Level) {
	members, listed := entra.Users.EnabledMemberUsersCount, entra.Posture.DenominatorEnabledMemberUsers
	if !level.AtLeast(componentsdk.LevelAudit) || members == nil || listed == nil || *listed == 0 || *listed == *members {
		return
	}
	for _, pointer := range []string{"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count"} {
		c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: pointer}, componentsdk.CodeVendorError, partlyListedMembers)
	}
}

// unlistedMembers is the detail of the gap on an MFA percentage when the
// tenant has enabled members and none of them are in the registration report.
const unlistedMembers = "None of the tenant's enabled members are in Microsoft's MFA registration report yet. Their MFA registration is unknown."

// markUnlistedMembers records why the normalized MFA percentages are left
// out when none of the tenant's enabled members are in the registration
// report. In the Entra artifact those percentages are taken over the members
// in the report, which are none, so they are null there.
func (c *Collector) markUnlistedMembers(entra *EntraArtifact, path string, pointers ...string) {
	members, listed := entra.Users.EnabledMemberUsersCount, entra.Posture.DenominatorEnabledMemberUsers
	if members == nil || *members == 0 || listed == nil || *listed != 0 {
		return
	}
	for _, pointer := range pointers {
		c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: path, Pointer: pointer}, componentsdk.CodeVendorError, unlistedMembers)
	}
}
