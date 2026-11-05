package collector

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// AccessPosture is the normalized evidencepack/access-posture@v1 artifact
// for Azure. People and service principals reach a subscription through
// Azure role assignments, and everyone signs in through Microsoft Entra ID.
// The sections hold totals across the configured subscriptions, and scopes
// holds each subscription from the audit level. Counts are written from the
// audit level, as the schema marks them, and the present flags at every
// level. A percentage over an empty population is null.
type AccessPosture struct {
	SchemaVersion string `json:"schema_version"`
	CollectedAt   string `json:"collected_at"`
	Provider      string `json:"provider"`
	SystemType    string `json:"system_type"`
	AccessSections
	Scopes []AccessScope `json:"scopes,omitempty"`
}

// AccessScope is one subscription. A subscription that could not be read
// has only its ID, its kind, and sign_in.
type AccessScope struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	AccessSections
}

// AccessSections are the sections the totals and each scope share. Azure has
// no root account, so root is left out with an unsupported gap.
type AccessSections struct {
	SignIn      *AccessSignIn      `json:"sign_in,omitempty"`
	Members     *AccessMembers     `json:"members,omitempty"`
	Admins      *AccessAdmins      `json:"admins,omitempty"`
	Credentials *AccessCredentials `json:"credentials,omitempty"`
}

type AccessSignIn struct {
	SSOConfigured *bool `json:"sso_configured,omitempty"`
	SSORequired   *bool `json:"sso_required,omitempty"`
}

// AccessMembers counts the enabled users with a role assignment. No one
// signs in to Azure without Entra ID, so the local values are false, 0, or
// null.
type AccessMembers struct {
	MembersPresent         *bool      `json:"members_present,omitempty"`
	MemberCount            *int       `json:"member_count,omitempty"`
	ExternalMembersPresent *bool      `json:"external_members_present,omitempty"`
	ExternalMemberCount    *int       `json:"external_member_count,omitempty"`
	SSOMemberCount         *int       `json:"sso_member_count,omitempty"`
	SSOCoveragePct         Percentage `json:"sso_coverage_pct,omitzero"`
	LocalMembersPresent    *bool      `json:"local_members_present,omitempty"`
	LocalMemberCount       *int       `json:"local_member_count,omitempty"`
	LocalMFAMemberCount    *int       `json:"local_mfa_member_count,omitempty"`
	LocalMFACoveragePct    Percentage `json:"local_mfa_coverage_pct,omitzero"`
	InactiveMemberCount    *int       `json:"inactive_member_count,omitempty"`
	InactivePct            Percentage `json:"inactive_pct,omitzero"`
}

// AccessAdmins counts the members with the Owner or User Access
// Administrator role.
type AccessAdmins struct {
	AdminsPresent            *bool      `json:"admins_present,omitempty"`
	AdminCount               *int       `json:"admin_count,omitempty"`
	AdminSharePct            Percentage `json:"admin_share_pct,omitzero"`
	LocalAdminsPresent       *bool      `json:"local_admins_present,omitempty"`
	LocalAdminCount          *int       `json:"local_admin_count,omitempty"`
	LocalMFAAdminCount       *int       `json:"local_mfa_admin_count,omitempty"`
	LocalAdminMFACoveragePct Percentage `json:"local_admin_mfa_coverage_pct,omitzero"`
}

// AccessCredentials counts the service principals with a role assignment.
// The never-expiring and rotation values come from their Entra ID
// credentials. The unused values are 0 or null when there are no service
// principals, and left out with a not_read gap otherwise. The unrestricted
// values are left out the same way when a service principal holds a role
// that is not read-only.
type AccessCredentials struct {
	CredentialsPresent             *bool      `json:"credentials_present,omitempty"`
	CredentialCount                *int       `json:"credential_count,omitempty"`
	NeverExpiringCredentialCount   *int       `json:"never_expiring_credential_count,omitempty"`
	NeverExpiringPct               Percentage `json:"never_expiring_pct,omitzero"`
	UnusedCredentialCount          *int       `json:"unused_credential_count,omitempty"`
	UnusedPct                      Percentage `json:"unused_pct,omitzero"`
	UnrestrictedCredentialCount    *int       `json:"unrestricted_credential_count,omitempty"`
	UnrestrictedPct                Percentage `json:"unrestricted_pct,omitzero"`
	WriteAccessCredentialCount     *int       `json:"write_access_credential_count,omitempty"`
	WriteAccessPct                 Percentage `json:"write_access_pct,omitzero"`
	RotationOverdueCredentialCount *int       `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             Percentage `json:"rotation_overdue_pct,omitzero"`
}

// The details of the gaps in the access posture. Microsoft never reports the
// first three, which get an unsupported gap. Microsoft reports the rest in
// places the collector does not read, which get a not_read gap.
const (
	noSignInWithoutEntra   = "People sign in to Azure only through Microsoft Entra ID, whose MFA rules are in idp-posture."
	noAzureAccounts        = "Azure has no accounts of its own to provision, since people sign in with their Microsoft Entra ID accounts."
	noRootAccount          = "Azure has no root account."
	connectedAppsUnread    = "Microsoft Graph's /oauth2PermissionGrants list shows which apps have delegated access to Azure Resource Manager. This collector does not read it."
	groupHoldsRole         = "An Azure role is assigned to a group, and the users and service principals in it hold the role too. Microsoft Graph lists them at /groups/{id}/transitiveMembers, which this collector does not read."
	groupHoldsAdminRole    = "The Owner or User Access Administrator role is assigned to a group, and the users in it hold the role too. Microsoft Graph lists them at /groups/{id}/transitiveMembers, which this collector does not read."
	otherHoldsRole         = "An Azure role is assigned to a principal that is not a user, a group or a service principal, such as an agent identity or a device. This collector does not count those principals as members or service principals."
	otherHoldsAdminRole    = "The Owner or User Access Administrator role is assigned to a principal that is not a user, a group or a service principal, such as an agent identity. This collector does not count those principals as members."
	servicePrincipalUse    = "Microsoft Graph reports when a service principal last signed in only in its beta servicePrincipalSignInActivities report, which this collector does not read."
	servicePrincipalLimits = "This collector does not read Azure's custom role definitions, which show whether a role grants full access. It also does not read the location conditions of Conditional Access policies for service principals."
)

// accessPosture returns the normalized access posture of the configured
// subscriptions, or nil when there are none.
func (c *Collector) accessPosture(level componentsdk.Level, azure *AzureArtifact, entra *EntraArtifact) *AccessPosture {
	if azure == nil || len(azure.Accounts) == 0 || entra == nil {
		return nil
	}
	audit := level.AtLeast(componentsdk.LevelAudit)
	now := c.clock.Now()
	out := &AccessPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   azure.CollectedAt,
		Provider:      "azure",
		SystemType:    "cloud",
	}
	total := newAccessPopulation()
	for i, account := range azure.Accounts {
		population := subscriptionPopulation(account)
		total.merge(population)
		if !audit {
			continue
		}
		scope := AccessScope{ID: account.AccountID, Kind: "subscription"}
		gaps := accessGaps{log: c.gaps, prefix: fmt.Sprintf("/scopes/%d", i), audit: true}
		if account.unreadable != nil {
			// Sign-in to any subscription goes through Entra ID, so the
			// sign_in values hold in every scope.
			scope.SignIn = accessSignIn(gaps)
			gaps.leaveOut(account.unreadable, "/members", "/admins", "/credentials")
		} else {
			scope.AccessSections = accessSections(population, entra.directory, now, gaps)
		}
		gaps.leaveOut(unsupported(noRootAccount), "/root")
		out.Scopes = append(out.Scopes, scope)
	}
	gaps := accessGaps{log: c.gaps, audit: audit}
	out.AccessSections = accessSections(total, entra.directory, now, gaps)
	gaps.leaveOut(unsupported(noRootAccount), "/root")
	gaps.leaveOut(notRead(connectedAppsUnread), "/connected_apps")
	return out
}

func accessSections(population accessPopulation, dir directory, now time.Time, gaps accessGaps) AccessSections {
	return AccessSections{
		SignIn:      accessSignIn(gaps),
		Members:     accessMembers(population, dir, now, gaps),
		Admins:      accessAdmins(population, dir, gaps),
		Credentials: accessCredentials(population, dir.apps, now, gaps),
	}
}

func accessSignIn(gaps accessGaps) *AccessSignIn {
	gaps.leaveOut(unsupported(noSignInWithoutEntra), "/sign_in/mfa_required")
	gaps.leaveOut(unsupported(noAzureAccounts), "/sign_in/scim_enabled")
	return &AccessSignIn{SSOConfigured: boolPtr(true), SSORequired: boolPtr(true)}
}

func accessMembers(population accessPopulation, dir directory, now time.Time, gaps accessGaps) *AccessMembers {
	out := &AccessMembers{
		LocalMembersPresent: boolPtr(false),
		LocalMemberCount:    gaps.count(intPtr(0)),
		LocalMFAMemberCount: gaps.count(intPtr(0)),
		LocalMFACoveragePct: Percentage{Read: true},
	}
	members := roleHolders(population.users, dir)
	guests := 0
	for _, user := range members {
		if user.UserType == "Guest" {
			guests++
		}
	}
	why := firstMissing(population.why, dir.usersMiss, population.holdersMiss())
	out.MembersPresent = gaps.present(len(members), why, "/members/members_present")
	out.ExternalMembersPresent = gaps.present(guests, why, "/members/external_members_present")
	if why != nil {
		gaps.leaveOut(why,
			"/members/member_count", "/members/external_member_count",
			"/members/sso_member_count", "/members/sso_coverage_pct",
			"/members/inactive_member_count", "/members/inactive_pct")
		return out
	}

	count := intPtr(len(members))
	out.MemberCount = gaps.count(count)
	out.ExternalMemberCount = gaps.count(intPtr(guests))
	// Everyone signs in through Entra ID, so every member uses SSO.
	out.SSOMemberCount = gaps.count(count)
	out.SSOCoveragePct = share(count, count, componentsdk.RoundDown)

	inactive := inactiveMembers(members, dir, now)
	out.InactiveMemberCount = gaps.count(inactive)
	out.InactivePct = share(inactive, count, componentsdk.RoundUp)
	if inactive == nil {
		gaps.leaveOut(dir.signInMiss, "/members/inactive_member_count", "/members/inactive_pct")
	}
	return out
}

func accessAdmins(population accessPopulation, dir directory, gaps accessGaps) *AccessAdmins {
	out := &AccessAdmins{
		LocalAdminsPresent:       boolPtr(false),
		LocalAdminCount:          gaps.count(intPtr(0)),
		LocalMFAAdminCount:       gaps.count(intPtr(0)),
		LocalAdminMFACoveragePct: Percentage{Read: true},
	}
	admins := roleHolders(population.admins, dir)
	why := firstMissing(population.why, dir.usersMiss, population.adminHoldersMiss())
	out.AdminsPresent = gaps.present(len(admins), why, "/admins/admins_present")
	if why != nil {
		gaps.leaveOut(why, "/admins/admin_count", "/admins/admin_share_pct")
		return out
	}
	count := intPtr(len(admins))
	out.AdminCount = gaps.count(count)
	// The share is taken over every member, and the members are unknown
	// when any group, or any principal of another type, holds a role.
	if membersWhy := population.holdersMiss(); membersWhy != nil {
		gaps.leaveOut(membersWhy, "/admins/admin_share_pct")
		return out
	}
	out.AdminSharePct = share(count, intPtr(len(roleHolders(population.users, dir))), componentsdk.RoundUp)
	return out
}

func accessCredentials(population accessPopulation, apps appCredentials, now time.Time, gaps accessGaps) *AccessCredentials {
	why := firstMissing(population.why, population.holdersMiss())
	if why != nil && len(population.servicePrincipals) == 0 {
		gaps.leaveOut(why, "/credentials")
		return nil
	}
	out := &AccessCredentials{
		CredentialsPresent: gaps.present(len(population.servicePrincipals), why, "/credentials/credentials_present"),
	}
	if why != nil {
		gaps.leaveOut(why,
			"/credentials/credential_count",
			"/credentials/never_expiring_credential_count", "/credentials/never_expiring_pct",
			"/credentials/unused_credential_count", "/credentials/unused_pct",
			"/credentials/unrestricted_credential_count", "/credentials/unrestricted_pct",
			"/credentials/write_access_credential_count", "/credentials/write_access_pct",
			"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct")
		return out
	}

	count := intPtr(len(population.servicePrincipals))
	out.CredentialCount = gaps.count(count)
	neverExpiring, neverExpiringMiss := neverExpiringServicePrincipals(population.servicePrincipals, apps, now)
	out.NeverExpiringCredentialCount = gaps.count(neverExpiring)
	out.NeverExpiringPct = share(neverExpiring, count, componentsdk.RoundUp)
	gaps.leaveOut(neverExpiringMiss, "/credentials/never_expiring_credential_count", "/credentials/never_expiring_pct")
	writers, writersMiss := enabledServicePrincipals(population.writers, apps)
	out.WriteAccessCredentialCount = gaps.count(writers)
	out.WriteAccessPct = share(writers, count, componentsdk.RoundUp)
	gaps.leaveOut(writersMiss, "/credentials/write_access_credential_count", "/credentials/write_access_pct")

	overdue, overdueMiss := rotationOverdueServicePrincipals(population.servicePrincipals, apps, now)
	out.RotationOverdueCredentialCount = gaps.count(overdue)
	out.RotationOverduePct = share(overdue, count, componentsdk.RoundUp)
	gaps.leaveOut(overdueMiss, "/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct")

	// A read-only role is narrower than full access, so a service principal
	// with only read-only roles is restricted. Any other role may be a custom
	// role that grants full access.
	if len(population.writers) == 0 {
		out.UnrestrictedCredentialCount = gaps.count(intPtr(0))
		out.UnrestrictedPct = share(intPtr(0), count, componentsdk.RoundUp)
	} else {
		gaps.leaveOut(notRead(servicePrincipalLimits), "/credentials/unrestricted_credential_count", "/credentials/unrestricted_pct")
	}

	if *count == 0 {
		out.UnusedCredentialCount = gaps.count(intPtr(0))
		out.UnusedPct = Percentage{Read: true}
		return out
	}
	gaps.leaveOut(notRead(servicePrincipalUse), "/credentials/unused_credential_count", "/credentials/unused_pct")
	return out
}

// neverExpiringYears is how far past the run an end date must be for a
// credential to count as never expiring. Secrets created with the Azure
// portal's former Never option end in 2299.
const neverExpiringYears = 50

// neverExpiringServicePrincipals counts the service principals among ids with
// a client secret or certificate that has no end date or ends more than
// neverExpiringYears after now. countServicePrincipalCredentials says which
// credentials it checks.
func neverExpiringServicePrincipals(ids map[string]struct{}, apps appCredentials, now time.Time) (*int, *missing) {
	cutoff := now.AddDate(neverExpiringYears, 0, 0)
	return countServicePrincipalCredentials(ids, apps, func(c credentialWindow) bool {
		return c.end.IsZero() || c.end.After(cutoff)
	})
}

// rotationOverdueDays is how long after a client secret or certificate
// becomes valid it is due for rotation.
const rotationOverdueDays = 90

// rotationOverdueServicePrincipals counts the service principals among ids
// with an active client secret or certificate whose startDateTime is more
// than rotationOverdueDays before now. A client secret's startDateTime is
// when it was added, unless whoever added it chose another date. A
// certificate's is the certificate's own start date. A credential with no
// startDateTime is not counted.
func rotationOverdueServicePrincipals(ids map[string]struct{}, apps appCredentials, now time.Time) (*int, *missing) {
	cutoff := now.AddDate(0, 0, -rotationOverdueDays)
	return countServicePrincipalCredentials(ids, apps, func(c credentialWindow) bool {
		active := c.end.IsZero() || c.end.After(now)
		return active && !c.start.IsZero() && c.start.Before(cutoff)
	})
}

// enabledServicePrincipals counts the service principals among ids that are
// not disabled. A disabled service principal cannot get a token, so its roles
// grant no access. A service principal outside the list of Application
// service principals, such as a managed identity, counts as enabled. The
// count is nil, with the reason, when that list could not be read.
func enabledServicePrincipals(ids map[string]struct{}, apps appCredentials) (*int, *missing) {
	if len(ids) == 0 {
		return intPtr(0), nil
	}
	if apps.servicePrincipalsMiss != nil {
		return nil, apps.servicePrincipalsMiss
	}
	count := 0
	for id := range ids {
		if sp, ok := apps.servicePrincipals[id]; !ok || !sp.Disabled() {
			count++
		}
	}
	return intPtr(count), nil
}

// countServicePrincipalCredentials counts the service principals among ids
// with a client secret or certificate that matches. Each one's own
// credentials are checked, and those of the application with its appId. A
// service principal outside the list of Application service principals, such
// as a managed identity, has no such credentials. The count is nil, with the
// reason, when a list it needs could not be read.
func countServicePrincipalCredentials(ids map[string]struct{}, apps appCredentials, matches func(credentialWindow) bool) (*int, *missing) {
	if len(ids) == 0 {
		return intPtr(0), nil
	}
	if apps.servicePrincipalsMiss != nil {
		return nil, apps.servicePrincipalsMiss
	}
	count := 0
	for id := range ids {
		sp, ok := apps.servicePrincipals[id]
		if !ok {
			continue
		}
		if apps.applicationsMiss != nil {
			return nil, apps.applicationsMiss
		}
		credentials := append(passwordCredentialWindows(sp.PasswordCredentials), keyCredentialWindows(sp.KeyCredentials)...)
		if app, ok := apps.applications[sp.AppID]; ok && sp.AppID != "" {
			credentials = append(credentials, passwordCredentialWindows(app.PasswordCredentials)...)
			credentials = append(credentials, keyCredentialWindows(app.KeyCredentials)...)
		}
		if slices.ContainsFunc(credentials, matches) {
			count++
		}
	}
	return intPtr(count), nil
}

// roleHolders returns the enabled users in the tenant's user list among ids.
// A user deleted after the role was assigned is missing from the list and
// holds no access. A disabled user holds none either. It returns nil when the
// user list could not be read.
func roleHolders(ids map[string]struct{}, dir directory) map[string]microsoft.User {
	if dir.usersMiss != nil {
		return nil
	}
	out := map[string]microsoft.User{}
	for id := range ids {
		if user, ok := dir.users[id]; ok && !user.Disabled() {
			out[id] = user
		}
	}
	return out
}

// inactiveMembers counts the members with no successful sign-in in the last
// 90 days. A member the sign-in activity list does not hold counts as
// inactive. It is nil when that list could not be read and there are members
// to count.
func inactiveMembers(members map[string]microsoft.User, dir directory, now time.Time) *int {
	if len(members) == 0 {
		return intPtr(0)
	}
	if dir.signInMiss != nil {
		return nil
	}
	cutoff := inactiveCutoff(now)
	inactive := 0
	for id := range members {
		if user, ok := dir.signIns[id]; !ok || !signedInSince(user, cutoff) {
			inactive++
		}
	}
	return intPtr(inactive)
}

// accessPopulation is who holds an Azure role assignment, in one
// subscription or merged across several. why is set when a subscription's
// role assignments could not be read, and the sets then hold the
// subscriptions that were read.
type accessPopulation struct {
	why               *missing
	users             map[string]struct{}
	admins            map[string]struct{}
	servicePrincipals map[string]struct{}
	writers           map[string]struct{}
	groupHeld         bool
	groupHeldAdmin    bool
	otherHeld         bool
	otherHeldAdmin    bool
}

func newAccessPopulation() accessPopulation {
	return accessPopulation{
		users:             map[string]struct{}{},
		admins:            map[string]struct{}{},
		servicePrincipals: map[string]struct{}{},
		writers:           map[string]struct{}{},
	}
}

func subscriptionPopulation(account AzureAccount) accessPopulation {
	out := newAccessPopulation()
	if why := firstMissing(account.unreadable, account.rbacMiss); why != nil {
		out.why = why
		return out
	}
	out.add(account.roleAssignments)
	return out
}

// add sorts each assignment's principal by its type, which is User when the
// assignment has none. A user with Owner or User Access Administrator is an
// admin. A service principal with any role but a read-only one has write
// access. Any other type, such as an agent identity or a device, is not
// sorted, so the values over everyone with a role are unknown.
// https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription
func (p *accessPopulation) add(assignments []microsoft.ARMRoleAssignment) {
	for _, assignment := range assignments {
		principal := assignment.Properties.PrincipalID
		role := roleDefinitionGUID(assignment.Properties.RoleDefinitionID)
		admin := role == azureOwnerRoleDefinitionID || role == azureUserAccessAdministratorRoleDefinitionID
		principalType := assignment.Properties.PrincipalType
		switch {
		case strings.EqualFold(principalType, "Group"), strings.EqualFold(principalType, "ForeignGroup"):
			p.groupHeld = true
			p.groupHeldAdmin = p.groupHeldAdmin || admin
		case principal == "":
		case principalType == "", strings.EqualFold(principalType, "User"):
			p.users[principal] = struct{}{}
			if admin {
				p.admins[principal] = struct{}{}
			}
		case strings.EqualFold(principalType, "ServicePrincipal"):
			p.servicePrincipals[principal] = struct{}{}
			if _, readOnly := readOnlyRoleDefinitionIDs[role]; !readOnly {
				p.writers[principal] = struct{}{}
			}
		default:
			p.otherHeld = true
			p.otherHeldAdmin = p.otherHeldAdmin || admin
		}
	}
}

// merge adds other to p, for the totals across subscriptions. A principal
// with roles in several subscriptions counts once.
func (p *accessPopulation) merge(other accessPopulation) {
	p.why = firstMissing(p.why, other.why)
	maps.Copy(p.users, other.users)
	maps.Copy(p.admins, other.admins)
	maps.Copy(p.servicePrincipals, other.servicePrincipals)
	maps.Copy(p.writers, other.writers)
	p.groupHeld = p.groupHeld || other.groupHeld
	p.groupHeldAdmin = p.groupHeldAdmin || other.groupHeldAdmin
	p.otherHeld = p.otherHeld || other.otherHeld
	p.otherHeldAdmin = p.otherHeldAdmin || other.otherHeldAdmin
}

// holdersMiss is why a value over everyone with a role is unknown. A role is
// assigned to a group, whose members are not read, or to a principal of a
// type that is not sorted.
func (p accessPopulation) holdersMiss() *missing {
	switch {
	case p.groupHeld:
		return notRead(groupHoldsRole)
	case p.otherHeld:
		return notRead(otherHoldsRole)
	}
	return nil
}

// adminHoldersMiss is why the admins are unknown when an admin role is
// assigned to a group or to a principal of a type that is not sorted.
func (p accessPopulation) adminHoldersMiss() *missing {
	switch {
	case p.groupHeldAdmin:
		return notRead(groupHoldsAdminRole)
	case p.otherHeldAdmin:
		return notRead(otherHoldsAdminRole)
	}
	return nil
}

// accessGaps records gaps under prefix, which is empty for the totals and
// names the scope otherwise. Below the audit level the counts are not
// written, so their gaps are not recorded either. Every count's name ends in
// _count.
type accessGaps struct {
	log    *gapLog
	prefix string
	audit  bool
}

func (g accessGaps) leaveOut(why *missing, fields ...string) {
	for _, field := range fields {
		if !g.audit && strings.HasSuffix(field, "_count") {
			continue
		}
		g.log.leaveOut(accessPosturePath, why, g.prefix+field)
	}
}

// count returns n from the audit level, and nil below it.
func (g accessGaps) count(n *int) *int {
	if g.audit {
		return n
	}
	return nil
}

// present returns whether a population has members when n of them were
// found. When none were found and why says the population was not read in
// full, it records the gap and returns nil.
func (g accessGaps) present(n int, why *missing, field string) *bool {
	if n > 0 {
		return boolPtr(true)
	}
	if why != nil {
		g.leaveOut(why, field)
		return nil
	}
	return boolPtr(false)
}
