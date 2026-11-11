package collector

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

var conditionalAccessFields = []string{
	"/policy/mfa_required",
	"/policy/admin_portals_mfa_required",
	"/policy/all_cloud_apps_mfa_required",
	"/policy/compliant_device_required",
	"/policy/legacy_auth_blocked",
	"/policy/policy_count",
}

// roleAssignmentList is the tenant's directory role assignments, or why they
// were not read.
type roleAssignmentList struct {
	assignments []microsoft.UnifiedRoleAssignment
	miss        *missing
}

func (c *Collector) collectPolicy(ctx context.Context, diagnostics *Diagnostics, enabledMemberIDs map[string]struct{}, usersMiss *missing, roles roleAssignmentList) (*Policy, *SecurityDefaults) {
	policies, caMiss := c.conditionalAccessPolicies(ctx, diagnostics)
	securityDefaults, defaultsMiss := c.securityDefaults(ctx, diagnostics)

	var defaults *SecurityDefaults
	if securityDefaults != nil {
		defaults = &SecurityDefaults{Enabled: securityDefaults.IsEnabled}
	}
	c.gaps.leaveOut(entraPath, defaultsMiss, "/security_defaults")
	defaultsOn := defaults != nil && defaults.Enabled

	var enabledPolicies []microsoft.ConditionalAccessPolicy
	var policy *Policy
	var space *signInSpace
	switch {
	case caMiss == nil:
		enabledPolicies = enabledConditionalAccessPolicies(policies)
		space = newSignInSpace(c.namedLocations(ctx, diagnostics, enabledPolicies))
		var mfaUnknown, legacyUnknown *missing
		policy, mfaUnknown, legacyUnknown = computePolicy(enabledPolicies, space)
		c.gaps.leaveOut(entraPath, mfaUnknown, "/policy/mfa_required")
		c.gaps.leaveOut(entraPath, legacyUnknown, "/policy/legacy_auth_blocked")
	case defaultsOn:
		// Entra allows no enabled Conditional Access policy while security
		// defaults are on, so the policies that weren't read change nothing.
		policy, _, _ = computePolicy(nil, newSignInSpace(nil))
	default:
		policy = &Policy{}
		c.gaps.leaveOut(entraPath, caMiss, conditionalAccessFields...)
	}
	if len(enabledPolicies) == 0 && policy.LegacyAuthBlocked != nil {
		// With no enabled policy, security defaults are the tenant's sign-in
		// policy, and they block legacy authentication.
		policy.LegacyAuthBlocked = securityDefaultsBlockLegacyAuth(defaults)
		c.gaps.leaveOut(entraPath, defaultsMiss, "/policy/legacy_auth_blocked")
	}

	var covered *int
	var why *missing
	switch {
	case usersMiss != nil:
		why = usersMiss
	case len(enabledPolicies) > 0:
		covered, why = mfaPolicyCoveredCount(enabledMemberIDs, enabledPolicies, space)
	case caMiss == nil || caMiss.err == nil || defaultsOn:
		// With no enabled Conditional Access policy, or no license for one,
		// security defaults are the tenant's MFA policy.
		covered, why = securityDefaultsCoveredCount(defaults, defaultsMiss, enabledMemberIDs, roles)
	default:
		why = caMiss
	}
	if covered != nil {
		policy.MFARequiredCoveragePct = PercentInt(*covered, len(enabledMemberIDs))
		policy.mfaRequiredUserCount = covered
	}
	c.gaps.leaveOut(entraPath, why, "/policy/mfa_required_coverage_pct")
	return policy, defaults
}

func (c *Collector) conditionalAccessPolicies(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.ConditionalAccessPolicy, *missing) {
	policies, err := c.graph.ConditionalAccessPolicies(ctx)
	switch {
	case err == nil:
		return policies, nil
	case microsoft.IsPremiumLicenseError(err):
		diagnostics.Warn("Entra ID P1 not licensed, conditional_access reported as license_absent")
		diagnostics.MarkCapabilityUnavailable("conditional_access")
		return nil, unlicensed("Conditional Access requires Entra ID P1 or P2.")
	case permissionDenied(err):
		diagnostics.Warn("graph permission Policy.Read.All not granted, conditional access skipped")
		diagnostics.MarkCapabilityUnavailable("conditional_access")
	default:
		diagnostics.warnNotCollected("Conditional Access policies", err)
	}
	return nil, failed(err)
}

// namedLocations reads whether each named location is trusted, when a
// policy names one. It returns nil when none does or they can't be read, and
// a policy that names one then can't be evaluated there.
func (c *Collector) namedLocations(ctx context.Context, diagnostics *Diagnostics, policies []microsoft.ConditionalAccessPolicy) map[string]bool {
	if !slices.ContainsFunc(policies, func(policy microsoft.ConditionalAccessPolicy) bool {
		l := policy.Conditions.Locations
		return l != nil && len(namedLocationIDs(l)) > 0
	}) {
		return nil
	}
	locations, err := c.graph.NamedLocations(ctx)
	if err != nil {
		diagnostics.warnNotCollected("Conditional Access named locations", err)
		return nil
	}
	out := map[string]bool{}
	for _, location := range locations {
		out[location.ID] = strings.EqualFold(location.ODataType, "#microsoft.graph.ipNamedLocation") && location.IsTrusted
	}
	return out
}

func (c *Collector) securityDefaults(ctx context.Context, diagnostics *Diagnostics) (*microsoft.IdentitySecurityDefaultsEnforcementPolicy, *missing) {
	defaults, err := c.graph.SecurityDefaults(ctx)
	switch {
	case err == nil:
		return defaults, nil
	case permissionDenied(err):
		diagnostics.Warn("graph permission Policy.Read.All not granted, security defaults skipped")
		diagnostics.MarkCapabilityUnavailable("security_defaults")
	default:
		diagnostics.warnNotCollected("Security defaults", err)
	}
	return nil, failed(err)
}

// computePolicy leaves the MFA coverage to the caller, which also needs the
// user list. Policies combine. mfa_required holds when the policies that
// include every user, between them, require MFA for or block every sign-in,
// and legacy_auth_blocked when they block every legacy sign-in. When either
// depends on something the collector can't evaluate, it is left out and the
// reason returned. The other flags each need one policy.
func computePolicy(enabledPolicies []microsoft.ConditionalAccessPolicy, space *signInSpace) (policy *Policy, mfaUnknown, legacyUnknown *missing) {
	everyone := policiesThat(enabledPolicies, targetsAllUsers)
	legacyAuthBlocked, legacyUnknown := space.settle(everyone, legacyClientTypes, blocksAt)
	mfaRequired, mfaUnknown := space.settle(everyone, clientAppTypes, protectsAt)
	legacyBlocked := legacyAuthBlocked != nil && *legacyAuthBlocked
	adminPortalsMFARequired := false
	allCloudAppsMFARequired := false
	compliantDeviceRequired := false

	for _, policy := range enabledPolicies {
		requiresMFA := requiresMFAOnEverySignIn(policy, legacyBlocked)
		if requiresMFA && targetsAdminPortals(policy) {
			adminPortalsMFARequired = true
		}
		if requiresMFA && targetsEveryApp(policy) {
			allCloudAppsMFARequired = true
		}
		if requiresCompliantDevice(policy) && targetsAdminOrPrivilegedAccess(policy) {
			compliantDeviceRequired = true
		}
	}

	return &Policy{
		MFARequired:             mfaRequired,
		AdminPortalsMFARequired: boolPtr(adminPortalsMFARequired),
		AllCloudAppsMFARequired: boolPtr(allCloudAppsMFARequired),
		CompliantDeviceRequired: boolPtr(compliantDeviceRequired),
		LegacyAuthBlocked:       legacyAuthBlocked,
		PolicyCount:             intPtr(len(enabledPolicies)),
	}, mfaUnknown, legacyUnknown
}

func policiesThat(policies []microsoft.ConditionalAccessPolicy, keep func(microsoft.ConditionalAccessPolicy) bool) []microsoft.ConditionalAccessPolicy {
	var out []microsoft.ConditionalAccessPolicy
	for _, policy := range policies {
		if keep(policy) {
			out = append(out, policy)
		}
	}
	return out
}

func enabledConditionalAccessPolicies(policies []microsoft.ConditionalAccessPolicy) []microsoft.ConditionalAccessPolicy {
	out := make([]microsoft.ConditionalAccessPolicy, 0, len(policies))
	for _, policy := range policies {
		if strings.EqualFold(policy.State, "enabled") {
			out = append(out, policy)
		}
	}
	return out
}

// groupOrRoleMembersUnread is the detail of the gap on the MFA policy
// coverage when a policy that requires MFA or blocks sign-ins includes or
// excludes a group or a directory role.
const groupOrRoleMembersUnread = "An MFA policy includes or excludes a group or a directory role, and this collector does not match their members to the policy. Microsoft Graph lists group members at /groups/{id}/transitiveMembers and role holders at /roleManagement/directory/roleAssignments."

// mfaPolicyCoveredCount counts the enabled members whose every sign-in the
// enabled policies, between them, require MFA for or block, as
// signInSpace.covers checks. Group members and role holders are not read,
// and some conditions can't be evaluated, so the count is taken twice: at
// best each member is in every group and role a policy includes and none it
// excludes, and each condition is taken in the way that lets the policy
// apply, and at worst the reverse. When the two differ, or the check ran
// over its budget, the count is unknown and the reason is returned instead.
func mfaPolicyCoveredCount(enabledMemberIDs map[string]struct{}, policies []microsoft.ConditionalAccessPolicy, space *signInSpace) (*int, *missing) {
	protecting := policiesThat(policies, func(policy microsoft.ConditionalAccessPolicy) bool {
		return policy.Conditions.Users != nil && protectsAt(policy, true)
	})
	// The same policies apply to every member no policy names by ID, so
	// they are checked once. The members a policy names are checked one by
	// one, and a set of policies once for all who share it.
	named := map[string]struct{}{}
	for _, policy := range protecting {
		for _, id := range append(slices.Clone(policy.Conditions.Users.IncludeUsers), policy.Conditions.Users.ExcludeUsers...) {
			if _, member := enabledMemberIDs[id]; member {
				named[id] = struct{}{}
			}
		}
	}
	checked := map[string]bool{}
	covered := func(id string, best bool) bool {
		var key strings.Builder
		fmt.Fprint(&key, best)
		var mine []microsoft.ConditionalAccessPolicy
		for i, policy := range protecting {
			if appliesTo(policy, id, best) {
				mine = append(mine, policy)
				fmt.Fprint(&key, ",", i)
			}
		}
		result, ok := checked[key.String()]
		if !ok {
			result = space.covers(mine, clientAppTypes, protectsAt, best)
			checked[key.String()] = result
		}
		return result
	}
	atWorst, atBest := 0, 0
	unnamed := len(enabledMemberIDs) - len(named)
	if covered("", false) {
		atWorst += unnamed
	}
	if covered("", true) {
		atBest += unnamed
	}
	for id := range named {
		if covered(id, false) {
			atWorst++
		}
		if covered(id, true) {
			atBest++
		}
	}
	switch {
	case space.overBudget:
		return nil, notRead(overBudgetDetail)
	case atWorst != atBest:
		return nil, notRead(space.doubtsAbout(protecting, true))
	}
	return intPtr(atWorst), nil
}

// appliesTo reports whether a policy applies to the member with id. A policy
// applies to a member it includes as All or by ID and doesn't exclude by ID.
// For the groups and roles it names, atBest says whether the member is in
// every one it includes and none it excludes, or the reverse.
func appliesTo(policy microsoft.ConditionalAccessPolicy, id string, atBest bool) bool {
	users := policy.Conditions.Users
	if slices.Contains(users.ExcludeUsers, id) {
		return false
	}
	if !atBest && (len(users.ExcludeGroups) > 0 || len(users.ExcludeRoles) > 0) {
		return false
	}
	return targetsAllUsers(policy) || slices.Contains(users.IncludeUsers, id) ||
		(atBest && (len(users.IncludeGroups) > 0 || len(users.IncludeRoles) > 0))
}

// securityDefaultsGroupMembersUnread is the detail of the gap on the MFA
// policy coverage under security defaults when a group holds one of the
// admin roles they name.
const securityDefaultsGroupMembersUnread = "Security defaults require MFA of the admin roles they name, and one of those roles is assigned to a group whose members hold it too. Microsoft Graph lists them at /groups/{id}/transitiveMembers, which this collector does not read."

// securityDefaultsCoveredCount counts the enabled members security defaults
// require MFA of on every sign-in: those who hold one of the admin roles
// they name. Security defaults require MFA of other users only when
// Microsoft judges a sign-in risky, so those users are not covered. It
// returns why the count is unknown instead when it is.
// https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults#require-administrators-to-do-multifactor-authentication
func securityDefaultsCoveredCount(defaults *SecurityDefaults, defaultsMiss *missing, enabledMemberIDs map[string]struct{}, roles roleAssignmentList) (*int, *missing) {
	switch {
	case defaults == nil:
		return nil, defaultsMiss
	case !defaults.Enabled:
		return intPtr(0), nil
	case roles.miss != nil:
		return nil, roles.miss
	}
	admins := map[string]struct{}{}
	groupHeld := false
	for _, assignment := range roles.assignments {
		if _, ok := securityDefaultsRoleTemplateIDs[roleTemplateIDFromAssignment(assignment)]; !ok {
			continue
		}
		if assignedToGroup(assignment) {
			groupHeld = true
			continue
		}
		if _, ok := enabledMemberIDs[assignment.PrincipalID]; ok {
			admins[assignment.PrincipalID] = struct{}{}
		}
	}
	if groupHeld && len(admins) < len(enabledMemberIDs) {
		return nil, notRead(securityDefaultsGroupMembersUnread)
	}
	return intPtr(len(admins)), nil
}

// securityDefaultsBlockLegacyAuth reports whether security defaults block
// legacy authentication, which they do for everyone while they are on. It is
// nil when they were not read.
// https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults#blocking-legacy-authentication-protocols
func securityDefaultsBlockLegacyAuth(defaults *SecurityDefaults) *bool {
	if defaults == nil {
		return nil
	}
	return boolPtr(defaults.Enabled)
}

func targetsAllUsers(policy microsoft.ConditionalAccessPolicy) bool {
	if policy.Conditions.Users == nil {
		return false
	}
	return containsFold(policy.Conditions.Users.IncludeUsers, "All")
}

// targetsEveryApp reports whether a policy applies to sign-ins to every app:
// it includes all of them, excludes none and has no app filter.
func targetsEveryApp(policy microsoft.ConditionalAccessPolicy) bool {
	apps := policy.Conditions.Applications
	return apps != nil && containsFold(apps.IncludeApplications, "All") &&
		len(apps.ExcludeApplications) == 0 && apps.ApplicationFilter == nil
}

func targetsAdminPortals(policy microsoft.ConditionalAccessPolicy) bool {
	if policy.Conditions.Applications == nil {
		return false
	}
	apps := policy.Conditions.Applications
	if containsFold(apps.ExcludeApplications, "MicrosoftAdminPortals") {
		return false
	}
	return containsFold(apps.IncludeApplications, "MicrosoftAdminPortals") ||
		containsFold(apps.IncludeApplications, "All")
}

func targetsAdminOrPrivilegedAccess(policy microsoft.ConditionalAccessPolicy) bool {
	if targetsAdminPortals(policy) || targetsAllUsers(policy) {
		return true
	}
	if policy.Conditions.Users == nil {
		return false
	}
	return len(policy.Conditions.Users.IncludeRoles) > 0
}

func requiresMFA(policy microsoft.ConditionalAccessPolicy) bool {
	return grantRequires(policy, isMFAControl)
}

func requiresCompliantDevice(policy microsoft.ConditionalAccessPolicy) bool {
	return grantRequires(policy, func(control grantControl) bool {
		return strings.EqualFold(control.builtIn, "compliantDevice") || strings.EqualFold(control.builtIn, "domainJoinedDevice")
	})
}

// requiresMFAOnEverySignIn reports whether a policy requires MFA on every
// sign-in of the users and apps it targets, from every kind of client.
func requiresMFAOnEverySignIn(policy microsoft.ConditionalAccessPolicy, legacyAuthBlocked bool) bool {
	return requiresMFA(policy) && appliesToEverySignIn(policy) && coversEveryClient(policy, legacyAuthBlocked)
}

// coversEveryClient reports whether a policy applies to sign-ins from every
// kind of client. With the client apps condition unset or set to all, it
// does. Legacy clients, Exchange ActiveSync and other, can't do MFA, so a
// policy for browsers and mobile apps and desktop clients also covers every
// client once a policy blocks legacy authentication.
// https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#client-apps
func coversEveryClient(policy microsoft.ConditionalAccessPolicy, legacyAuthBlocked bool) bool {
	types := policy.Conditions.ClientAppTypes
	if len(types) == 0 || containsFold(types, "all") {
		return true
	}
	modern := containsFold(types, "browser") && containsFold(types, "mobileAppsAndDesktopClients")
	legacy := containsFold(types, "exchangeActiveSync") && containsFold(types, "other")
	return modern && (legacy || legacyAuthBlocked)
}

// appliesToEverySignIn reports whether a policy applies to every sign-in of
// the users and resources it targets. A risk level, location, platform,
// device or authentication flow condition limits a policy to the sign-ins
// that meet it. A policy for a user action, such as registering security
// information, applies to that action alone.
// https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset
func appliesToEverySignIn(policy microsoft.ConditionalAccessPolicy) bool {
	conditions := policy.Conditions
	if len(conditions.Unrecognized) > 0 || !forUserSignIns(policy) {
		return false
	}
	if len(conditions.SignInRiskLevels) > 0 || len(conditions.UserRiskLevels) > 0 ||
		len(conditions.ServicePrincipalRiskLevels) > 0 || conditions.InsiderRiskLevels != "" {
		return false
	}
	if locations := conditions.Locations; locations != nil && narrows(locations.IncludeLocations, locations.ExcludeLocations, "All") {
		return false
	}
	if platforms := conditions.Platforms; platforms != nil && narrows(platforms.IncludePlatforms, platforms.ExcludePlatforms, "all") {
		return false
	}
	if devices := conditions.Devices; devices != nil && devices.DeviceFilter != nil && strings.TrimSpace(devices.DeviceFilter.Rule) != "" {
		return false
	}
	if flows := conditions.AuthenticationFlows; flows != nil && flows.TransferMethods != "" && !strings.EqualFold(flows.TransferMethods, "none") {
		return false
	}
	return conditions.Applications == nil || len(conditions.Applications.IncludeUserActions) == 0
}

// narrows reports whether a condition's include and exclude lists limit it
// to some values. With both lists empty the condition is not set. An include
// list that holds all and an empty exclude list cover every value.
func narrows(include, exclude []string, all string) bool {
	return len(exclude) > 0 || (len(include) > 0 && !containsFold(include, all))
}

// grantControl is a built-in control, an authentication strength, a custom
// control or terms of use in a policy's grant.
type grantControl struct {
	builtIn  string
	strength *microsoft.AuthenticationStrengthPolicy
}

func grantControls(policy microsoft.ConditionalAccessPolicy) []grantControl {
	grant := policy.GrantControls
	if grant == nil {
		return nil
	}
	var controls []grantControl
	for _, control := range grant.BuiltInControls {
		controls = append(controls, grantControl{builtIn: control})
	}
	if grant.AuthenticationStrength != nil {
		controls = append(controls, grantControl{strength: grant.AuthenticationStrength})
	}
	for range len(grant.CustomAuthenticationFactors) + len(grant.TermsOfUse) {
		controls = append(controls, grantControl{})
	}
	return controls
}

// grantRequires reports whether a user the policy covers must satisfy a
// control that meets want. With the AND operator one such control is enough.
// With OR, a user can pass with any one of the controls, so all of them must
// meet want.
// https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols
func grantRequires(policy microsoft.ConditionalAccessPolicy, want func(grantControl) bool) bool {
	controls := grantControls(policy)
	if len(controls) == 0 {
		return false
	}
	if !strings.EqualFold(policy.GrantControls.Operator, "OR") {
		return slices.ContainsFunc(controls, want)
	}
	for _, control := range controls {
		if !want(control) {
			return false
		}
	}
	return true
}

// isMFAControl reports whether a control requires MFA. That is the built-in
// mfa control, or an authentication strength whose requirementsSatisfied is
// mfa. The built-in Multifactor authentication strength is one, and a custom
// strength is one when it grants the MFA claim.
// https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy
func isMFAControl(control grantControl) bool {
	if control.strength != nil {
		return strings.EqualFold(control.strength.RequirementsSatisfied, "mfa")
	}
	return strings.EqualFold(control.builtIn, "mfa")
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func boolPtr(value bool) *bool {
	return &value
}

func intPtr(value int) *int {
	return &value
}
