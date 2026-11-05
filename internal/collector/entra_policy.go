package collector

import (
	"context"
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

func (c *Collector) collectPolicy(ctx context.Context, diagnostics *Diagnostics, enabledMemberIDs map[string]struct{}, usersMiss *missing) (*Policy, *SecurityDefaults) {
	policies, caMiss := c.conditionalAccessPolicies(ctx, diagnostics)
	securityDefaults, defaultsMiss := c.securityDefaults(ctx, diagnostics)

	var defaults *SecurityDefaults
	if securityDefaults != nil {
		defaults = &SecurityDefaults{Enabled: securityDefaults.IsEnabled}
	}
	c.gaps.leaveOut(entraPath, defaultsMiss, "/security_defaults")

	const coverage = "/policy/mfa_required_coverage_pct"
	if caMiss == nil {
		enabledPolicies := enabledConditionalAccessPolicies(policies)
		policy := computePolicy(enabledPolicies)
		switch {
		case usersMiss != nil:
			c.gaps.leaveOut(entraPath, usersMiss, coverage)
		case len(enabledPolicies) == 0:
			// Security defaults can be on only while no Conditional Access
			// policy is enabled, and then they are the tenant's MFA policy.
			if covered := securityDefaultsCoveredCount(defaults, enabledMemberIDs, usersMiss); covered != nil {
				policy.MFARequiredCoveragePct = PercentInt(*covered, len(enabledMemberIDs))
				policy.mfaRequiredUserCount = covered
			}
			c.gaps.leaveOut(entraPath, defaultsMiss, coverage)
		default:
			covered, unknown := mfaPolicyCoveredCount(enabledMemberIDs, enabledPolicies)
			if unknown != nil {
				c.gaps.leaveOut(entraPath, unknown, coverage)
				break
			}
			policy.MFARequiredCoveragePct = PercentInt(covered, len(enabledMemberIDs))
			policy.mfaRequiredUserCount = intPtr(covered)
		}
		return policy, defaults
	}

	c.gaps.leaveOut(entraPath, caMiss, conditionalAccessFields...)
	policy := &Policy{}
	switch {
	case caMiss.err == nil:
		// Without a Conditional Access license, security defaults are the
		// only MFA policy the tenant can have.
		policy.MFARequiredCoveragePct = securityDefaultsCoverage(defaults)
		policy.mfaRequiredUserCount = securityDefaultsCoveredCount(defaults, enabledMemberIDs, usersMiss)
		c.gaps.leaveOut(entraPath, defaultsMiss, coverage)
	case defaults != nil && defaults.Enabled:
		// Entra does not allow enabled Conditional Access policies while
		// security defaults are on, so the unread policies cannot change the
		// coverage.
		policy.MFARequiredCoveragePct = securityDefaultsCoverage(defaults)
		policy.mfaRequiredUserCount = securityDefaultsCoveredCount(defaults, enabledMemberIDs, usersMiss)
	default:
		c.gaps.leaveOut(entraPath, caMiss, coverage)
	}
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
// user list.
func computePolicy(enabledPolicies []microsoft.ConditionalAccessPolicy) *Policy {
	mfaRequired := false
	adminPortalsMFARequired := false
	allCloudAppsMFARequired := false
	compliantDeviceRequired := false
	legacyAuthBlocked := false

	for _, policy := range enabledPolicies {
		requiresMFA := requiresMFA(policy) && appliesToEverySignIn(policy)
		if requiresMFA && targetsAllUsers(policy) {
			mfaRequired = true
		}
		if requiresMFA && targetsAdminPortals(policy) {
			adminPortalsMFARequired = true
		}
		if requiresMFA && targetsAllCloudApps(policy) {
			allCloudAppsMFARequired = true
		}
		if requiresCompliantDevice(policy) && targetsAdminOrPrivilegedAccess(policy) {
			compliantDeviceRequired = true
		}
		if blocksLegacyAuth(policy) {
			legacyAuthBlocked = true
		}
	}

	return &Policy{
		MFARequired:             boolPtr(mfaRequired),
		AdminPortalsMFARequired: boolPtr(adminPortalsMFARequired),
		AllCloudAppsMFARequired: boolPtr(allCloudAppsMFARequired),
		CompliantDeviceRequired: boolPtr(compliantDeviceRequired),
		LegacyAuthBlocked:       boolPtr(legacyAuthBlocked),
		PolicyCount:             intPtr(len(enabledPolicies)),
	}
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
// coverage when a policy that requires MFA includes or excludes a group or a
// directory role.
const groupOrRoleMembersUnread = "An MFA policy includes or excludes a group or a directory role, and this collector does not match their members to the policy. Microsoft Graph lists group members at /groups/{id}/transitiveMembers and role holders at /roleManagement/directory/roleAssignments."

// mfaPolicyCoveredCount counts the enabled members that an enabled policy
// requiring MFA on every sign-in covers. A policy that includes or excludes a
// group or a role covers an unknown set of members. When the other policies
// leave members uncovered, the count is unknown and the reason is returned
// instead.
func mfaPolicyCoveredCount(enabledMemberIDs map[string]struct{}, policies []microsoft.ConditionalAccessPolicy) (int, *missing) {
	covered := map[string]struct{}{}
	groupsOrRoles := false
	for _, policy := range policies {
		users := policy.Conditions.Users
		if users == nil || !requiresMFA(policy) || !appliesToEverySignIn(policy) {
			continue
		}
		if len(users.ExcludeGroups) > 0 || len(users.ExcludeRoles) > 0 {
			groupsOrRoles = true
			continue
		}
		policyCovered := map[string]struct{}{}
		if targetsAllUsers(policy) {
			for id := range enabledMemberIDs {
				policyCovered[id] = struct{}{}
			}
			for _, id := range users.ExcludeUsers {
				delete(policyCovered, id)
			}
		} else {
			if len(users.IncludeGroups) > 0 || len(users.IncludeRoles) > 0 {
				groupsOrRoles = true
			}
			for _, id := range users.IncludeUsers {
				if _, ok := enabledMemberIDs[id]; ok {
					policyCovered[id] = struct{}{}
				}
			}
		}
		for id := range policyCovered {
			covered[id] = struct{}{}
		}
	}
	if groupsOrRoles && len(covered) < len(enabledMemberIDs) {
		return 0, notRead(groupOrRoleMembersUnread)
	}
	return len(covered), nil
}

// securityDefaultsCoveredCount counts the enabled members security defaults
// cover, which is all of them when security defaults are on. It is nil when
// the defaults or the user list were not read.
func securityDefaultsCoveredCount(defaults *SecurityDefaults, enabledMemberIDs map[string]struct{}, usersMiss *missing) *int {
	if defaults == nil || usersMiss != nil {
		return nil
	}
	if defaults.Enabled {
		return intPtr(len(enabledMemberIDs))
	}
	return intPtr(0)
}

func securityDefaultsCoverage(defaults *SecurityDefaults) *int {
	if defaults == nil {
		return nil
	}
	if defaults.Enabled {
		return intPtr(100)
	}
	return intPtr(0)
}

func targetsAllUsers(policy microsoft.ConditionalAccessPolicy) bool {
	if policy.Conditions.Users == nil {
		return false
	}
	return containsFold(policy.Conditions.Users.IncludeUsers, "All")
}

func targetsAllCloudApps(policy microsoft.ConditionalAccessPolicy) bool {
	if policy.Conditions.Applications == nil {
		return false
	}
	return containsFold(policy.Conditions.Applications.IncludeApplications, "All") &&
		!containsFold(policy.Conditions.Applications.ExcludeApplications, "All")
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

// blocksLegacyAuth reports whether a policy blocks legacy authentication as
// Microsoft's policy does. It must block access for all users and all
// resources, on both Exchange ActiveSync clients and other clients. It
// excludes no app, and its only condition is the client apps condition.
// https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication
func blocksLegacyAuth(policy microsoft.ConditionalAccessPolicy) bool {
	blocks := grantRequires(policy, func(control grantControl) bool { return strings.EqualFold(control.builtIn, "block") })
	if !blocks || !targetsAllUsers(policy) || !targetsAllCloudApps(policy) || !appliesToEverySignIn(policy) {
		return false
	}
	if apps := policy.Conditions.Applications; len(apps.ExcludeApplications) > 0 || apps.ApplicationFilter != nil {
		return false
	}
	clientAppTypes := policy.Conditions.ClientAppTypes
	return containsFold(clientAppTypes, "all") ||
		(containsFold(clientAppTypes, "exchangeActiveSync") && containsFold(clientAppTypes, "other"))
}

// appliesToEverySignIn reports whether a policy applies to every sign-in of
// the users and resources it targets. A risk level, location, platform,
// device or authentication flow condition limits a policy to the sign-ins
// that meet it. A policy for a user action, such as registering security
// information, applies to that action alone.
// https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset
func appliesToEverySignIn(policy microsoft.ConditionalAccessPolicy) bool {
	conditions := policy.Conditions
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
