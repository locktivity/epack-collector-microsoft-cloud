package collector

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectPolicy(ctx context.Context, diagnostics *Diagnostics, enabledMemberIDs map[string]struct{}) (*Policy, *SecurityDefaults, error) {
	policies, caAvailable, err := c.conditionalAccessPolicies(ctx, diagnostics)
	if err != nil {
		return nil, nil, err
	}

	securityDefaults, _, err := c.securityDefaults(ctx, diagnostics)
	if err != nil {
		return nil, nil, err
	}

	var defaults *SecurityDefaults
	if securityDefaults != nil {
		defaults = &SecurityDefaults{Enabled: securityDefaults.IsEnabled}
	}

	return computePolicy(policies, caAvailable, defaults, enabledMemberIDs), defaults, nil
}

func (c *Collector) conditionalAccessPolicies(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.ConditionalAccessPolicy, bool, error) {
	policies, err := c.graph.ConditionalAccessPolicies(ctx)
	if err == nil {
		return policies, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if microsoft.IsPremiumLicenseError(err) {
			diagnostics.Warn("Entra ID P1 not licensed, conditional_access reported as license_absent")
			diagnostics.MarkCapabilityUnavailable("conditional_access")
			return nil, false, nil
		}
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission Policy.Read.All not granted, conditional access skipped")
			diagnostics.MarkCapabilityUnavailable("conditional_access")
			return nil, false, nil
		}
	}
	return nil, false, err
}

func (c *Collector) securityDefaults(ctx context.Context, diagnostics *Diagnostics) (*microsoft.IdentitySecurityDefaultsEnforcementPolicy, bool, error) {
	defaults, err := c.graph.SecurityDefaults(ctx)
	if err == nil {
		return defaults, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		diagnostics.Warn("graph permission Policy.Read.All not granted, security defaults skipped")
		diagnostics.MarkCapabilityUnavailable("security_defaults")
		return nil, false, nil
	}
	return nil, false, err
}

func computePolicy(policies []microsoft.ConditionalAccessPolicy, caAvailable bool, defaults *SecurityDefaults, enabledMemberIDs map[string]struct{}) *Policy {
	if !caAvailable {
		if defaults == nil {
			return nil
		}
		return &Policy{
			MFARequiredCoveragePct: securityDefaultsCoverage(defaults),
		}
	}

	enabledPolicies := enabledConditionalAccessPolicies(policies)
	policyCount := len(enabledPolicies)
	mfaRequired := false
	adminPortalsMFARequired := false
	allCloudAppsMFARequired := false
	compliantDeviceRequired := false
	legacyAuthBlocked := false

	for _, policy := range enabledPolicies {
		requiresMFA := requiresGrantControl(policy, "mfa")
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
		MFARequiredCoveragePct:  computeMFAPolicyCoverage(enabledMemberIDs, enabledPolicies),
		AdminPortalsMFARequired: boolPtr(adminPortalsMFARequired),
		AllCloudAppsMFARequired: boolPtr(allCloudAppsMFARequired),
		CompliantDeviceRequired: boolPtr(compliantDeviceRequired),
		LegacyAuthBlocked:       boolPtr(legacyAuthBlocked),
		PolicyCount:             intPtr(policyCount),
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

func computeMFAPolicyCoverage(enabledMemberIDs map[string]struct{}, policies []microsoft.ConditionalAccessPolicy) *int {
	if len(enabledMemberIDs) == 0 {
		return nil
	}

	covered := map[string]struct{}{}
	for _, policy := range policies {
		if !requiresGrantControl(policy, "mfa") {
			continue
		}
		policyCovered := map[string]struct{}{}
		if targetsAllUsers(policy) {
			for id := range enabledMemberIDs {
				policyCovered[id] = struct{}{}
			}
			for _, id := range policy.Conditions.Users.ExcludeUsers {
				delete(policyCovered, id)
			}
		} else if policy.Conditions.Users != nil {
			for _, id := range policy.Conditions.Users.IncludeUsers {
				if _, ok := enabledMemberIDs[id]; ok {
					policyCovered[id] = struct{}{}
				}
			}
		}
		for id := range policyCovered {
			covered[id] = struct{}{}
		}
	}
	return PercentInt(len(covered), len(enabledMemberIDs))
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

func requiresCompliantDevice(policy microsoft.ConditionalAccessPolicy) bool {
	return requiresGrantControl(policy, "compliantDevice") ||
		requiresGrantControl(policy, "domainJoinedDevice")
}

func blocksLegacyAuth(policy microsoft.ConditionalAccessPolicy) bool {
	if !requiresGrantControl(policy, "block") {
		return false
	}
	for _, clientAppType := range policy.Conditions.ClientAppTypes {
		if containsFold([]string{"all", "exchangeActiveSync", "other"}, clientAppType) {
			return true
		}
	}
	return false
}

func requiresGrantControl(policy microsoft.ConditionalAccessPolicy, control string) bool {
	if policy.GrantControls == nil {
		return false
	}
	return containsFold(policy.GrantControls.BuiltInControls, control)
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
