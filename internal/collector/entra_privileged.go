package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type privilegedSources struct {
	users             []microsoft.User
	usersMiss         *missing
	signInUsers       []microsoft.User
	signInMiss        *missing
	registrations     []microsoft.UserRegistrationDetail
	registrationsMiss *missing
}

func (c *Collector) collectPrivilegedAccess(ctx context.Context, diagnostics *Diagnostics, in privilegedSources) *PrivilegedAccess {
	assignments, assignmentsMiss := c.roleAssignments(ctx, diagnostics)
	if why := firstMissing(assignmentsMiss, in.usersMiss); why != nil {
		c.gaps.leaveOut(entraPath, why, "/privileged_access")
		return nil
	}

	userByID := usersByID(in.users)
	privilegedUserIDs := map[string]struct{}{}
	superAdminIDs := map[string]struct{}{}
	privilegedAssignmentCount := 0
	var groupHeld, groupHeldGlobalAdmin bool
	for _, assignment := range assignments {
		roleTemplateID := roleTemplateIDFromAssignment(assignment)
		if !isPrivilegedRoleTemplateID(roleTemplateID) {
			continue
		}
		if assignedToGroup(assignment) {
			groupHeld = true
			groupHeldGlobalAdmin = groupHeldGlobalAdmin || roleTemplateID == globalAdministratorTemplateID
			continue
		}
		user, ok := userByID[assignment.PrincipalID]
		if !ok {
			continue
		}
		privilegedAssignmentCount++
		// A disabled account cannot sign in, so it is not a privileged user.
		// Its assignment still counts toward the PIM values.
		if user.Disabled() {
			continue
		}
		privilegedUserIDs[assignment.PrincipalID] = struct{}{}
		if roleTemplateID == globalAdministratorTemplateID {
			superAdminIDs[assignment.PrincipalID] = struct{}{}
		}
	}

	// A role assigned to a group is held by each of its members, and group
	// members are not read. The values over privileged users are then left
	// out. The Global Administrator count is left out too when that role is
	// assigned to a group.
	var membersUnread, globalAdminsUnread *missing
	if groupHeld {
		membersUnread = notRead(groupRoleMembersUnread)
	}
	if groupHeldGlobalAdmin {
		globalAdminsUnread = membersUnread
	}

	out := &PrivilegedAccess{}
	if globalAdminsUnread == nil {
		out.SuperAdminCount = intPtr(len(superAdminIDs))
	}
	c.gaps.leaveOut(entraPath, globalAdminsUnread, "/privileged_access/super_admin_count")
	if membersUnread == nil {
		out.PrivilegedUsersCount = intPtr(len(privilegedUserIDs))
		out.PrivilegedGuestCount = intPtr(privilegedGuestCount(privilegedUserIDs, userByID))
	}
	c.gaps.leaveOut(entraPath, membersUnread, "/privileged_access/privileged_users_count", "/privileged_access/privileged_guest_count")

	if why := firstMissing(in.registrationsMiss, membersUnread); why == nil {
		mfa, phishingResistant := privilegedRegistrations(privilegedUserIDs, in.registrations)
		out.PrivilegedMFACoveragePct = PercentInt(mfa, len(privilegedUserIDs))
		out.PrivilegedPhishingResistantPct = PercentInt(phishingResistant, len(privilegedUserIDs))
		out.mfaRegisteredCount = intPtr(mfa)
		out.phishingResistantCount = intPtr(phishingResistant)
	} else {
		c.gaps.leaveOut(entraPath, why,
			"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct")
	}

	if why := firstMissing(in.signInMiss, membersUnread); why == nil {
		out.InactivePrivilegedUsersCount = inactivePrivilegedUsersCount(privilegedUserIDs, in.signInUsers, c.clock.Now())
	} else {
		c.gaps.leaveOut(entraPath, why, "/privileged_access/inactive_privileged_users_count")
	}

	schedules, schedulesMiss := c.roleEligibilitySchedules(ctx, diagnostics)
	if schedulesMiss == nil {
		eligibleCount := privilegedEligibilityScheduleCount(schedules)
		out.PIMEligiblePct = PercentInt(eligibleCount, eligibleCount+privilegedAssignmentCount)
		out.StandingAssignmentCount = intPtr(privilegedAssignmentCount)
	}
	c.gaps.leaveOut(entraPath, schedulesMiss, "/privileged_access/pim_eligible_pct", "/privileged_access/standing_assignment_count")
	return out
}

// groupRoleMembersUnread is the detail of the gap on the values over
// privileged users when a privileged role is assigned to a group.
const groupRoleMembersUnread = "A privileged directory role is assigned to a group, and the users in it hold the role too. Microsoft Graph lists them at /groups/{id}/transitiveMembers, which this collector does not read."

// assignedToGroup reports whether a role assignment's principal is a group.
func assignedToGroup(assignment microsoft.UnifiedRoleAssignment) bool {
	return assignment.Principal != nil && strings.EqualFold(assignment.Principal.ODataType, "#microsoft.graph.group")
}

func (c *Collector) roleAssignments(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UnifiedRoleAssignment, *missing) {
	assignments, err := c.graph.RoleAssignments(ctx)
	switch {
	case err == nil:
		return assignments, nil
	case permissionDenied(err):
		diagnostics.Warn("graph permission RoleManagement.Read.Directory not granted, privileged access skipped")
		diagnostics.MarkCapabilityUnavailable("privileged_access")
	default:
		diagnostics.warnNotCollected("Entra role assignments", err)
	}
	return nil, failed(err)
}

func (c *Collector) roleEligibilitySchedules(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UnifiedRoleEligibilitySchedule, *missing) {
	schedules, err := c.graph.RoleEligibilitySchedules(ctx)
	switch {
	case err == nil:
		return schedules, nil
	case microsoft.IsPremiumLicenseError(err):
		diagnostics.Warn("Entra ID P2 not licensed, pim reported as license_absent")
		diagnostics.MarkCapabilityUnavailable("pim")
		return nil, unlicensed("PIM eligibility schedules require Entra ID P2 or Entra ID Governance.")
	case permissionDenied(err):
		diagnostics.Warn("graph permission RoleEligibilitySchedule.Read.Directory not granted, PIM skipped")
		diagnostics.MarkCapabilityUnavailable("pim")
	default:
		diagnostics.warnNotCollected("PIM eligibility schedules", err)
	}
	return nil, failed(err)
}

func usersByID(users []microsoft.User) map[string]microsoft.User {
	out := map[string]microsoft.User{}
	for _, user := range users {
		if user.ID != "" {
			out[user.ID] = user
		}
	}
	return out
}

func roleTemplateIDFromAssignment(assignment microsoft.UnifiedRoleAssignment) string {
	return assignment.RoleDefinitionID
}

func roleTemplateIDFromSchedule(schedule microsoft.UnifiedRoleEligibilitySchedule) string {
	if schedule.RoleDefinition != nil && schedule.RoleDefinition.TemplateID != "" {
		return schedule.RoleDefinition.TemplateID
	}
	return schedule.RoleDefinitionID
}

func isPrivilegedRoleTemplateID(templateID string) bool {
	_, ok := privilegedRoleTemplateIDs[templateID]
	return ok
}

func privilegedGuestCount(privilegedUserIDs map[string]struct{}, userByID map[string]microsoft.User) int {
	count := 0
	for id := range privilegedUserIDs {
		if userByID[id].UserType == "Guest" {
			count++
		}
	}
	return count
}

// privilegedRegistrations counts the privileged users the registration
// report shows registered for MFA, and those registered for a
// phishing-resistant method. A privileged user the report does not list
// counts as registered for neither.
func privilegedRegistrations(privilegedUserIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) (mfa, phishingResistant int) {
	for _, registration := range registrations {
		if _, ok := privilegedUserIDs[registration.ID]; !ok {
			continue
		}
		if registration.IsMFARegistered {
			mfa++
		}
		if hasPhishingResistantMethod(registration.MethodsRegistered) {
			phishingResistant++
		}
	}
	return mfa, phishingResistant
}

func inactivePrivilegedUsersCount(privilegedUserIDs map[string]struct{}, users []microsoft.User, now time.Time) *int {
	if len(privilegedUserIDs) == 0 {
		return nil
	}
	byID := usersByID(users)
	inactive := 0
	cutoff := inactiveCutoff(now)
	for id := range privilegedUserIDs {
		if user, ok := byID[id]; !ok || !signedInSince(user, cutoff) {
			inactive++
		}
	}
	return intPtr(inactive)
}

func privilegedEligibilityScheduleCount(schedules []microsoft.UnifiedRoleEligibilitySchedule) int {
	count := 0
	for _, schedule := range schedules {
		if isPrivilegedRoleTemplateID(roleTemplateIDFromSchedule(schedule)) {
			count++
		}
	}
	return count
}
