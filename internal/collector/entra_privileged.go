package collector

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type privilegedSources struct {
	roles             roleAssignmentList
	definitions       privilegedRoles
	definitionsMiss   *missing
	users             []microsoft.User
	usersMiss         *missing
	signInUsers       []microsoft.User
	signInMiss        *missing
	registrations     []microsoft.UserRegistrationDetail
	registrationsMiss *missing
}

func (c *Collector) collectPrivilegedAccess(ctx context.Context, diagnostics *Diagnostics, in privilegedSources) *PrivilegedAccess {
	assignments, roles := in.roles.assignments, in.definitions
	if why := firstMissing(in.roles.miss, in.definitionsMiss, in.usersMiss); why != nil {
		c.gaps.leaveOut(entraPath, why, "/privileged_access")
		return nil
	}

	userByID := usersByID(in.users)
	privilegedUserIDs := map[string]struct{}{}
	rolesByUser := map[string]map[string]struct{}{}
	superAdminIDs := map[string]struct{}{}
	privilegedAssignmentCount := 0
	var groupHeld, groupHeldGlobalAdmin, unclassifiedHeld bool
	unclassifiedUsers := map[string]struct{}{}
	for _, assignment := range assignments {
		roleTemplateID := roleTemplateIDFromAssignment(assignment)
		privileged, classified := roles.classify(roleTemplateID)
		if classified && !privileged {
			continue
		}
		if assignedToGroup(assignment) {
			groupHeld = true
			groupHeldGlobalAdmin = groupHeldGlobalAdmin || roleTemplateID == globalAdministratorTemplateID
			unclassifiedHeld = unclassifiedHeld || !classified
			continue
		}
		user, ok := userByID[assignment.PrincipalID]
		if !ok {
			continue
		}
		if !classified {
			unclassifiedHeld = true
			if !user.Disabled() {
				unclassifiedUsers[assignment.PrincipalID] = struct{}{}
			}
			continue
		}
		privilegedAssignmentCount++
		// A disabled account cannot sign in, so it is not a privileged user.
		// Its assignment still counts toward the PIM values.
		if user.Disabled() {
			continue
		}
		privilegedUserIDs[assignment.PrincipalID] = struct{}{}
		if rolesByUser[assignment.PrincipalID] == nil {
			rolesByUser[assignment.PrincipalID] = map[string]struct{}{}
		}
		rolesByUser[assignment.PrincipalID][roleTemplateID] = struct{}{}
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
	// A user who holds a role Microsoft hasn't classified, and no
	// privileged one, may or may not be privileged.
	for id := range unclassifiedUsers {
		if _, ok := privilegedUserIDs[id]; !ok {
			membersUnread = firstMissing(membersUnread, notRead(unclassifiedRoleHeld))
		}
	}
	var assignmentsUnclassified *missing
	if unclassifiedHeld {
		assignmentsUnclassified = notRead(unclassifiedRoleHeld)
	}
	if groupHeldGlobalAdmin {
		globalAdminsUnread = membersUnread
	}

	out := &PrivilegedAccess{userIDs: privilegedUserIDs}
	if globalAdminsUnread == nil {
		out.SuperAdminCount = intPtr(len(superAdminIDs))
	}
	c.gaps.leaveOut(entraPath, globalAdminsUnread, "/privileged_access/super_admin_count")
	if membersUnread == nil {
		out.PrivilegedUsersCount = intPtr(len(privilegedUserIDs))
	}
	guests, noType := privilegedGuestCount(privilegedUserIDs, userByID)
	guestsUnread := firstMissing(membersUnread, untyped(noType))
	if guestsUnread == nil {
		out.PrivilegedGuestCount = intPtr(guests)
	}
	out.privilegedUsersPresent = presentAtLeast(len(privilegedUserIDs), membersUnread)
	c.gaps.leaveOut(entraPath, membersUnread, "/privileged_access/privileged_users_count")
	c.gaps.leaveOut(entraPath, guestsUnread, "/privileged_access/privileged_guest_count")

	if why := firstMissing(in.registrationsMiss, membersUnread, unlistedPrivileged(privilegedUserIDs, in.registrations)); why == nil {
		mfa, phishingResistant := privilegedRegistrations(privilegedUserIDs, in.registrations)
		out.PrivilegedMFACoveragePct = PercentInt(mfa, len(privilegedUserIDs))
		out.PrivilegedPhishingResistantPct = PercentInt(phishingResistant, len(privilegedUserIDs))
		out.mfaRegisteredCount = intPtr(mfa)
		out.phishingResistantCount = intPtr(phishingResistant)
	} else {
		c.gaps.leaveOut(entraPath, why,
			"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct")
	}

	if why := firstMissing(in.registrationsMiss, globalAdminsUnread, unlistedPrivileged(superAdminIDs, in.registrations)); why == nil {
		out.globalAdminsMFA = globalAdminsMFARegistered(superAdminIDs, in.registrations)
	} else {
		out.globalAdminsMFAUnread = why
	}

	if why := firstMissing(in.signInMiss, membersUnread); why == nil {
		out.InactivePrivilegedUsersCount = inactivePrivilegedUsersCount(privilegedUserIDs, in.signInUsers, c.clock.Now())
	} else {
		c.gaps.leaveOut(entraPath, why, "/privileged_access/inactive_privileged_users_count")
	}

	schedules, schedulesMiss := c.roleEligibilitySchedules(ctx, diagnostics)
	if schedulesMiss == nil {
		eligibleCount, eligibleUnclassified := privilegedEligibilityScheduleCount(schedules, roles)
		if why := firstMissing(assignmentsUnclassified, eligibleUnclassified); why == nil {
			out.PIMEligiblePct = PercentInt(eligibleCount, eligibleCount+privilegedAssignmentCount)
			out.StandingAssignmentCount = intPtr(privilegedAssignmentCount)
		} else {
			c.gaps.leaveOut(entraPath, why, "/privileged_access/pim_eligible_pct", "/privileged_access/standing_assignment_count")
		}
		standing := standingPrivilegedUsers(rolesByUser, schedules, roles)
		if membersUnread == nil {
			out.standingPrivilegedUsersCount = intPtr(standing)
		}
		out.standingPrivilegedUsersPresent = presentAtLeast(standing, membersUnread)
	}
	c.gaps.leaveOut(entraPath, schedulesMiss, "/privileged_access/pim_eligible_pct", "/privileged_access/standing_assignment_count")
	return out
}

// presentAtLeast returns whether a population has any members, given the
// count of those read and why the rest were not. Any read member shows it
// has. With none read, it is nil when some were not read.
func presentAtLeast(read int, unread *missing) *bool {
	if read == 0 && unread != nil {
		return nil
	}
	return boolPtr(read > 0)
}

// unclassifiedRoleHeld is the detail of the gap on the privileged values
// when someone holds a directory role Microsoft's role definitions don't
// classify as privileged or not.
const unclassifiedRoleHeld = "A directory role someone holds has no privileged classification in Microsoft Graph's role definitions, so whether it counts as privileged isn't known."

// privilegedRoles classifies directory roles from Microsoft Graph's role
// definitions, by definition ID and template ID. A role is privileged when
// Microsoft marks it isPrivileged and some directory action it allows does
// more than read, so roles such as Global Reader don't count. A custom role
// is classified the same way.
// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions
type privilegedRoles map[string]bool

func classifyRoles(definitions []microsoft.UnifiedRoleDefinition) privilegedRoles {
	out := privilegedRoles{}
	for _, definition := range definitions {
		if definition.IsPrivileged == nil {
			continue
		}
		privileged := *definition.IsPrivileged && !onlyReads(definition)
		for _, id := range []string{definition.ID, definition.TemplateID} {
			if id != "" {
				out[id] = privileged
			}
		}
	}
	return out
}

// classify returns whether the role with id is privileged, and false for
// classified when Microsoft hasn't classified it or the definitions don't
// list it. Global Administrator is privileged whatever the definitions say.
func (r privilegedRoles) classify(id string) (privileged, classified bool) {
	if id == globalAdministratorTemplateID {
		return true, true
	}
	privileged, classified = r[id]
	return privileged, classified
}

// onlyReads reports whether every directory action a role allows reads: its
// last segment ends in read, as in standard/read or restrictedRead, or starts
// with get. A role that lists no action at all doesn't show that it only
// reads, so Microsoft's classification stands.
func onlyReads(definition microsoft.UnifiedRoleDefinition) bool {
	if !slices.ContainsFunc(definition.RolePermissions, func(p microsoft.UnifiedRolePermission) bool { return len(p.AllowedResourceActions) > 0 }) {
		return false
	}
	for _, permission := range definition.RolePermissions {
		for _, action := range permission.AllowedResourceActions {
			if !strings.HasPrefix(action, "microsoft.directory/") {
				continue
			}
			last := action[strings.LastIndex(action, "/")+1:]
			if !strings.HasSuffix(strings.ToLower(last), "read") && !strings.HasPrefix(last, "get") {
				return false
			}
		}
	}
	return true
}

func (c *Collector) roleDefinitions(ctx context.Context, diagnostics *Diagnostics) (privilegedRoles, *missing) {
	definitions, err := c.graph.RoleDefinitions(ctx)
	switch {
	case err == nil:
		return classifyRoles(definitions), nil
	case permissionDenied(err):
		diagnostics.Warn("graph permission RoleManagement.Read.Directory not granted, privileged access skipped")
		diagnostics.MarkCapabilityUnavailable("privileged_access")
	default:
		diagnostics.warnNotCollected("Entra role definitions", err)
	}
	return nil, failed(err)
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

// privilegedGuestCount counts the privileged users who are guests, and those
// with no user type, who may be.
func privilegedGuestCount(privilegedUserIDs map[string]struct{}, userByID map[string]microsoft.User) (guests, noType int) {
	for id := range privilegedUserIDs {
		switch userByID[id].UserType {
		case "Guest":
			guests++
		case "":
			noType++
		}
	}
	return guests, noType
}

// unlistedPrivilegedUsers is the detail of the gap on the privileged MFA
// values when the registration report doesn't list every privileged user.
const unlistedPrivilegedUsers = "Microsoft's MFA registration report doesn't list every privileged user yet, so whether each of them has MFA isn't known. The report lists a new user after its next refresh."

// unlistedPrivileged returns why the privileged MFA values are unknown when
// the registration report leaves out a privileged user, or nil when it lists
// them all.
func unlistedPrivileged(privilegedUserIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) *missing {
	listed := 0
	for _, registration := range registrations {
		if _, ok := privilegedUserIDs[registration.ID]; ok {
			listed++
		}
	}
	if listed < len(privilegedUserIDs) {
		return vendorError(unlistedPrivilegedUsers)
	}
	return nil
}

// privilegedRegistrations counts the privileged users the registration
// report shows registered for MFA, and those registered for a
// phishing-resistant method.
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

// standingPrivilegedUsers counts the users in rolesByUser who hold a
// privileged role at all times. PIM lists an activated role both as an
// assignment and as the user's eligibility, so a user whose every privileged
// role is also one they are eligible for has activated it just in time and
// doesn't count.
func standingPrivilegedUsers(rolesByUser map[string]map[string]struct{}, schedules []microsoft.UnifiedRoleEligibilitySchedule, roles privilegedRoles) int {
	eligible := map[string]map[string]struct{}{}
	for _, schedule := range schedules {
		role := roleTemplateIDFromSchedule(schedule)
		if privileged, _ := roles.classify(role); !privileged {
			continue
		}
		if eligible[schedule.PrincipalID] == nil {
			eligible[schedule.PrincipalID] = map[string]struct{}{}
		}
		eligible[schedule.PrincipalID][role] = struct{}{}
	}
	count := 0
	for user, roles := range rolesByUser {
		for role := range roles {
			if _, ok := eligible[user][role]; !ok {
				count++
				break
			}
		}
	}
	return count
}

// privilegedEligibilityScheduleCount counts the eligibility schedules for
// privileged roles, and returns why the count is unknown when one is for a
// role Microsoft hasn't classified.
func privilegedEligibilityScheduleCount(schedules []microsoft.UnifiedRoleEligibilitySchedule, roles privilegedRoles) (int, *missing) {
	count := 0
	var unclassified *missing
	for _, schedule := range schedules {
		privileged, classified := roles.classify(roleTemplateIDFromSchedule(schedule))
		if !classified {
			unclassified = notRead(unclassifiedRoleHeld)
		}
		if privileged {
			count++
		}
	}
	return count, unclassified
}
