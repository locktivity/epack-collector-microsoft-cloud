package collector

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectPrivilegedAccess(
	ctx context.Context,
	diagnostics *Diagnostics,
	users []microsoft.User,
	signInUsers []microsoft.User,
	signInAvailable bool,
	registrations []microsoft.UserRegistrationDetail,
	registrationAvailable bool,
) (*PrivilegedAccess, error) {
	assignments, assignmentsAvailable, err := c.roleAssignments(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	if !assignmentsAvailable {
		return nil, nil
	}

	userByID := usersByID(users)
	privilegedUserIDs := map[string]struct{}{}
	superAdminIDs := map[string]struct{}{}
	privilegedAssignmentCount := 0
	for _, assignment := range assignments {
		roleTemplateID := roleTemplateIDFromAssignment(assignment)
		if !isPrivilegedRoleTemplateID(roleTemplateID) {
			continue
		}
		if _, ok := userByID[assignment.PrincipalID]; !ok {
			continue
		}
		privilegedAssignmentCount++
		privilegedUserIDs[assignment.PrincipalID] = struct{}{}
		if roleTemplateID == globalAdministratorTemplateID {
			superAdminIDs[assignment.PrincipalID] = struct{}{}
		}
	}

	out := &PrivilegedAccess{
		SuperAdminCount:      len(superAdminIDs),
		PrivilegedUsersCount: len(privilegedUserIDs),
		PrivilegedGuestCount: privilegedGuestCount(privilegedUserIDs, userByID),
	}
	if registrationAvailable {
		out.PrivilegedMFACoveragePct = privilegedMFACoverage(privilegedUserIDs, registrations)
		out.PrivilegedPhishingResistantPct = privilegedPhishingResistantCoverage(privilegedUserIDs, registrations)
		out.RootMFAEnabled = rootMFAEnabled(superAdminIDs, registrations)
	}
	if signInAvailable {
		out.InactivePrivilegedUsersCount = inactivePrivilegedUsersCount(privilegedUserIDs, signInUsers, c.clock.Now())
	}

	schedules, pimAvailable, err := c.roleEligibilitySchedules(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	if pimAvailable {
		eligibleCount := privilegedEligibilityScheduleCount(schedules)
		out.PIMEligiblePct = PercentInt(eligibleCount, eligibleCount+privilegedAssignmentCount)
		out.StandingAssignmentCount = intPtr(privilegedAssignmentCount)
	}
	return out, nil
}

func rootMFAEnabled(superAdminIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) *bool {
	registeredByID := map[string]bool{}
	for _, registration := range registrations {
		registeredByID[registration.ID] = registration.IsMFARegistered
	}
	enabled := true
	for id := range superAdminIDs {
		if !registeredByID[id] {
			enabled = false
			break
		}
	}
	return boolPtr(enabled)
}

func (c *Collector) roleAssignments(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UnifiedRoleAssignment, bool, error) {
	assignments, err := c.graph.RoleAssignments(ctx)
	if err == nil {
		return assignments, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		diagnostics.Warn("graph permission RoleManagement.Read.Directory not granted, privileged access skipped")
		diagnostics.MarkCapabilityUnavailable("privileged_access")
		return nil, false, nil
	}
	return nil, false, err
}

func (c *Collector) roleEligibilitySchedules(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UnifiedRoleEligibilitySchedule, bool, error) {
	schedules, err := c.graph.RoleEligibilitySchedules(ctx)
	if err == nil {
		return schedules, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if microsoft.IsPremiumLicenseError(err) {
			diagnostics.Warn("Entra ID P2 not licensed, pim reported as license_absent")
			diagnostics.MarkCapabilityUnavailable("pim")
			return nil, false, nil
		}
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission RoleEligibilitySchedule.Read.Directory not granted, PIM skipped")
			diagnostics.MarkCapabilityUnavailable("pim")
			return nil, false, nil
		}
	}
	return nil, false, err
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

func privilegedMFACoverage(privilegedUserIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) *int {
	if len(privilegedUserIDs) == 0 {
		return nil
	}
	registered := 0
	for _, registration := range registrations {
		if _, ok := privilegedUserIDs[registration.ID]; ok && registration.IsMFARegistered {
			registered++
		}
	}
	return PercentInt(registered, len(privilegedUserIDs))
}

func privilegedPhishingResistantCoverage(privilegedUserIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) *int {
	if len(privilegedUserIDs) == 0 {
		return nil
	}
	registered := 0
	for _, registration := range registrations {
		if _, ok := privilegedUserIDs[registration.ID]; ok && hasPhishingResistantMethod(registration.MethodsRegistered) {
			registered++
		}
	}
	return PercentInt(registered, len(privilegedUserIDs))
}

func inactivePrivilegedUsersCount(privilegedUserIDs map[string]struct{}, users []microsoft.User, now time.Time) *int {
	if len(privilegedUserIDs) == 0 {
		return nil
	}
	byID := usersByID(users)
	inactive := 0
	cutoff := now.AddDate(0, 0, -90)
	for id := range privilegedUserIDs {
		user, ok := byID[id]
		if !ok || user.SignInActivity == nil || user.SignInActivity.LastSignInDateTime == "" {
			inactive++
			continue
		}
		lastSignIn, err := time.Parse(time.RFC3339, user.SignInActivity.LastSignInDateTime)
		if err != nil || lastSignIn.Before(cutoff) {
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
