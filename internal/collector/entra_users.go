package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func (c *Collector) collectEntra(ctx context.Context, level componentsdk.Level, org *microsoft.Organization, diagnostics *Diagnostics) *EntraArtifact {
	users, usersMiss := c.users(ctx, diagnostics)
	summary := summarizeUsers(users)
	registrations, registrationsMiss := c.mfaRegistrationDetails(ctx, diagnostics)
	signInUsers, signInMiss := c.usersWithSignInActivity(ctx, diagnostics)

	artifact := &EntraArtifact{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      c.clock.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CollectedAtLevel: string(level),
		TenantID:         org.ID,
		OrgDomain:        org.PrimaryDomain(),
	}

	if usersMiss == nil {
		artifact.Users.TotalCount = intPtr(summary.TotalCount)
		artifact.Users.EnabledMemberUsersCount = intPtr(len(summary.EnabledMemberIDs))
		artifact.Users.GuestPct = PercentInt(summary.GuestCount, summary.TotalCount)
		artifact.Users.DisabledPct = PercentInt(summary.DisabledCount, summary.TotalCount)
		artifact.Users.disabledCount = intPtr(summary.DisabledCount)
	}
	c.gaps.leaveOut(entraPath, usersMiss,
		"/users/total_count", "/users/enabled_member_users_count", "/users/guest_pct", "/users/disabled_pct")

	if why := firstMissing(usersMiss, registrationsMiss); why != nil {
		c.gaps.leaveOut(entraPath, why,
			"/posture/denominator_enabled_member_users",
			"/posture/mfa_coverage", "/posture/mfa_phishing_resistant",
			"/posture/mfa_weak_method_only", "/posture/sspr_registered")
	} else {
		registrationMetrics := computeRegistrationMetrics(summary.EnabledMemberIDs, registrations)
		artifact.Posture.DenominatorEnabledMemberUsers = intPtr(registrationMetrics.Listed)
		artifact.Posture.MFACoverage = registrationMetrics.MFACoverage
		artifact.Posture.MFAPhishingResistant = registrationMetrics.MFAPhishingResistant
		artifact.Posture.MFAWeakMethodOnly = registrationMetrics.MFAWeakMethodOnly
		artifact.Posture.SSPRRegistered = registrationMetrics.SSPRRegistered
		artifact.Posture.mfaRegisteredCount = intPtr(registrationMetrics.Registered)
		artifact.Posture.phishingResistantCount = intPtr(registrationMetrics.PhishingResistant)
	}

	if signInMiss == nil {
		enabled := countInactive(signInUsers, func(user microsoft.User) bool {
			return user.AccountEnabled != nil && *user.AccountEnabled
		}, c.clock.Now())
		artifact.Users.InactivePct = enabled.pct()
		artifact.Users.inactiveCount = intPtr(enabled.inactive)
		artifact.Users.signInEnabledCount = intPtr(enabled.total)
		artifact.Users.InactiveGuestPct = countInactive(signInUsers, func(user microsoft.User) bool {
			return user.AccountEnabled != nil && *user.AccountEnabled && user.UserType == "Guest"
		}, c.clock.Now()).pct()
	}
	c.gaps.leaveOut(entraPath, signInMiss, "/users/inactive_pct", "/users/inactive_guest_pct")

	artifact.Policy, artifact.SecurityDefaults = c.collectPolicy(ctx, diagnostics, summary.EnabledMemberIDs, usersMiss)
	artifact.PrivilegedAccess = c.collectPrivilegedAccess(ctx, diagnostics, privilegedSources{
		users:             users,
		usersMiss:         usersMiss,
		signInUsers:       signInUsers,
		signInMiss:        signInMiss,
		registrations:     registrations,
		registrationsMiss: registrationsMiss,
	})
	var appCreds appCredentials
	artifact.Apps, appCreds = c.collectApps(ctx, diagnostics)
	if artifact.Apps != nil {
		artifact.Posture.SSOCoverage = artifact.Apps.SSOCoveragePct
	}
	artifact.SecureScore = c.collectSecureScore(ctx, diagnostics)
	artifact.DirectoryActivity = c.collectDirectoryActivity(ctx, level, diagnostics)
	artifact.SignInMonitoring = c.collectSignInMonitoring(ctx, level, diagnostics)
	artifact.Diagnostics = *diagnostics
	artifact.directory = directory{
		users:      usersByID(users),
		usersMiss:  usersMiss,
		signIns:    usersByID(signInUsers),
		signInMiss: signInMiss,
		apps:       appCreds,
	}
	return artifact
}

func (c *Collector) users(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.User, *missing) {
	users, err := c.graph.Users(ctx)
	if err != nil {
		diagnostics.warnNotCollected("Entra users", err)
		return nil, failed(err)
	}
	return users, nil
}

func (c *Collector) mfaRegistrationDetails(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UserRegistrationDetail, *missing) {
	report, err := c.graph.UserRegistrationDetails(ctx)
	switch {
	case err == nil:
		return report, nil
	case microsoft.IsPremiumLicenseError(err):
		diagnostics.Warn("Entra ID P1/P2 not licensed, mfa registration report reported as not_collected")
		diagnostics.MarkCapabilityUnavailable("mfa_registration_report")
		return nil, unlicensed("The MFA registration report requires Entra ID P1 or P2.")
	case permissionDenied(err):
		diagnostics.Warn("graph permission AuditLog.Read.All not granted, mfa registration report skipped")
		diagnostics.MarkCapabilityUnavailable("mfa_registration_report")
	default:
		diagnostics.warnNotCollected("MFA registration report", err)
	}
	return nil, failed(err)
}

type userSummary struct {
	TotalCount       int
	EnabledMemberIDs map[string]struct{}
	GuestCount       int
	DisabledCount    int
}

func summarizeUsers(users []microsoft.User) userSummary {
	summary := userSummary{TotalCount: len(users), EnabledMemberIDs: map[string]struct{}{}}
	for _, user := range users {
		if user.UserType == "Guest" {
			summary.GuestCount++
		}
		if user.AccountEnabled != nil && !*user.AccountEnabled {
			summary.DisabledCount++
		}
		if user.ID != "" && user.EnabledMember() {
			summary.EnabledMemberIDs[user.ID] = struct{}{}
		}
	}
	return summary
}

type registrationMetrics struct {
	Listed               int
	Registered           int
	PhishingResistant    int
	MFACoverage          *int
	MFAPhishingResistant *int
	MFAWeakMethodOnly    *int
	SSPRRegistered       *int
}

// computeRegistrationMetrics measures only the enabled members the
// registration report lists. The report lags the live user list, so a member
// created since its last refresh is outside the population rather than
// counted as unregistered.
func computeRegistrationMetrics(enabledMemberIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) registrationMetrics {
	listed := map[string]microsoft.UserRegistrationDetail{}
	for _, registration := range registrations {
		if _, ok := enabledMemberIDs[registration.ID]; ok {
			listed[registration.ID] = registration
		}
	}
	registered := 0
	phishingResistant := 0
	weakOnly := 0
	ssprRegistered := 0
	for _, registration := range listed {
		if registration.IsMFARegistered {
			registered++
		}
		if hasPhishingResistantMethod(registration.MethodsRegistered) {
			phishingResistant++
		}
		if registration.IsMFARegistered && hasOnlyWeakMFAMethods(registration.MethodsRegistered) {
			weakOnly++
		}
		if registration.IsSSPRRegistered {
			ssprRegistered++
		}
	}
	return registrationMetrics{
		Listed:               len(listed),
		Registered:           registered,
		PhishingResistant:    phishingResistant,
		MFACoverage:          PercentInt(registered, len(listed)),
		MFAPhishingResistant: PercentInt(phishingResistant, len(listed)),
		MFAWeakMethodOnly:    PercentInt(weakOnly, len(listed)),
		SSPRRegistered:       PercentInt(ssprRegistered, len(listed)),
	}
}

func hasPhishingResistantMethod(methods []string) bool {
	for _, method := range methods {
		normalized := strings.ToLower(method)
		if strings.Contains(normalized, "fido") ||
			strings.Contains(normalized, "windowshelloforbusiness") ||
			strings.Contains(normalized, "passkey") ||
			strings.Contains(normalized, "certificate") {
			return true
		}
	}
	return false
}

func hasOnlyWeakMFAMethods(methods []string) bool {
	if len(methods) == 0 {
		return false
	}
	for _, method := range methods {
		if !isWeakMFAMethod(method) {
			return false
		}
	}
	return true
}

// phoneMethods are the methodsRegistered values for a phone number, used for
// SMS or a voice call.
var phoneMethods = []string{"mobilePhone", "alternateMobilePhone", "officePhone"}

func isWeakMFAMethod(method string) bool {
	normalized := strings.ToLower(method)
	return strings.Contains(normalized, "sms") ||
		strings.Contains(normalized, "voice") ||
		strings.Contains(normalized, "email") ||
		containsFold(phoneMethods, method)
}

func (c *Collector) usersWithSignInActivity(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.User, *missing) {
	users, err := c.graph.UsersWithSignInActivity(ctx)
	switch {
	case err == nil:
		return users, nil
	case microsoft.IsPremiumLicenseError(err):
		diagnostics.Warn("Entra ID P1 not licensed, sign_in_activity reported as license_absent")
		diagnostics.MarkCapabilityUnavailable("sign_in_activity")
		return nil, unlicensed("Sign-in activity requires Entra ID P1 or P2.")
	case permissionDenied(err):
		diagnostics.Warn("graph permission AuditLog.Read.All not granted, sign-in activity skipped")
		diagnostics.MarkCapabilityUnavailable("sign_in_activity")
	default:
		diagnostics.warnNotCollected("Entra sign-in activity", err)
	}
	return nil, failed(err)
}

// inactivity counts the users a filter includes and those of them with no
// successful sign-in in the last 90 days.
type inactivity struct{ total, inactive int }

func (i inactivity) pct() *int { return PercentInt(i.inactive, i.total) }

func countInactive(users []microsoft.User, include func(microsoft.User) bool, now time.Time) inactivity {
	var out inactivity
	cutoff := inactiveCutoff(now)
	for _, user := range users {
		if !include(user) {
			continue
		}
		out.total++
		if !signedInSince(user, cutoff) {
			out.inactive++
		}
	}
	return out
}

func inactiveCutoff(now time.Time) time.Time { return now.AddDate(0, 0, -90) }

// signedInSince reports whether the user's last successful sign-in is at or
// after cutoff. A failed sign-in attempt does not count.
func signedInSince(user microsoft.User, cutoff time.Time) bool {
	if user.SignInActivity == nil || user.SignInActivity.LastSuccessfulSignInDateTime == "" {
		return false
	}
	lastSignIn, err := time.Parse(time.RFC3339, user.SignInActivity.LastSuccessfulSignInDateTime)
	return err == nil && !lastSignIn.Before(cutoff)
}
