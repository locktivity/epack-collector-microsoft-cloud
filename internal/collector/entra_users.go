package collector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func (c *Collector) collectEntra(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) (*EntraArtifact, error) {
	org, err := c.graph.Organization(ctx)
	if err != nil {
		return nil, err
	}

	users, err := c.graph.Users(ctx)
	if err != nil {
		return nil, err
	}

	userSummary := summarizeUsers(users)
	mfaRegistrations, reportAvailable, err := c.mfaRegistrationDetails(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	signInUsers, signInAvailable, err := c.usersWithSignInActivity(ctx, diagnostics)
	if err != nil {
		return nil, err
	}

	policy, securityDefaults, err := c.collectPolicy(ctx, diagnostics, userSummary.EnabledMemberIDs)
	if err != nil {
		return nil, err
	}
	privilegedAccess, err := c.collectPrivilegedAccess(ctx, diagnostics, users, signInUsers, signInAvailable, mfaRegistrations, reportAvailable)
	if err != nil {
		return nil, err
	}
	apps, err := c.collectApps(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	secureScore, err := c.collectSecureScore(ctx, diagnostics)
	if err != nil {
		return nil, err
	}
	directoryActivity, err := c.collectDirectoryActivity(ctx, level, diagnostics)
	if err != nil {
		return nil, err
	}
	signInMonitoring, err := c.collectSignInMonitoring(ctx, level, diagnostics)
	if err != nil {
		return nil, err
	}

	artifact := &EntraArtifact{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      c.clock.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CollectedAtLevel: string(level),
		TenantID:         org.ID,
		OrgDomain:        org.PrimaryDomain(),
		Posture: Posture{
			DenominatorEnabledMemberUsers: len(userSummary.EnabledMemberIDs),
		},
		Users: Users{
			TotalCount:              userSummary.TotalCount,
			EnabledMemberUsersCount: len(userSummary.EnabledMemberIDs),
			GuestPct:                PercentInt(userSummary.GuestCount, userSummary.TotalCount),
			DisabledPct:             PercentInt(userSummary.DisabledCount, userSummary.TotalCount),
		},
		Policy:            policy,
		SecurityDefaults:  securityDefaults,
		PrivilegedAccess:  privilegedAccess,
		Apps:              apps,
		SecureScore:       secureScore,
		DirectoryActivity: directoryActivity,
		SignInMonitoring:  signInMonitoring,
	}

	if reportAvailable {
		registrationMetrics := computeRegistrationMetrics(userSummary.EnabledMemberIDs, mfaRegistrations)
		artifact.Posture.MFACoverage = registrationMetrics.MFACoverage
		artifact.Posture.MFAPhishingResistant = registrationMetrics.MFAPhishingResistant
		artifact.Posture.MFAWeakMethodOnly = registrationMetrics.MFAWeakMethodOnly
		artifact.Posture.SSPRRegistered = registrationMetrics.SSPRRegistered
	}
	if signInAvailable {
		artifact.Users.InactivePct = computeInactivePct(signInUsers, func(user microsoft.User) bool {
			return user.AccountEnabled != nil && *user.AccountEnabled
		}, c.clock.Now())
		artifact.Users.InactiveGuestPct = computeInactivePct(signInUsers, func(user microsoft.User) bool {
			return user.AccountEnabled != nil && *user.AccountEnabled && user.UserType == "Guest"
		}, c.clock.Now())
	}
	if apps != nil {
		artifact.Posture.SSOCoverage = apps.SSOCoveragePct
	}
	artifact.Diagnostics = *diagnostics
	return artifact, nil
}

func (c *Collector) mfaRegistrationDetails(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.UserRegistrationDetail, bool, error) {
	report, err := c.graph.UserRegistrationDetails(ctx)
	if err == nil {
		return report, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if microsoft.IsPremiumLicenseError(err) {
			diagnostics.Warn("Entra ID P1/P2 not licensed, mfa registration report reported as not_collected")
			diagnostics.MarkCapabilityUnavailable("mfa_registration_report")
			return nil, false, nil
		}
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission AuditLog.Read.All not granted, mfa registration report skipped")
			diagnostics.MarkCapabilityUnavailable("mfa_registration_report")
			return nil, false, nil
		}
	}
	return nil, false, err
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
	MFACoverage          *int
	MFAPhishingResistant *int
	MFAWeakMethodOnly    *int
	SSPRRegistered       *int
}

func computeRegistrationMetrics(enabledMemberIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) registrationMetrics {
	if len(enabledMemberIDs) == 0 {
		return registrationMetrics{}
	}
	registered := 0
	phishingResistant := 0
	weakOnly := 0
	ssprRegistered := 0
	for _, registration := range registrations {
		if registration.ID == "" {
			continue
		}
		if _, ok := enabledMemberIDs[registration.ID]; ok {
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
	}
	return registrationMetrics{
		MFACoverage:          PercentInt(registered, len(enabledMemberIDs)),
		MFAPhishingResistant: PercentInt(phishingResistant, len(enabledMemberIDs)),
		MFAWeakMethodOnly:    PercentInt(weakOnly, len(enabledMemberIDs)),
		SSPRRegistered:       PercentInt(ssprRegistered, len(enabledMemberIDs)),
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

func isWeakMFAMethod(method string) bool {
	normalized := strings.ToLower(method)
	return strings.Contains(normalized, "sms") ||
		strings.Contains(normalized, "voice") ||
		strings.Contains(normalized, "email")
}

func (c *Collector) usersWithSignInActivity(ctx context.Context, diagnostics *Diagnostics) ([]microsoft.User, bool, error) {
	users, err := c.graph.UsersWithSignInActivity(ctx)
	if err == nil {
		return users, true, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if microsoft.IsPremiumLicenseError(err) {
			diagnostics.Warn("Entra ID P1 not licensed, sign_in_activity reported as license_absent")
			diagnostics.MarkCapabilityUnavailable("sign_in_activity")
			return nil, false, nil
		}
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission AuditLog.Read.All not granted, sign-in activity skipped")
			diagnostics.MarkCapabilityUnavailable("sign_in_activity")
			return nil, false, nil
		}
	}
	return nil, false, err
}

func computeInactivePct(users []microsoft.User, include func(microsoft.User) bool, now time.Time) *int {
	total := 0
	inactive := 0
	cutoff := now.AddDate(0, 0, -90)
	for _, user := range users {
		if !include(user) {
			continue
		}
		total++
		if user.SignInActivity == nil || user.SignInActivity.LastSignInDateTime == "" {
			inactive++
			continue
		}
		lastSignIn, err := time.Parse(time.RFC3339, user.SignInActivity.LastSignInDateTime)
		if err != nil || lastSignIn.Before(cutoff) {
			inactive++
		}
	}
	return PercentInt(inactive, total)
}
