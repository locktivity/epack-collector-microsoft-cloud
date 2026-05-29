package collector

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

const signInMonitoringLookback = 7 * 24 * time.Hour

func (c *Collector) collectSignInMonitoring(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) (*SignInMonitoring, error) {
	if !level.AtLeast(componentsdk.LevelInternal) {
		return nil, nil
	}

	signIns, err := c.graph.SignIns(ctx, c.clock.Now().Add(-signInMonitoringLookback))
	if err == nil {
		return summarizeSignIns(signIns, int(signInMonitoringLookback.Hours())), nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if microsoft.IsPremiumLicenseError(err) {
			diagnostics.Warn("Entra ID P1 not licensed, sign-in monitoring skipped")
			diagnostics.MarkCapabilityUnavailable("sign_in_logs")
			return nil, nil
		}
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission AuditLog.Read.All not granted, sign-in monitoring skipped")
			diagnostics.MarkCapabilityUnavailable("sign_in_logs")
			return nil, nil
		}
	}
	return nil, err
}

func summarizeSignIns(signIns []microsoft.SignIn, lookbackHours int) *SignInMonitoring {
	out := &SignInMonitoring{LookbackHours: lookbackHours, SignInsCount: len(signIns)}
	userIDs := map[string]struct{}{}
	appIDs := map[string]struct{}{}
	policyIDs := map[string]struct{}{}
	failureCodes := map[int]int{}

	for _, signIn := range signIns {
		if signIn.UserID != "" {
			userIDs[signIn.UserID] = struct{}{}
		}
		if signIn.AppID != "" {
			appIDs[signIn.AppID] = struct{}{}
		}
		if signInFailed(signIn) {
			out.FailureCount++
			if signIn.Status.ErrorCode != 0 {
				failureCodes[signIn.Status.ErrorCode]++
			}
		}
		if legacyClientApp(signIn.ClientAppUsed) {
			out.LegacyClientSignInsCount++
		}
		if riskySignIn(signIn) {
			out.RiskySignInsCount++
		}
		switch normalizedPolicyResult(signIn.ConditionalAccessStatus) {
		case "success":
			out.ConditionalAccessSuccessCount++
		case "failure":
			out.ConditionalAccessFailureCount++
		case "notapplied":
			out.ConditionalAccessNotAppliedCount++
		}
		for _, policy := range signIn.AppliedConditionalAccessPolicies {
			if policy.ID != "" {
				policyIDs[policy.ID] = struct{}{}
			}
			out.AppliedPolicyEvaluationsCount++
			switch normalizedPolicyResult(policy.Result) {
			case "success":
				out.AppliedPolicySuccessCount++
			case "failure":
				out.AppliedPolicyFailureCount++
			case "notapplied", "notenabled":
				out.AppliedPolicyNotAppliedCount++
			case "reportonlyfailure":
				out.AppliedPolicyReportOnlyFailCount++
			}
		}
	}

	out.UniqueUsersCount = len(userIDs)
	out.UniqueAppsCount = len(appIDs)
	out.AppliedPoliciesCount = len(policyIDs)
	out.TopFailureCodes = topFailureCodes(failureCodes, 10)
	return out
}

func signInFailed(signIn microsoft.SignIn) bool {
	return signIn.Status.ErrorCode != 0
}

func legacyClientApp(clientAppUsed string) bool {
	normalized := strings.ToLower(clientAppUsed)
	return strings.Contains(normalized, "other clients") ||
		strings.Contains(normalized, "exchange activesync") ||
		strings.Contains(normalized, "imap") ||
		strings.Contains(normalized, "pop") ||
		strings.Contains(normalized, "smtp") ||
		strings.Contains(normalized, "mapi") ||
		strings.Contains(normalized, "autodiscover")
}

func riskySignIn(signIn microsoft.SignIn) bool {
	return riskyLevel(signIn.RiskLevelAggregated) || riskyLevel(signIn.RiskLevelDuringSignIn)
}

func riskyLevel(level string) bool {
	normalized := strings.ToLower(strings.TrimSpace(level))
	return normalized != "" && normalized != "none" && normalized != "hidden" && normalized != "unknownfuturevalue"
}

func normalizedPolicyResult(result string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(result) {
		if r >= 'a' && r <= 'z' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func topFailureCodes(counts map[int]int, limit int) []SignInFailureCodeCount {
	out := make([]SignInFailureCodeCount, 0, len(counts))
	for code, count := range counts {
		out = append(out, SignInFailureCodeCount{Code: code, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
