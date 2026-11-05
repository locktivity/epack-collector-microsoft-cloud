package collector

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

const signInMonitoringLookback = 7 * 24 * time.Hour

func (c *Collector) collectSignInMonitoring(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) *SignInMonitoring {
	if !level.AtLeast(componentsdk.LevelInternal) {
		return nil
	}

	signIns, err := c.graph.SignIns(ctx, c.clock.Now().Add(-signInMonitoringLookback))
	why := failed(err)
	switch {
	case err == nil:
		out, unrated, policiesOmitted := summarizeSignIns(signIns, int(signInMonitoringLookback.Hours()))
		if unrated {
			c.gaps.leaveOut(entraPath, unlicensed(riskLevelsHidden), "/sign_in_monitoring/risky_sign_ins_count")
		}
		if policiesOmitted {
			c.gaps.leaveOut(entraPath, failed(errAppliedPoliciesOmitted), appliedPolicyFields...)
		}
		return out
	case microsoft.IsPremiumLicenseError(err):
		diagnostics.Warn("Entra ID P1 not licensed, sign-in monitoring skipped")
		diagnostics.MarkCapabilityUnavailable("sign_in_logs")
		why = unlicensed("Sign-in logs require Entra ID P1 or P2.")
	case permissionDenied(err):
		diagnostics.Warn("graph permission AuditLog.Read.All not granted, sign-in monitoring skipped")
		diagnostics.MarkCapabilityUnavailable("sign_in_logs")
	default:
		diagnostics.warnNotCollected("Sign-in monitoring", err)
	}
	c.gaps.leaveOut(entraPath, why, "/sign_in_monitoring")
	return nil
}

// riskLevelsHidden is the detail of the gap on the risky sign-in count when
// a sign-in's risk level is hidden. Sign-in risk is rated only for tenants
// with Entra ID P2.
// https://learn.microsoft.com/en-us/graph/api/resources/signin
const riskLevelsHidden = "Sign-in risk levels require Entra ID P2. At least one sign-in has a hidden risk level."

// errAppliedPoliciesOmitted is why the applied policy counts are left out
// when the sign-ins have no appliedConditionalAccessPolicies. The property is
// left out for an app that cannot read Conditional Access data.
// https://learn.microsoft.com/en-us/graph/api/signin-list#permissions
var errAppliedPoliciesOmitted = componentsdk.CodeError(componentsdk.CodePermissionDenied,
	errors.New("sign-ins have no appliedConditionalAccessPolicies, which needs the Policy.Read.All permission"))

// appliedPolicyFields are the counts taken from appliedConditionalAccessPolicies.
var appliedPolicyFields = []string{
	"/sign_in_monitoring/applied_policies_count",
	"/sign_in_monitoring/applied_policy_evaluations_count",
	"/sign_in_monitoring/applied_policy_success_count",
	"/sign_in_monitoring/applied_policy_failure_count",
	"/sign_in_monitoring/applied_policy_not_applied_count",
	"/sign_in_monitoring/applied_policy_report_only_fail_count",
}

// summarizeSignIns counts the sign-ins. unrated is true when a sign-in has a
// hidden risk level, and policiesOmitted when a sign-in has no
// appliedConditionalAccessPolicies. The counts those make unknown are nil.
func summarizeSignIns(signIns []microsoft.SignIn, lookbackHours int) (out *SignInMonitoring, unrated, policiesOmitted bool) {
	out = &SignInMonitoring{LookbackHours: lookbackHours, SignInsCount: len(signIns)}
	userIDs := map[string]struct{}{}
	appIDs := map[string]struct{}{}
	policyIDs := map[string]struct{}{}
	failureCodes := map[int]int{}
	var risky, evaluations, successes, failures, notApplied, reportOnlyFailures int

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
		switch {
		case riskySignIn(signIn):
			risky++
		case riskHidden(signIn):
			unrated = true
		}
		switch normalizedPolicyResult(signIn.ConditionalAccessStatus) {
		case "success":
			out.ConditionalAccessSuccessCount++
		case "failure":
			out.ConditionalAccessFailureCount++
		case "notapplied":
			out.ConditionalAccessNotAppliedCount++
		}
		if signIn.AppliedConditionalAccessPolicies == nil {
			policiesOmitted = true
		}
		for _, policy := range signIn.AppliedConditionalAccessPolicies {
			if policy.ID != "" {
				policyIDs[policy.ID] = struct{}{}
			}
			evaluations++
			switch normalizedPolicyResult(policy.Result) {
			case "success":
				successes++
			case "failure":
				failures++
			case "notapplied", "notenabled":
				notApplied++
			case "reportonlyfailure":
				reportOnlyFailures++
			}
		}
	}

	out.UniqueUsersCount = len(userIDs)
	out.UniqueAppsCount = len(appIDs)
	out.TopFailureCodes = topFailureCodes(failureCodes, 10)
	if !unrated {
		out.RiskySignInsCount = intPtr(risky)
	}
	if !policiesOmitted {
		out.AppliedPoliciesCount = intPtr(len(policyIDs))
		out.AppliedPolicyEvaluationsCount = intPtr(evaluations)
		out.AppliedPolicySuccessCount = intPtr(successes)
		out.AppliedPolicyFailureCount = intPtr(failures)
		out.AppliedPolicyNotAppliedCount = intPtr(notApplied)
		out.AppliedPolicyReportOnlyFailCount = intPtr(reportOnlyFailures)
	}
	return out, unrated, policiesOmitted
}

func signInFailed(signIn microsoft.SignIn) bool {
	return signIn.Status.ErrorCode != 0
}

// legacyClients are the clientAppUsed names of Exchange ActiveSync and of the
// protocols behind the Other clients condition.
// https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions
var legacyClients = []string{
	"other clients",
	"exchange activesync",
	"imap",
	"pop",
	"smtp",
	"mapi",
	"autodiscover",
	"exchange web services",
	"exchange online powershell",
	"offline address book",
	"outlook anywhere",
	"outlook service",
	"reporting web services",
}

func legacyClientApp(clientAppUsed string) bool {
	normalized := strings.ToLower(clientAppUsed)
	for _, client := range legacyClients {
		if strings.Contains(normalized, client) {
			return true
		}
	}
	return false
}

func riskySignIn(signIn microsoft.SignIn) bool {
	return riskyLevel(signIn.RiskLevelAggregated) || riskyLevel(signIn.RiskLevelDuringSignIn)
}

// riskHidden reports whether a risk level of the sign-in is hidden. The
// sign-in was then not enabled for Entra ID Protection.
func riskHidden(signIn microsoft.SignIn) bool {
	return strings.EqualFold(signIn.RiskLevelAggregated, "hidden") || strings.EqualFold(signIn.RiskLevelDuringSignIn, "hidden")
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
