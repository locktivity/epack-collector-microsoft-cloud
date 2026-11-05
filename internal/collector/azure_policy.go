package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectAzurePolicy(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) *AzurePolicy {
	assignments, err := c.arm.PolicyAssignments(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Azure Policy assignments", scope.id, err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("policy"))
		return nil
	}

	out := &AzurePolicy{AssignmentsCount: len(assignments)}
	if len(assignments) == 0 {
		return out
	}

	summary, err := c.arm.PolicyStateSummary(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Azure Policy compliance summary", scope.id, err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("policy/compliant_pct"), scope.pointer("policy/noncompliant_resources_count"))
		return out
	}
	compliant, noncompliant := policyResourceCompliance(summary)
	out.CompliantPct = PercentInt(compliant, compliant+noncompliant)
	out.NoncompliantResourcesCount = intPtr(noncompliant)
	return out
}

func policyResourceCompliance(summary *microsoft.PolicyStateSummaryResult) (compliant, noncompliant int) {
	if summary == nil {
		return 0, 0
	}
	for _, item := range summary.Value {
		for _, detail := range item.Results.ResourceDetails {
			switch strings.ToLower(detail.ComplianceState) {
			case "compliant":
				compliant += detail.Count
			case "noncompliant":
				noncompliant += detail.Count
			}
		}
	}
	return compliant, noncompliant
}
