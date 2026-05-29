package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectAzurePolicy(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzurePolicy, error) {
	assignments, err := c.arm.PolicyAssignments(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("Azure Policy assignments unavailable for subscription " + subscriptionID)
			return &AzurePolicy{}, nil
		}
		return nil, err
	}

	out := &AzurePolicy{AssignmentsCount: len(assignments)}
	if len(assignments) == 0 {
		return out, nil
	}

	summary, err := c.arm.PolicyStateSummary(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("Azure Policy compliance summary unavailable for subscription " + subscriptionID)
			return out, nil
		}
		return nil, err
	}
	compliant, noncompliant := policyResourceCompliance(summary)
	out.CompliantPct = PercentInt(compliant, compliant+noncompliant)
	out.NoncompliantResourcesCount = intPtr(noncompliant)
	return out, nil
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
