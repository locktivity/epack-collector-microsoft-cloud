package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

const azureOwnerRoleDefinitionID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

func (c *Collector) collectRBAC(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzureRBAC, error) {
	assignments, err := c.arm.RoleAssignments(ctx, subscriptionID)
	if err == nil {
		return ownerCounts(assignments), nil
	}
	if surfaceUnavailable(err) {
		diagnostics.Warn("RBAC role assignments unavailable for subscription " + subscriptionID)
		return &AzureRBAC{}, nil
	}
	return nil, err
}

func ownerCounts(assignments []microsoft.ARMRoleAssignment) *AzureRBAC {
	out := &AzureRBAC{}
	for _, assignment := range assignments {
		if !isOwnerRoleDefinitionID(assignment.Properties.RoleDefinitionID) {
			continue
		}
		out.OwnerCount++
		if strings.EqualFold(assignment.Properties.PrincipalType, "ServicePrincipal") {
			out.OwnerServicePrincipalCount++
		}
	}
	return out
}

func isOwnerRoleDefinitionID(roleDefinitionID string) bool {
	return strings.HasSuffix(strings.ToLower(roleDefinitionID), "/"+azureOwnerRoleDefinitionID) ||
		strings.EqualFold(roleDefinitionID, azureOwnerRoleDefinitionID)
}
