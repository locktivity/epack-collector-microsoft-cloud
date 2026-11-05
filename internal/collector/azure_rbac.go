package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

// The IDs of the built-in Azure roles that make a user an admin.
const (
	azureOwnerRoleDefinitionID                   = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	azureUserAccessAdministratorRoleDefinitionID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
)

// readOnlyRoleDefinitionIDs are the built-in Azure roles that only read. A
// service principal with any other role counts as having write access, and
// so does one with a custom role.
var readOnlyRoleDefinitionIDs = map[string]struct{}{
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": {}, // Reader
	"39bc4728-0917-49c7-9d2c-d95423bc2eb4": {}, // Security Reader
	"43d0d8ad-25c7-4714-9337-8ba259a9fe05": {}, // Monitoring Reader
	"fa23ad8b-c56e-40d8-ac0c-ce449e1d2c64": {}, // Billing Reader
	"72fafb9e-0641-4937-9268-a91bfd8191a3": {}, // Cost Management Reader
	"73c42c96-874c-492b-b04d-ab87d138a893": {}, // Log Analytics Reader
}

// collectRBAC returns the owner counts and the role assignments they are
// taken from, or why the assignments could not be read.
func (c *Collector) collectRBAC(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) (*AzureRBAC, []microsoft.ARMRoleAssignment, *missing) {
	assignments, err := c.arm.RoleAssignments(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("RBAC role assignments", scope.id, err)
		why := failed(err)
		c.gaps.leaveOut(azurePath, why, scope.pointer("rbac"))
		return nil, nil, why
	}
	return ownerCounts(assignments), assignments, nil
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

// roleDefinitionGUID returns the role's ID from a role definition's resource
// ID, in lower case.
func roleDefinitionGUID(roleDefinitionID string) string {
	id := strings.ToLower(roleDefinitionID)
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return id
}
