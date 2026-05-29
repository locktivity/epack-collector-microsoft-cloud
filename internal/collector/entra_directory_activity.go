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

const directoryAuditLookback = 7 * 24 * time.Hour

func (c *Collector) collectDirectoryActivity(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) (*DirectoryActivity, error) {
	if !level.AtLeast(componentsdk.LevelInternal) {
		return nil, nil
	}

	audits, err := c.graph.DirectoryAudits(ctx, c.clock.Now().Add(-directoryAuditLookback))
	if err == nil {
		return summarizeDirectoryActivity(audits, int(directoryAuditLookback.Hours())), nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		diagnostics.Warn("graph permission AuditLog.Read.All or Directory.Read.All not granted, directory audit activity skipped")
		diagnostics.MarkCapabilityUnavailable("directory_audit_activity")
		return nil, nil
	}
	return nil, err
}

func summarizeDirectoryActivity(audits []microsoft.DirectoryAudit, lookbackHours int) *DirectoryActivity {
	out := &DirectoryActivity{LookbackHours: lookbackHours, EventsCount: len(audits)}
	for _, audit := range audits {
		if auditResultFailed(audit.Result) {
			out.FailureCount++
		}
		if strings.EqualFold(audit.OperationType, "Delete") {
			out.DeleteEventsCount++
		}
		if auditInSurface(audit, "UserManagement", "User") {
			out.UserChangeEventsCount++
		}
		if auditInSurface(audit, "GroupManagement", "Group") {
			out.GroupChangeEventsCount++
		}
		if auditInSurface(audit, "ApplicationManagement", "App") {
			out.AppChangeEventsCount++
		}
		if auditInSurface(audit, "RoleManagement", "Role") {
			out.RoleChangeEventsCount++
		}
		if auditInSurface(audit, "Policy", "Policy") {
			out.PolicyChangeEventsCount++
		}
		if strings.Contains(strings.ToLower(audit.Category+" "+audit.LoggedByService), "privileged identity management") {
			out.PIMEventsCount++
		}
	}
	return out
}

func auditResultFailed(result string) bool {
	return strings.EqualFold(result, "failure") || strings.EqualFold(result, "timeout")
}

func auditInSurface(audit microsoft.DirectoryAudit, categoryNeedle, targetType string) bool {
	if strings.Contains(strings.ToLower(audit.Category), strings.ToLower(categoryNeedle)) {
		return true
	}
	for _, target := range audit.TargetResources {
		if strings.EqualFold(target.Type, targetType) {
			return true
		}
	}
	return false
}
