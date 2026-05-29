package collector

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectBackup(ctx context.Context, subscriptionID string, virtualMachines []microsoft.VirtualMachine, databases []microsoft.SQLDatabase, diagnostics *Diagnostics) (*AzureBackup, error) {
	vaults, err := c.arm.RecoveryServicesVaults(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("Recovery Services vault inventory unavailable for subscription " + subscriptionID)
			return &AzureBackup{}, nil
		}
		return nil, err
	}

	out := backupVaultPosture(vaults)
	if len(vaults) == 0 {
		out.ProtectedResourcePct = protectedResourcePct(nil, virtualMachines, databases)
		return out, nil
	}

	var protectedItems []microsoft.BackupProtectedItem
	protectedKnown := true
	var policies []microsoft.BackupPolicy
	policiesKnown := true
	var jobs []microsoft.BackupJob
	jobsKnown := true
	for _, vault := range vaults {
		vaultProtectedItems, err := c.arm.BackupProtectedItems(ctx, vault.ID)
		if err != nil {
			if surfaceUnavailable(err) {
				diagnostics.Warn("Backup protected items unavailable for subscription " + subscriptionID)
				protectedKnown = false
			} else {
				return nil, err
			}
		}
		protectedItems = append(protectedItems, vaultProtectedItems...)

		vaultPolicies, err := c.arm.BackupPolicies(ctx, vault.ID)
		if err != nil {
			if surfaceUnavailable(err) {
				diagnostics.Warn("Backup policies unavailable for subscription " + subscriptionID)
				policiesKnown = false
			} else {
				return nil, err
			}
		}
		policies = append(policies, vaultPolicies...)

		vaultJobs, err := c.arm.BackupJobs(ctx, vault.ID, "operation eq 'Backup'")
		if err != nil {
			if surfaceUnavailable(err) {
				diagnostics.Warn("Backup job history unavailable for subscription " + subscriptionID)
				jobsKnown = false
			} else {
				return nil, err
			}
		}
		jobs = append(jobs, vaultJobs...)
	}

	if protectedKnown {
		out.ProtectedResourcePct = protectedResourcePct(protectedItems, virtualMachines, databases)
	}
	if policiesKnown {
		out.RetentionDaysMin = retentionDaysMin(policies)
	}
	if jobsKnown {
		out.LatestSuccessfulBackupAgeHoursMax = latestSuccessfulBackupAgeHoursMax(jobs, c.clock.Now())
		out.FailedJobs7dCount = failedBackupJobs7dCount(jobs, c.clock.Now())
	}
	return out, nil
}

func backupVaultPosture(vaults []microsoft.RecoveryServicesVault) *AzureBackup {
	out := &AzureBackup{}
	if len(vaults) == 0 {
		return out
	}

	softDelete := 0
	immutability := 0
	for _, vault := range vaults {
		if vaultSoftDeleteEnabled(vault) {
			softDelete++
		}
		if vaultImmutabilityEnabled(vault) {
			immutability++
		}
	}
	out.VaultSoftDeletePct = PercentInt(softDelete, len(vaults))
	out.VaultImmutabilityPct = PercentInt(immutability, len(vaults))
	return out
}

func vaultSoftDeleteEnabled(vault microsoft.RecoveryServicesVault) bool {
	state := vault.Properties.SecuritySettings.SoftDeleteSettings.SoftDeleteState
	if state == "" {
		state = vault.Properties.SoftDeleteFeatureState
	}
	return enabledState(state)
}

func vaultImmutabilityEnabled(vault microsoft.RecoveryServicesVault) bool {
	switch strings.ToLower(vault.Properties.SecuritySettings.ImmutabilitySettings.State) {
	case "enabled", "locked", "unlocked":
		return true
	default:
		return false
	}
}

func protectedResourcePct(items []microsoft.BackupProtectedItem, virtualMachines []microsoft.VirtualMachine, databases []microsoft.SQLDatabase) *int {
	denominator := len(virtualMachines) + len(databases)
	if denominator == 0 {
		return nil
	}
	protectedIDs := map[string]struct{}{}
	for _, item := range items {
		if !backupProtectionActive(item.Properties.ProtectionState) {
			continue
		}
		id := strings.ToLower(item.Properties.SourceResourceID)
		if id != "" {
			protectedIDs[id] = struct{}{}
		}
	}
	protected := 0
	for _, vm := range virtualMachines {
		if _, ok := protectedIDs[strings.ToLower(vm.ID)]; ok {
			protected++
		}
	}
	for _, database := range databases {
		if _, ok := protectedIDs[strings.ToLower(database.ID)]; ok {
			protected++
		}
	}
	return PercentInt(protected, denominator)
}

func backupProtectionActive(state string) bool {
	state = strings.ToLower(state)
	return state == "protected" || state == "protectionconfigured" || state == "backupprotectionenabled"
}

func retentionDaysMin(policies []microsoft.BackupPolicy) *int {
	minDays := 0
	for _, policy := range policies {
		for _, days := range retentionDays(policy.Properties, false) {
			if days <= 0 {
				continue
			}
			if minDays == 0 || days < minDays {
				minDays = days
			}
		}
	}
	if minDays == 0 {
		return nil
	}
	return intPtr(minDays)
}

func retentionDays(value any, inRetention bool) []int {
	switch typed := value.(type) {
	case map[string]any:
		var out []int
		if inRetention {
			if days := retentionDurationDays(typed); days > 0 {
				out = append(out, days)
			}
		}
		for key, child := range typed {
			childInRetention := inRetention || strings.Contains(strings.ToLower(key), "retention")
			out = append(out, retentionDays(child, childInRetention)...)
		}
		return out
	case []any:
		var out []int
		for _, child := range typed {
			out = append(out, retentionDays(child, inRetention)...)
		}
		return out
	default:
		return nil
	}
}

func retentionDurationDays(value map[string]any) int {
	if days, ok := numericMapValue(value, "durationCountInDays"); ok {
		return days
	}
	count, ok := numericMapValue(value, "count")
	if !ok {
		return 0
	}
	durationType, _ := stringMapValue(value, "durationType")
	switch strings.ToLower(durationType) {
	case "", "days", "day":
		return count
	case "weeks", "week":
		return count * 7
	case "months", "month":
		return count * 30
	case "years", "year":
		return count * 365
	default:
		return 0
	}
}

func numericMapValue(value map[string]any, key string) (int, bool) {
	for mapKey, entry := range value {
		if !strings.EqualFold(mapKey, key) {
			continue
		}
		switch typed := entry.(type) {
		case int:
			return typed, true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case json.Number:
			out, err := typed.Int64()
			return int(out), err == nil
		}
	}
	return 0, false
}

func stringMapValue(value map[string]any, key string) (string, bool) {
	for mapKey, entry := range value {
		if strings.EqualFold(mapKey, key) {
			out, ok := entry.(string)
			return out, ok
		}
	}
	return "", false
}

func latestSuccessfulBackupAgeHoursMax(jobs []microsoft.BackupJob, now time.Time) *int {
	var maxAge *int
	for _, job := range jobs {
		if !backupOperation(job.Properties.Operation) || !successfulBackupStatus(job.Properties.Status) {
			continue
		}
		completedAt := backupJobTime(job)
		if completedAt.IsZero() || completedAt.After(now) {
			continue
		}
		age := int(math.Round(now.Sub(completedAt).Hours()))
		if maxAge == nil || age > *maxAge {
			maxAge = intPtr(age)
		}
	}
	return maxAge
}

func failedBackupJobs7dCount(jobs []microsoft.BackupJob, now time.Time) *int {
	since := now.AddDate(0, 0, -7)
	failed := 0
	for _, job := range jobs {
		if !backupOperation(job.Properties.Operation) || !failedBackupStatus(job.Properties.Status) {
			continue
		}
		occurredAt := backupJobTime(job)
		if occurredAt.IsZero() || occurredAt.Before(since) || occurredAt.After(now) {
			continue
		}
		failed++
	}
	return intPtr(failed)
}

func backupOperation(operation string) bool {
	return operation == "" || strings.EqualFold(operation, "Backup")
}

func successfulBackupStatus(status string) bool {
	return strings.EqualFold(status, "Completed") || strings.EqualFold(status, "Succeeded") || strings.EqualFold(status, "CompletedWithWarnings")
}

func failedBackupStatus(status string) bool {
	return strings.EqualFold(status, "Failed")
}

func backupJobTime(job microsoft.BackupJob) time.Time {
	if parsed := parseGraphTime(job.Properties.EndTime); !parsed.IsZero() {
		return parsed
	}
	return parseGraphTime(job.Properties.StartTime)
}

func enabledState(value string) bool {
	return strings.EqualFold(value, "Enabled") || strings.EqualFold(value, "AlwaysON")
}
