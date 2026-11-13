package collector

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

type backupPopulation struct {
	virtualMachines []microsoft.VirtualMachine
	databases       []microsoft.SQLDatabase
	why             *missing
}

func (c *Collector) collectBackup(ctx context.Context, scope subscriptionScope, population backupPopulation, diagnostics *Diagnostics) *AzureBackup {
	vaults, err := c.arm.RecoveryServicesVaults(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Recovery Services vault inventory", scope.name, err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("backup"))
		return nil
	}

	// The vault list leaves out each vault's security settings, so a vault
	// without them is read on its own. One that can't be read leaves the
	// soft delete and immutability shares out rather than counting as off.
	var settingsReads unreadVaults
	for i, vault := range vaults {
		if vault.Properties.SecuritySettings.SoftDeleteSettings.SoftDeleteState != "" || vault.Properties.SoftDeleteFeatureState != "" {
			continue
		}
		full, err := c.arm.RecoveryServicesVault(ctx, vault.ID)
		if err != nil {
			diagnostics.warnSubscription("Recovery Services vault settings", scope.name, err)
			settingsReads.add(err)
			continue
		}
		vaults[i].Properties = full.Properties
	}

	protectedPct := scope.pointer("backup/protected_resource_pct")
	out := backupVaultPosture(vaults)
	if settingsReads.count > 0 {
		out.VaultSoftDeletePct, out.VaultImmutabilityPct = nil, nil
		c.gaps.partial(azurePath, settingsReads.count, failed(settingsReads.err),
			scope.pointer("backup/vault_soft_delete_pct"), scope.pointer("backup/vault_immutability_pct"))
	}
	if len(vaults) == 0 {
		out.retentionRead = true
		if population.why == nil {
			out.ProtectedResourcePct = protectedResourcePct(nil, population.virtualMachines, population.databases)
		}
		c.gaps.leaveOut(azurePath, population.why, protectedPct)
		return out
	}

	var protectedItems []microsoft.BackupProtectedItem
	var policies []microsoft.BackupPolicy
	var jobs []microsoft.BackupJob
	var items, policyReads, jobReads unreadVaults
	for _, vault := range vaults {
		vaultProtectedItems, err := c.arm.BackupProtectedItems(ctx, vault.ID)
		if err != nil {
			diagnostics.warnSubscription("Backup protected items", scope.name, err)
			items.add(err)
		}
		protectedItems = append(protectedItems, vaultProtectedItems...)

		vaultPolicies, err := c.arm.BackupPolicies(ctx, vault.ID)
		if err != nil {
			diagnostics.warnSubscription("Backup policies", scope.name, err)
			policyReads.add(err)
		}
		policies = append(policies, vaultPolicies...)

		vaultJobs, err := c.arm.BackupJobs(ctx, vault.ID, "operation eq 'Backup'")
		if err != nil {
			diagnostics.warnSubscription("Backup job history", scope.name, err)
			jobReads.add(err)
		}
		jobs = append(jobs, vaultJobs...)
	}

	switch {
	case population.why != nil:
		c.gaps.leaveOut(azurePath, population.why, protectedPct)
	case items.count > 0:
		c.gaps.partial(azurePath, items.count, failed(items.err), protectedPct)
	default:
		out.ProtectedResourcePct = protectedResourcePct(protectedItems, population.virtualMachines, population.databases)
	}
	// The retention depends on which policies the protected items use, so
	// both lists must be read.
	switch {
	case policyReads.count > 0:
		c.gaps.partial(azurePath, policyReads.count, failed(policyReads.err), scope.pointer("backup/retention_days_min"))
	case items.count > 0:
		c.gaps.partial(azurePath, items.count, failed(items.err), scope.pointer("backup/retention_days_min"))
	default:
		days, err := retentionDaysMin(policies, protectedItems)
		if err != nil {
			c.gaps.leaveOut(azurePath, failed(err), scope.pointer("backup/retention_days_min"))
			break
		}
		out.RetentionDaysMin = days
		out.retentionRead = true
	}
	if jobReads.count > 0 {
		c.gaps.partial(azurePath, jobReads.count, failed(jobReads.err),
			scope.pointer("backup/latest_successful_backup_age_hours_max"), scope.pointer("backup/failed_jobs_7d_count"))
	} else {
		out.LatestSuccessfulBackupAgeHoursMax = latestSuccessfulBackupAgeHoursMax(jobs, c.clock.Now())
		out.FailedJobs7dCount = failedBackupJobs7dCount(jobs, c.clock.Now())
	}
	return out
}

type unreadVaults struct {
	count int
	err   error
}

func (u *unreadVaults) add(err error) {
	if u.count == 0 {
		u.err = err
	}
	u.count++
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

// retentionDaysMin is the shortest retention in the backup policies that a
// protected item uses. A vault lists its built-in policies whether or not an
// item uses them. It is nil when no item uses a policy. An item under
// protection always names its policy, the vault lists it, and the policy sets
// a retention period, so an answer that breaks one of these is an error, as is
// a retention duration with no count or durationType.
// https://learn.microsoft.com/en-us/rest/api/backup/protected-items/get
func retentionDaysMin(policies []microsoft.BackupPolicy, items []microsoft.BackupProtectedItem) (*int, error) {
	inUse := map[string]struct{}{}
	for _, item := range items {
		id := strings.ToLower(item.Properties.PolicyID)
		if id == "" && backupProtectionActive(item.Properties.ProtectionState) {
			return nil, invalidBackup("arm.backup.protected_items.list lists an item under protection with no policyId")
		}
		if id != "" {
			inUse[id] = struct{}{}
		}
	}
	minDays := 0
	for _, policy := range policies {
		id := strings.ToLower(policy.ID)
		if _, ok := inUse[id]; !ok {
			continue
		}
		delete(inUse, id)
		days, ok := retentionDays(policy.Properties, false)
		if !ok {
			return nil, invalidBackup("arm.backup.policies.list lists a retention duration with no count or durationType")
		}
		if len(days) == 0 {
			return nil, invalidBackup("arm.backup.policies.list lists a policy in use that sets no retention period")
		}
		for _, d := range days {
			if minDays == 0 || d < minDays {
				minDays = d
			}
		}
	}
	if len(inUse) > 0 {
		return nil, invalidBackup("arm.backup.policies.list does not list a policy a protected item uses")
	}
	if minDays == 0 {
		return nil, nil
	}
	return intPtr(minDays), nil
}

// invalidBackup is the error for backup answers that can't be read
// together.
func invalidBackup(problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New(problem))
}

// retentionDays lists the retention periods, in days, set in value. ok is
// false when a retention duration lacks its count or its durationType, which
// Azure Backup always sends together.
// https://learn.microsoft.com/en-us/rest/api/backup/backup-policies/list
func retentionDays(value any, inRetention bool) (days []int, ok bool) {
	switch typed := value.(type) {
	case map[string]any:
		var out []int
		if inRetention {
			count, counted := numericMapValue(typed, "count")
			durationType, typedDuration := stringMapValue(typed, "durationType")
			if (counted || typedDuration) && (count <= 0 || durationType == "") {
				return nil, false
			}
			if d := retentionDurationDays(typed); d > 0 {
				out = append(out, d)
			}
		}
		for key, child := range typed {
			childInRetention := inRetention || strings.Contains(strings.ToLower(key), "retention")
			childDays, ok := retentionDays(child, childInRetention)
			if !ok {
				return nil, false
			}
			out = append(out, childDays...)
		}
		return out, true
	case []any:
		var out []int
		for _, child := range typed {
			childDays, ok := retentionDays(child, inRetention)
			if !ok {
				return nil, false
			}
			out = append(out, childDays...)
		}
		return out, true
	default:
		return nil, true
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
	case "days", "day":
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
