package collector

import "github.com/locktivity/epack/componentsdk"

// CloudPosture is the normalized evidencepack/cloud-posture@v1 artifact. A
// value the Azure artifact left out is absent here too, with the same gap. A percentage over an empty population is null. The account ID
// and the counts behind the percentages are written from the audit level, as
// the schema marks them, and the present flags at every level.
type CloudPosture struct {
	SchemaVersion string                `json:"schema_version"`
	CollectedAt   string                `json:"collected_at"`
	Provider      string                `json:"provider"`
	Accounts      []CloudPostureAccount `json:"accounts"`
}

// CloudPostureAccount is one subscription. IAM is a deprecated block,
// written as before epack v0.10.0 (see deprecated.go).
type CloudPostureAccount struct {
	AccountID string               `json:"account_id,omitempty"`
	Storage   *CloudPostureStorage `json:"storage,omitempty"`
	Logging   *CloudPostureLogging `json:"logging,omitempty"`
	Backup    *CloudPostureBackup  `json:"backup,omitempty"`
	Network   *CloudPostureNetwork `json:"network,omitempty"`
	IAM       *CloudPostureIAM     `json:"iam,omitempty"`
}

type CloudPostureStorage struct {
	StorageResourcesPresent                 *bool      `json:"storage_resources_present,omitempty"`
	StorageResourceCount                    *int       `json:"storage_resource_count,omitempty"`
	EncryptedStorageResourceCount           *int       `json:"encrypted_storage_resource_count,omitempty"`
	PublicAccessBlockedStorageResourceCount *int       `json:"public_access_blocked_storage_resource_count,omitempty"`
	NetworkRestrictedStorageResourceCount   *int       `json:"network_restricted_storage_resource_count,omitempty"`
	EncryptionPct                           Percentage `json:"encryption_pct,omitzero"`
	PublicAccessBlockedPct                  Percentage `json:"public_access_blocked_pct,omitzero"`
	NetworkRestrictedPct                    Percentage `json:"network_restricted_pct,omitzero"`
}

type CloudPostureLogging struct {
	AuditLogEnabled       *bool `json:"audit_log_enabled,omitempty"`
	AuditLogAllRegions    *bool `json:"audit_log_all_regions,omitempty"`
	CloudTrailEnabled     *bool `json:"cloudtrail_enabled,omitempty"`
	CloudTrailMultiregion *bool `json:"cloudtrail_multiregion,omitempty"`
}

// CloudPostureBackup's retention is null when no backup policy that a
// protected item uses sets a retention period, as when the subscription has
// no Recovery Services vault.
type CloudPostureBackup struct {
	RetentionDaysMin Days `json:"retention_days_min,omitzero"`
}

// Days is a normalized number of days. Like a Percentage, it is left out
// when Read is false. Otherwise it is written as Value, which is nil when
// there is nothing to measure.
type Days = Percentage

type CloudPostureNetwork struct {
	SecurityGroupsPresent     *bool      `json:"security_groups_present,omitempty"`
	SecurityGroupCount        *int       `json:"security_group_count,omitempty"`
	SSHOpenSecurityGroupCount *int       `json:"ssh_open_security_group_count,omitempty"`
	RDPOpenSecurityGroupCount *int       `json:"rdp_open_security_group_count,omitempty"`
	SSHOpenToWorldPct         Percentage `json:"ssh_open_to_world_pct,omitzero"`
	RDPOpenToWorldPct         Percentage `json:"rdp_open_to_world_pct,omitzero"`
}

func (a *AzureArtifact) ToCloudPosture() *CloudPosture {
	if a == nil || len(a.Accounts) == 0 {
		return nil
	}
	audit := componentsdk.Level(a.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	atAudit := func(count *int) *int {
		if audit {
			return count
		}
		return nil
	}
	posture := &CloudPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   a.CollectedAt,
		Provider:      "azure",
		Accounts:      make([]CloudPostureAccount, 0, len(a.Accounts)),
	}
	for _, account := range a.Accounts {
		out := CloudPostureAccount{}
		if audit {
			out.AccountID = account.AccountID
		}
		if account.unreadable == nil {
			out.Storage = cloudPostureStorage(account.Storage, atAudit)
			out.Logging = cloudPostureLogging(account.Logging)
			out.Backup = cloudPostureBackup(account.Backup)
			out.Network = cloudPostureNetwork(account.Network, atAudit)
		}
		posture.Accounts = append(posture.Accounts, out)
	}
	return posture
}

func cloudPostureStorage(storage *AzureStorage, atAudit func(*int) *int) *CloudPostureStorage {
	if storage == nil {
		return nil
	}
	count := intPtr(storage.StorageAccountsCount)
	return &CloudPostureStorage{
		StorageResourcesPresent:                 present(count),
		StorageResourceCount:                    atAudit(count),
		EncryptedStorageResourceCount:           atAudit(intPtr(storage.encryptedAtRestCount)),
		PublicAccessBlockedStorageResourceCount: atAudit(intPtr(storage.publicAccessBlockedCount)),
		NetworkRestrictedStorageResourceCount:   atAudit(intPtr(storage.networkRestrictedCount)),
		EncryptionPct:                           share(intPtr(storage.encryptedAtRestCount), count, componentsdk.RoundDown),
		PublicAccessBlockedPct:                  share(intPtr(storage.publicAccessBlockedCount), count, componentsdk.RoundDown),
		NetworkRestrictedPct:                    share(intPtr(storage.networkRestrictedCount), count, componentsdk.RoundDown),
	}
}

// The Activity Log has no region scope, so one export covers every region and
// every field carries the same value. The cloudtrail_* fields are the schema's
// deprecated names for audit_log_*, kept until cloud-posture v2 removes them.
func cloudPostureLogging(logging *AzureLogging) *CloudPostureLogging {
	if logging == nil || logging.ActivityLogAdministrativeExported == nil {
		return nil
	}
	return &CloudPostureLogging{
		AuditLogEnabled:       logging.ActivityLogAdministrativeExported,
		AuditLogAllRegions:    logging.ActivityLogAdministrativeExported,
		CloudTrailEnabled:     logging.ActivityLogAdministrativeExported,
		CloudTrailMultiregion: logging.ActivityLogAdministrativeExported,
	}
}

func cloudPostureBackup(backup *AzureBackup) *CloudPostureBackup {
	if backup == nil || !backup.retentionRead {
		return nil
	}
	return &CloudPostureBackup{RetentionDaysMin: Days{Value: backup.RetentionDaysMin, Read: true}}
}

func cloudPostureNetwork(network *AzureNetwork, atAudit func(*int) *int) *CloudPostureNetwork {
	if network == nil || network.NetworkSecurityGroupsCount == nil {
		return nil
	}
	count := network.NetworkSecurityGroupsCount
	return &CloudPostureNetwork{
		SecurityGroupsPresent:     present(count),
		SecurityGroupCount:        atAudit(count),
		SSHOpenSecurityGroupCount: atAudit(network.sshOpenCount),
		RDPOpenSecurityGroupCount: atAudit(network.rdpOpenCount),
		SSHOpenToWorldPct:         share(network.sshOpenCount, count, componentsdk.RoundUp),
		RDPOpenToWorldPct:         share(network.rdpOpenCount, count, componentsdk.RoundUp),
	}
}

// cloudPostureSources maps each normalized account field to the Azure account
// field it is taken from, so a gap on the Azure value carries over.
var cloudPostureSources = []struct{ normalized, detailed string }{
	{"storage/storage_resources_present", "storage/storage_accounts_count"},
	{"storage/storage_resource_count", "storage/storage_accounts_count"},
	{"storage/encrypted_storage_resource_count", "storage/storage_accounts_count"},
	{"storage/public_access_blocked_storage_resource_count", "storage/public_access_blocked_pct"},
	{"storage/network_restricted_storage_resource_count", "storage/network_restricted_pct"},
	{"storage/encryption_pct", "storage/storage_accounts_count"},
	{"storage/public_access_blocked_pct", "storage/public_access_blocked_pct"},
	{"storage/network_restricted_pct", "storage/network_restricted_pct"},
	{"logging/audit_log_enabled", "logging/activity_log_administrative_exported"},
	{"logging/audit_log_all_regions", "logging/activity_log_administrative_exported"},
	{"logging/cloudtrail_enabled", "logging/activity_log_administrative_exported"},
	{"logging/cloudtrail_multiregion", "logging/activity_log_administrative_exported"},
	{"backup/retention_days_min", "backup/retention_days_min"},
	{"network/security_groups_present", "network/network_security_groups_count"},
	{"network/security_group_count", "network/network_security_groups_count"},
	{"network/ssh_open_security_group_count", "network/ssh_open_to_world_pct"},
	{"network/rdp_open_security_group_count", "network/rdp_open_to_world_pct"},
	{"network/ssh_open_to_world_pct", "network/ssh_open_to_world_pct"},
	{"network/rdp_open_to_world_pct", "network/rdp_open_to_world_pct"},
}

func (c *Collector) mirrorCloudPostureGaps(azure *AzureArtifact) {
	if azure == nil {
		return
	}
	for i, account := range azure.Accounts {
		if account.unreadable != nil {
			c.gaps.leaveOut(cloudPosturePath, account.unreadable,
				accountPointer(i, "storage"), accountPointer(i, "logging"),
				accountPointer(i, "backup"), accountPointer(i, "network"))
			continue
		}
		for _, source := range cloudPostureSources {
			c.gaps.rec.Mirror(
				componentsdk.Location{Path: azurePath, Pointer: accountPointer(i, source.detailed)},
				componentsdk.Location{Path: cloudPosturePath, Pointer: accountPointer(i, source.normalized)})
		}
	}
}
