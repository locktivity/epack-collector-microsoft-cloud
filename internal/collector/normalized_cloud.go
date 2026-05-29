package collector

type CloudPosture struct {
	SchemaVersion string                `json:"schema_version"`
	CollectedAt   string                `json:"collected_at"`
	Provider      string                `json:"provider"`
	Accounts      []CloudPostureAccount `json:"accounts"`
}

type CloudPostureAccount struct {
	AccountID string               `json:"account_id"`
	IAM       *CloudPostureIAM     `json:"iam,omitempty"`
	Storage   *CloudPostureStorage `json:"storage,omitempty"`
	Backup    *CloudPostureBackup  `json:"backup,omitempty"`
	Network   *CloudPostureNetwork `json:"network,omitempty"`
}

type CloudPostureIAM struct {
	MFACoveragePct *int  `json:"mfa_coverage_pct,omitempty"`
	RootMFAEnabled *bool `json:"root_mfa_enabled,omitempty"`
}

type CloudPostureStorage struct {
	EncryptionPct          *int `json:"encryption_pct,omitempty"`
	PublicAccessBlockedPct *int `json:"public_access_blocked_pct,omitempty"`
}

type CloudPostureBackup struct {
	RetentionDaysMin *int `json:"retention_days_min,omitempty"`
}

type CloudPostureNetwork struct {
	SSHOpenToWorldPct *int `json:"ssh_open_to_world_pct,omitempty"`
	RDPOpenToWorldPct *int `json:"rdp_open_to_world_pct,omitempty"`
}

func (a *AzureArtifact) ToCloudPosture(entra *EntraArtifact) *CloudPosture {
	if a == nil || len(a.Accounts) == 0 {
		return nil
	}
	posture := &CloudPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   a.CollectedAt,
		Provider:      "azure",
		Accounts:      make([]CloudPostureAccount, 0, len(a.Accounts)),
	}
	for _, account := range a.Accounts {
		posture.Accounts = append(posture.Accounts, CloudPostureAccount{
			AccountID: account.AccountID,
			IAM:       cloudPostureIAM(entra),
			Storage:   cloudPostureStorage(account.Storage),
			Backup:    cloudPostureBackup(account.Backup),
			Network:   cloudPostureNetwork(account.Network),
		})
	}
	return posture
}

func cloudPostureIAM(entra *EntraArtifact) *CloudPostureIAM {
	if entra == nil {
		return nil
	}
	iam := &CloudPostureIAM{}
	if entra.Posture.MFACoverage != nil {
		iam.MFACoveragePct = entra.Posture.MFACoverage
	}
	if entra.PrivilegedAccess != nil && entra.PrivilegedAccess.RootMFAEnabled != nil {
		iam.RootMFAEnabled = entra.PrivilegedAccess.RootMFAEnabled
	}
	if iam.MFACoveragePct == nil && iam.RootMFAEnabled == nil {
		return nil
	}
	return iam
}

func cloudPostureStorage(storage *AzureStorage) *CloudPostureStorage {
	if storage == nil {
		return nil
	}
	out := &CloudPostureStorage{}
	if storage.EncryptionCMKPct != nil {
		out.EncryptionPct = storage.EncryptionCMKPct
	}
	if storage.PublicAccessBlockedPct != nil {
		out.PublicAccessBlockedPct = storage.PublicAccessBlockedPct
	}
	if out.EncryptionPct == nil && out.PublicAccessBlockedPct == nil {
		return nil
	}
	return out
}

func cloudPostureBackup(backup *AzureBackup) *CloudPostureBackup {
	if backup == nil || backup.RetentionDaysMin == nil {
		return nil
	}
	return &CloudPostureBackup{RetentionDaysMin: backup.RetentionDaysMin}
}

func cloudPostureNetwork(network *AzureNetwork) *CloudPostureNetwork {
	if network == nil {
		return nil
	}
	out := &CloudPostureNetwork{}
	if network.SSHOpenToWorldPct != nil {
		out.SSHOpenToWorldPct = network.SSHOpenToWorldPct
	}
	if network.RDPOpenToWorldPct != nil {
		out.RDPOpenToWorldPct = network.RDPOpenToWorldPct
	}
	if out.SSHOpenToWorldPct == nil && out.RDPOpenToWorldPct == nil {
		return nil
	}
	return out
}
