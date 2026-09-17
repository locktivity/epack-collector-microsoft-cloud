package microsoft

type Subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
}

type ARMResource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
}

type ARMSecureScore struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties ARMSecureScoreProperties `json:"properties"`
}

type ARMSecureScoreProperties struct {
	Score ARMScore `json:"score"`
}

type ARMScore struct {
	Max        float64 `json:"max"`
	Current    float64 `json:"current"`
	Percentage float64 `json:"percentage"`
}

type SecurityAssessment struct {
	ID         string                       `json:"id"`
	Name       string                       `json:"name"`
	Properties SecurityAssessmentProperties `json:"properties"`
}

type SecurityAssessmentProperties struct {
	DisplayName string                     `json:"displayName"`
	Status      SecurityAssessmentStatus   `json:"status"`
	Metadata    SecurityAssessmentMetadata `json:"metadata"`
}

type SecurityAssessmentStatus struct {
	Code  string `json:"code"`
	Cause string `json:"cause"`
}

type SecurityAssessmentMetadata struct {
	Categories []string `json:"categories"`
}

type ARMRoleAssignment struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Properties ARMRoleAssignmentProperties `json:"properties"`
}

type ARMRoleAssignmentProperties struct {
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	Scope            string `json:"scope"`
}

type PolicyAssignment struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Properties PolicyAssignmentProperties `json:"properties"`
}

type PolicyAssignmentProperties struct {
	Scope string `json:"scope"`
}

type PolicyStateSummaryResult struct {
	Value []PolicyStateSummary `json:"value"`
}

type PolicyStateSummary struct {
	Results PolicyStateSummaryResults `json:"results"`
}

type PolicyStateSummaryResults struct {
	NonCompliantResources int                `json:"nonCompliantResources"`
	ResourceDetails       []ComplianceDetail `json:"resourceDetails"`
}

type ComplianceDetail struct {
	ComplianceState string `json:"complianceState"`
	Count           int    `json:"count"`
}

type StorageAccount struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties StorageAccountProperties `json:"properties"`
}

type StorageAccountProperties struct {
	SupportsHTTPSTrafficOnly *bool             `json:"supportsHttpsTrafficOnly"`
	MinimumTLSVersion        string            `json:"minimumTlsVersion"`
	Encryption               StorageEncryption `json:"encryption"`
	AllowBlobPublicAccess    *bool             `json:"allowBlobPublicAccess"`
	PublicNetworkAccess      string            `json:"publicNetworkAccess"`
}

type StorageEncryption struct {
	KeySource                       string `json:"keySource"`
	RequireInfrastructureEncryption *bool  `json:"requireInfrastructureEncryption"`
}

type KeyVault struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Properties KeyVaultProperties `json:"properties"`
}

type KeyVaultProperties struct {
	EnablePurgeProtection   *bool `json:"enablePurgeProtection"`
	EnableRBACAuthorization *bool `json:"enableRbacAuthorization"`
}

type SQLServer struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Properties SQLServerProperties `json:"properties"`
}

type SQLServerProperties struct {
	MinimalTLSVersion   string `json:"minimalTlsVersion"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
}

type SQLDatabase struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SQLTransparentDataEncryption struct {
	ID         string                                 `json:"id"`
	Name       string                                 `json:"name"`
	Properties SQLTransparentDataEncryptionProperties `json:"properties"`
}

type SQLTransparentDataEncryptionProperties struct {
	State string `json:"state"`
}

type VirtualMachine struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties VirtualMachineProperties `json:"properties"`
}

type VirtualMachineProperties struct {
	StorageProfile VirtualMachineStorageProfile `json:"storageProfile"`
	NetworkProfile VirtualMachineNetworkProfile `json:"networkProfile"`
}

type VirtualMachineStorageProfile struct {
	OSDisk    VirtualMachineDisk   `json:"osDisk"`
	DataDisks []VirtualMachineDisk `json:"dataDisks"`
}

type VirtualMachineDisk struct {
	ManagedDisk        *ManagedDiskReference   `json:"managedDisk"`
	EncryptionSettings *DiskEncryptionSettings `json:"encryptionSettings"`
}

type ManagedDiskReference struct {
	ID                string                `json:"id"`
	DiskEncryptionSet *DiskEncryptionSetRef `json:"diskEncryptionSet,omitempty"`
}

type DiskEncryptionSetRef struct {
	ID string `json:"id"`
}

type DiskEncryptionSettings struct {
	Enabled *bool `json:"enabled"`
}

type VirtualMachineNetworkProfile struct {
	NetworkInterfaces []NetworkInterfaceReference `json:"networkInterfaces"`
}

type NetworkInterfaceReference struct {
	ID string `json:"id"`
}

type PublicIPAddress struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Properties PublicIPAddressProperties `json:"properties"`
}

type PublicIPAddressProperties struct {
	IPConfiguration *SubResource `json:"ipConfiguration"`
}

type NetworkSecurityGroup struct {
	ID         string                         `json:"id"`
	Name       string                         `json:"name"`
	Properties NetworkSecurityGroupProperties `json:"properties"`
}

type NetworkSecurityGroupProperties struct {
	SecurityRules []SecurityRule `json:"securityRules"`
}

type SecurityRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Properties SecurityRuleProperties `json:"properties"`
}

type SecurityRuleProperties struct {
	Access                     string   `json:"access"`
	Direction                  string   `json:"direction"`
	Protocol                   string   `json:"protocol"`
	SourceAddressPrefix        string   `json:"sourceAddressPrefix"`
	SourceAddressPrefixes      []string `json:"sourceAddressPrefixes"`
	DestinationPortRange       string   `json:"destinationPortRange"`
	DestinationPortRanges      []string `json:"destinationPortRanges"`
	DestinationAddressPrefix   string   `json:"destinationAddressPrefix"`
	DestinationAddressPrefixes []string `json:"destinationAddressPrefixes"`
}

type SubResource struct {
	ID string `json:"id"`
}

type DiagnosticSetting struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Properties DiagnosticSettingProperties `json:"properties"`
}

type DiagnosticSettingProperties struct {
	WorkspaceID                 string                    `json:"workspaceId"`
	StorageAccountID            string                    `json:"storageAccountId"`
	EventHubAuthorizationRuleID string                    `json:"eventHubAuthorizationRuleId"`
	MarketplacePartnerID        string                    `json:"marketplacePartnerId"`
	Logs                        []DiagnosticLogSetting    `json:"logs"`
	Metrics                     []DiagnosticMetricSetting `json:"metrics"`
}

type DiagnosticLogSetting struct {
	Category      string `json:"category"`
	CategoryGroup string `json:"categoryGroup"`
	Enabled       bool   `json:"enabled"`
}

type DiagnosticMetricSetting struct {
	Enabled bool `json:"enabled"`
}

type RecoveryServicesVault struct {
	ID         string                          `json:"id"`
	Name       string                          `json:"name"`
	Properties RecoveryServicesVaultProperties `json:"properties"`
}

type RecoveryServicesVaultProperties struct {
	SoftDeleteFeatureState string                `json:"softDeleteFeatureState"`
	SecuritySettings       VaultSecuritySettings `json:"securitySettings"`
}

type VaultSecuritySettings struct {
	SoftDeleteSettings   VaultSoftDeleteSettings   `json:"softDeleteSettings"`
	ImmutabilitySettings VaultImmutabilitySettings `json:"immutabilitySettings"`
}

type VaultSoftDeleteSettings struct {
	SoftDeleteState string `json:"softDeleteState"`
}

type VaultImmutabilitySettings struct {
	State string `json:"state"`
}

type BackupProtectedItem struct {
	ID         string                        `json:"id"`
	Name       string                        `json:"name"`
	Properties BackupProtectedItemProperties `json:"properties"`
}

type BackupProtectedItemProperties struct {
	SourceResourceID string `json:"sourceResourceId"`
	PolicyID         string `json:"policyId"`
	ProtectionState  string `json:"protectionState"`
}

type BackupPolicy struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties"`
}

type BackupJob struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Properties BackupJobProperties `json:"properties"`
}

type BackupJobProperties struct {
	Status    string `json:"status"`
	Operation string `json:"operation"`
	EndTime   string `json:"endTime"`
	StartTime string `json:"startTime"`
}
