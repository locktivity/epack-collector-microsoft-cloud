package microsoft

import (
	"fmt"
	"slices"
	"strings"
)

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

// problem says how a summary breaks its own counts: the resources it counts
// as noncompliant in resourceDetails are those nonCompliantResources counts.
func (s PolicyStateSummary) problem() string {
	noncompliant := 0
	for _, detail := range s.Results.ResourceDetails {
		if strings.EqualFold(detail.ComplianceState, "noncompliant") {
			noncompliant += detail.Count
		}
	}
	if noncompliant != s.Results.NonCompliantResources {
		return fmt.Sprintf("counts %d noncompliant resources in resourceDetails and %d in nonCompliantResources", noncompliant, s.Results.NonCompliantResources)
	}
	return ""
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
	SupportsHTTPSTrafficOnly *bool               `json:"supportsHttpsTrafficOnly"`
	MinimumTLSVersion        string              `json:"minimumTlsVersion"`
	Encryption               StorageEncryption   `json:"encryption"`
	AllowBlobPublicAccess    *bool               `json:"allowBlobPublicAccess"`
	PublicNetworkAccess      string              `json:"publicNetworkAccess"`
	NetworkACLs              *StorageNetworkACLs `json:"networkAcls"`
}

// StorageNetworkACLs is a storage account's firewall. With defaultAction
// Deny, only the allowed networks and private endpoints reach the account.
type StorageNetworkACLs struct {
	DefaultAction string `json:"defaultAction"`
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

// problem says how a virtual machine breaks Azure's rules for one: it has a
// network interface, and each disk is a managed disk or a VHD.
// https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface-vm
func (vm VirtualMachine) problem() string {
	if len(vm.Properties.NetworkProfile.NetworkInterfaces) == 0 {
		return "has no network interface, and every virtual machine has one"
	}
	disks := append([]VirtualMachineDisk{vm.Properties.StorageProfile.OSDisk}, vm.Properties.StorageProfile.DataDisks...)
	for _, disk := range disks {
		if (disk.ManagedDisk == nil || disk.ManagedDisk.ID == "") && disk.VHD == nil {
			return "has a disk with neither a managed disk ID nor a VHD"
		}
	}
	return ""
}

type VirtualMachineStorageProfile struct {
	OSDisk    VirtualMachineDisk   `json:"osDisk"`
	DataDisks []VirtualMachineDisk `json:"dataDisks"`
}

// VirtualMachineDisk is a disk of a virtual machine. A managed disk has
// managedDisk, and an unmanaged one the VHD it is stored in.
type VirtualMachineDisk struct {
	ManagedDisk        *ManagedDiskReference   `json:"managedDisk"`
	VHD                *VirtualHardDisk        `json:"vhd,omitempty"`
	EncryptionSettings *DiskEncryptionSettings `json:"encryptionSettings"`
}

type VirtualHardDisk struct {
	URI string `json:"uri"`
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

// problem says how a public IP address breaks Azure's rules for one: the IP
// configuration it is attached to has an ID.
func (ip PublicIPAddress) problem() string {
	if ip.Properties.IPConfiguration != nil && ip.Properties.IPConfiguration.ID == "" {
		return "has an ipConfiguration with no id"
	}
	return ""
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

// problem says how a network security group breaks Azure's rules for one:
// each rule has a source, as address prefixes or application security
// groups, and destination ports.
// https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#security-rules
func (nsg NetworkSecurityGroup) problem() string {
	for _, rule := range nsg.Properties.SecurityRules {
		props := rule.Properties
		if props.SourceAddressPrefix == "" && len(props.SourceAddressPrefixes) == 0 && len(props.SourceApplicationSecurityGroups) == 0 {
			return "has a security rule with no source"
		}
		if props.DestinationPortRange == "" && len(props.DestinationPortRanges) == 0 {
			return "has a security rule with no destination ports"
		}
	}
	return ""
}

type SecurityRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Properties SecurityRuleProperties `json:"properties"`
}

type SecurityRuleProperties struct {
	Priority              int      `json:"priority"`
	Access                string   `json:"access"`
	Direction             string   `json:"direction"`
	Protocol              string   `json:"protocol"`
	SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
	SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	// SourceApplicationSecurityGroups is the source of a rule that names
	// application security groups rather than addresses.
	SourceApplicationSecurityGroups []SubResource `json:"sourceApplicationSecurityGroups,omitempty"`
	DestinationPortRange            string        `json:"destinationPortRange"`
	DestinationPortRanges           []string      `json:"destinationPortRanges"`
	DestinationAddressPrefix        string        `json:"destinationAddressPrefix"`
	DestinationAddressPrefixes      []string      `json:"destinationAddressPrefixes"`
}

type SubResource struct {
	ID string `json:"id"`
}

type DiagnosticSetting struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Properties DiagnosticSettingProperties `json:"properties"`
}

// problem says how a diagnostic setting breaks Azure Monitor's rules for
// one: each log setting names a category or a category group.
func (s DiagnosticSetting) problem() string {
	for _, log := range s.Properties.Logs {
		if log.Category == "" && log.CategoryGroup == "" {
			return "has a log setting with neither a category nor a categoryGroup"
		}
	}
	return ""
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
	BackupManagementType string `json:"backupManagementType"`
	SourceResourceID     string `json:"sourceResourceId"`
	PolicyID             string `json:"policyId"`
	ProtectionState      string `json:"protectionState"`
}

// azureBackupManagementTypes are the backup management types of items that
// back up an Azure resource, which sourceResourceId names. An item a backup
// agent or server protects backs up a machine outside Azure.
// https://learn.microsoft.com/en-us/rest/api/backup/backup-protected-items/list
var azureBackupManagementTypes = []string{"AzureIaasVM", "AzureSql", "AzureWorkload", "AzureStorage"}

// problem says how a protected item breaks Azure Backup's rules for one: an
// item that backs up an Azure resource names it.
func (i BackupProtectedItem) problem() string {
	azure := slices.ContainsFunc(azureBackupManagementTypes, func(t string) bool { return strings.EqualFold(t, i.Properties.BackupManagementType) })
	if azure && i.Properties.SourceResourceID == "" {
		return "backs up an Azure resource with no sourceResourceId"
	}
	return ""
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

// finishedJobStatuses are the statuses of a backup job that has ended.
// https://learn.microsoft.com/en-us/rest/api/backup/backup-jobs/list
var finishedJobStatuses = []string{"Completed", "CompletedWithWarnings", "Failed", "Cancelled"}

// problem says how a backup job breaks Azure Backup's rules for one: a job
// that has ended has an end time.
func (j BackupJob) problem() string {
	if j.Properties.EndTime == "" && slices.ContainsFunc(finishedJobStatuses, func(status string) bool { return strings.EqualFold(status, j.Properties.Status) }) {
		return "has ended with no endTime"
	}
	return ""
}

type BackupJobProperties struct {
	Status    string `json:"status"`
	Operation string `json:"operation"`
	EndTime   string `json:"endTime"`
	StartTime string `json:"startTime"`
}
