package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

type fakeGraph struct {
	org                  *microsoft.Organization
	users                []microsoft.User
	signInUsers          []microsoft.User
	registrations        []microsoft.UserRegistrationDetail
	regErr               error
	policies             []microsoft.ConditionalAccessPolicy
	policiesErr          error
	securityDefaults     *microsoft.IdentitySecurityDefaultsEnforcementPolicy
	securityDefErr       error
	roleAssignments      []microsoft.UnifiedRoleAssignment
	roleAssignmentsErr   error
	roleSchedules        []microsoft.UnifiedRoleEligibilitySchedule
	roleSchedulesErr     error
	servicePrincipals    []microsoft.ServicePrincipal
	servicePrincipalsErr error
	applications         []microsoft.Application
	applicationsErr      error
	secureScores         []microsoft.SecureScore
	secureScoresErr      error
	signIns              []microsoft.SignIn
	signInsErr           error
	directoryAudits      []microsoft.DirectoryAudit
	directoryAuditsErr   error
}

type fakeARM struct {
	subscriptions            map[string]*microsoft.Subscription
	subscriptionErrs         map[string]error
	resources                map[string][]microsoft.ARMResource
	resourceErrs             map[string]error
	secureScores             map[string]*microsoft.ARMSecureScore
	secureScoreErrs          map[string]error
	defenderAssessments      map[string][]microsoft.SecurityAssessment
	defenderAssessmentErrs   map[string]error
	roleAssignments          map[string][]microsoft.ARMRoleAssignment
	roleAssignmentErrs       map[string]error
	policyAssignments        map[string][]microsoft.PolicyAssignment
	policyAssignmentErrs     map[string]error
	policyStateSummaries     map[string]*microsoft.PolicyStateSummaryResult
	policyStateSummaryErrs   map[string]error
	storageAccounts          map[string][]microsoft.StorageAccount
	storageAccountErrs       map[string]error
	keyVaults                map[string][]microsoft.KeyVault
	keyVaultErrs             map[string]error
	sqlServers               map[string][]microsoft.SQLServer
	sqlServerErrs            map[string]error
	sqlDatabases             map[string][]microsoft.SQLDatabase
	sqlDatabaseErrs          map[string]error
	sqlTDE                   map[string]*microsoft.SQLTransparentDataEncryption
	sqlTDEErrs               map[string]error
	virtualMachines          map[string][]microsoft.VirtualMachine
	virtualMachineErrs       map[string]error
	publicIPs                map[string][]microsoft.PublicIPAddress
	publicIPErrs             map[string]error
	networkSecurityGroups    map[string][]microsoft.NetworkSecurityGroup
	networkSecurityGroupErrs map[string]error
	diagnosticSettings       map[string][]microsoft.DiagnosticSetting
	diagnosticSettingErrs    map[string]error
	recoveryVaults           map[string][]microsoft.RecoveryServicesVault
	recoveryVaultErrs        map[string]error
	backupProtectedItems     map[string][]microsoft.BackupProtectedItem
	backupProtectedItemErrs  map[string]error
	backupPolicies           map[string][]microsoft.BackupPolicy
	backupPolicyErrs         map[string]error
	backupJobs               map[string][]microsoft.BackupJob
	backupJobErrs            map[string]error
}

func fakeGraphClient() *fakeGraph {
	enabled := true
	disabled := false
	return &fakeGraph{
		org: &microsoft.Organization{
			ID: "72f988bf-86f1-41af-91ab-2d7cd011db47",
			VerifiedDomains: []microsoft.VerifiedDomain{
				{Name: "contoso.onmicrosoft.com", IsInitial: true},
				{Name: "contoso.com", IsDefault: true},
			},
		},
		users: []microsoft.User{
			{ID: "u1", AccountEnabled: &enabled, UserType: "Member"},
			{ID: "u2", AccountEnabled: &enabled, UserType: "Member"},
			{ID: "u3", AccountEnabled: &enabled, UserType: "Guest"},
			{ID: "u4", AccountEnabled: &disabled, UserType: "Member"},
		},
		signInUsers: []microsoft.User{
			{ID: "u1", AccountEnabled: &enabled, UserType: "Member", SignInActivity: &microsoft.SignInActivity{LastSignInDateTime: "2026-05-20T00:00:00Z"}},
			{ID: "u2", AccountEnabled: &enabled, UserType: "Member", SignInActivity: &microsoft.SignInActivity{LastSignInDateTime: "2026-01-01T00:00:00Z"}},
			{ID: "u3", AccountEnabled: &enabled, UserType: "Guest", SignInActivity: &microsoft.SignInActivity{LastSignInDateTime: "2026-01-01T00:00:00Z"}},
			{ID: "u4", AccountEnabled: &disabled, UserType: "Member", SignInActivity: &microsoft.SignInActivity{LastSignInDateTime: "2026-01-01T00:00:00Z"}},
		},
		registrations: []microsoft.UserRegistrationDetail{
			{ID: "u1", IsMFARegistered: true, IsSSPRRegistered: true, MethodsRegistered: []string{"fido2SecurityKey"}},
			{ID: "u2", IsMFARegistered: false, MethodsRegistered: []string{"sms"}},
			{ID: "u3", IsMFARegistered: true, MethodsRegistered: []string{"mobilePhone"}},
		},
		policies: []microsoft.ConditionalAccessPolicy{
			mfaAllUsersPolicy("mfa-all-users"),
		},
		securityDefaults: &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: false},
		roleAssignments: []microsoft.UnifiedRoleAssignment{
			{ID: "ra1", PrincipalID: "u1", RoleDefinitionID: globalAdministratorTemplateID},
			{ID: "ra2", PrincipalID: "u2", RoleDefinitionID: "194ae4cb-b126-40b2-bd5b-6091b380977d"},
			{ID: "ra3", PrincipalID: "u3", RoleDefinitionID: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"},
			{ID: "ra4", PrincipalID: "u1", RoleDefinitionID: "not-privileged"},
		},
		roleSchedules: []microsoft.UnifiedRoleEligibilitySchedule{
			{ID: "rs1", PrincipalID: "u2", RoleDefinitionID: "194ae4cb-b126-40b2-bd5b-6091b380977d", RoleDefinition: &microsoft.UnifiedRoleDefinition{TemplateID: "194ae4cb-b126-40b2-bd5b-6091b380977d"}},
			{ID: "rs2", PrincipalID: "u1", RoleDefinitionID: "not-privileged", RoleDefinition: &microsoft.UnifiedRoleDefinition{TemplateID: "not-privileged"}},
		},
		servicePrincipals: []microsoft.ServicePrincipal{
			{
				ID: "sp1", AccountEnabled: &enabled, AppRoleAssignmentRequired: &enabled, PreferredSingleSignOnMode: "saml", ServicePrincipalType: "Application",
				PasswordCredentials: []microsoft.PasswordCredential{{KeyID: "sp-p1", StartDateTime: "2025-05-01T00:00:00Z", EndDateTime: "2026-06-01T00:00:00Z"}},
			},
			{
				ID: "sp2", AccountEnabled: &enabled, AppRoleAssignmentRequired: &disabled, PreferredSingleSignOnMode: "oidc", ServicePrincipalType: "Application",
				KeyCredentials: []microsoft.KeyCredential{{KeyID: "sp-k1", StartDateTime: "2025-05-01T00:00:00Z", EndDateTime: "2026-05-01T00:00:00Z"}},
			},
			{ID: "sp3", AccountEnabled: &disabled, AppRoleAssignmentRequired: &enabled, PreferredSingleSignOnMode: "saml", ServicePrincipalType: "Application"},
		},
		applications: []microsoft.Application{
			{
				ID:                  "app1",
				PasswordCredentials: []microsoft.PasswordCredential{{KeyID: "app-p1", StartDateTime: "2025-05-01T00:00:00Z", EndDateTime: "2026-06-10T00:00:00Z"}},
				KeyCredentials:      []microsoft.KeyCredential{{KeyID: "app-k1", StartDateTime: "2025-05-01T00:00:00Z", EndDateTime: "2026-05-01T00:00:00Z"}},
			},
			{
				ID:             "app2",
				KeyCredentials: []microsoft.KeyCredential{{KeyID: "app-k2", StartDateTime: "2026-01-01T00:00:00Z", EndDateTime: "2027-06-01T00:00:00Z"}},
			},
		},
		secureScores: []microsoft.SecureScore{{CurrentScore: 74, MaxScore: 100}},
		signIns: []microsoft.SignIn{
			{
				ID:                      "signin-success",
				UserID:                  "u1",
				AppID:                   "app1",
				ConditionalAccessStatus: "success",
				ClientAppUsed:           "Browser",
				RiskLevelAggregated:     "none",
				AppliedConditionalAccessPolicies: []microsoft.AppliedConditionalAccessPolicy{
					{ID: "policy-1", Result: "success"},
					{ID: "policy-2", Result: "reportOnlyFailure"},
				},
			},
			{
				ID:                      "signin-failure-password",
				UserID:                  "u2",
				AppID:                   "app2",
				Status:                  microsoft.SignInStatus{ErrorCode: 50126, Reason: "Invalid username or password"},
				ConditionalAccessStatus: "failure",
				ClientAppUsed:           "Browser",
				RiskLevelAggregated:     "high",
				AppliedConditionalAccessPolicies: []microsoft.AppliedConditionalAccessPolicy{
					{ID: "policy-1", Result: "failure"},
				},
			},
			{
				ID:                      "signin-failure-legacy",
				UserID:                  "u3",
				AppID:                   "app2",
				Status:                  microsoft.SignInStatus{ErrorCode: 50053, Reason: "Account is locked"},
				ConditionalAccessStatus: "notApplied",
				ClientAppUsed:           "IMAP",
				RiskLevelDuringSignIn:   "medium",
			},
			{
				ID:                      "signin-success-mobile",
				UserID:                  "u1",
				AppID:                   "app1",
				ConditionalAccessStatus: "success",
				ClientAppUsed:           "Mobile Apps and Desktop clients",
				RiskLevelAggregated:     "none",
				AppliedConditionalAccessPolicies: []microsoft.AppliedConditionalAccessPolicy{
					{ID: "policy-3", Result: "notApplied"},
				},
			},
		},
		directoryAudits: []microsoft.DirectoryAudit{
			{
				ID:              "audit-user-add",
				Category:        "UserManagement",
				OperationType:   "Add",
				Result:          "success",
				TargetResources: []microsoft.AuditTargetResource{{Type: "User"}},
			},
			{
				ID:              "audit-app-update",
				Category:        "ApplicationManagement",
				OperationType:   "Update",
				Result:          "failure",
				TargetResources: []microsoft.AuditTargetResource{{Type: "App"}},
			},
			{
				ID:              "audit-role-assign",
				Category:        "RoleManagement",
				OperationType:   "Assign",
				Result:          "success",
				TargetResources: []microsoft.AuditTargetResource{{Type: "Role"}},
			},
			{
				ID:              "audit-policy-delete",
				Category:        "Policy",
				OperationType:   "Delete",
				Result:          "timeout",
				TargetResources: []microsoft.AuditTargetResource{{Type: "Policy"}},
			},
			{
				ID:              "audit-group-update",
				Category:        "GroupManagement",
				OperationType:   "Update",
				Result:          "success",
				TargetResources: []microsoft.AuditTargetResource{{Type: "Group"}},
			},
			{
				ID:              "audit-pim",
				Category:        "RoleManagement",
				LoggedByService: "Privileged Identity Management",
				OperationType:   "Update",
				Result:          "success",
			},
		},
	}
}

func fakeARMClient() *fakeARM {
	subscriptionID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	serverID := "/subscriptions/" + subscriptionID + "/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a"
	dbProtectedID := serverID + "/databases/appdb"
	dbUnprotectedID := serverID + "/databases/logdb"
	vmProtectedID := "/subscriptions/" + subscriptionID + "/resourceGroups/compute/providers/Microsoft.Compute/virtualMachines/vm-a"
	vmUnprotectedID := "/subscriptions/" + subscriptionID + "/resourceGroups/compute/providers/Microsoft.Compute/virtualMachines/vm-b"
	nicID := "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/networkInterfaces/nic-a"
	vaultEnabledID := "/subscriptions/" + subscriptionID + "/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a"
	vaultDisabledID := "/subscriptions/" + subscriptionID + "/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-b"
	trueValue := true
	falseValue := false
	enabledDiagnosticSetting := func() microsoft.DiagnosticSetting {
		return microsoft.DiagnosticSetting{
			Properties: microsoft.DiagnosticSettingProperties{
				WorkspaceID: "/subscriptions/" + subscriptionID + "/resourceGroups/monitor/providers/Microsoft.OperationalInsights/workspaces/law-a",
				Logs:        []microsoft.DiagnosticLogSetting{{Category: "Administrative", Enabled: true}},
			},
		}
	}
	return &fakeARM{
		subscriptions: map[string]*microsoft.Subscription{
			subscriptionID: {SubscriptionID: subscriptionID, State: "Enabled"},
		},
		subscriptionErrs: map[string]error{},
		resources: map[string][]microsoft.ARMResource{
			subscriptionID: {
				{
					ID:       "/subscriptions/" + subscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea",
					Name:     "storagea",
					Type:     "Microsoft.Storage/storageAccounts",
					Location: "eastus",
					Tags:     map[string]string{"owner": "platform", "environment": "prod"},
				},
				{
					ID:       "/subscriptions/" + subscriptionID + "/resourceGroups/security/providers/Microsoft.KeyVault/vaults/kv-a",
					Name:     "kv-a",
					Type:     "Microsoft.KeyVault/vaults",
					Location: "eastus",
					Tags:     map[string]string{"Owner": "security", "env": "production"},
				},
				{
					ID:       vmProtectedID,
					Name:     "vm-a",
					Type:     "Microsoft.Compute/virtualMachines",
					Location: "westus",
					Tags:     map[string]string{"environment": "dev"},
				},
				{
					ID:       serverID,
					Name:     "sql-a",
					Type:     "Microsoft.Sql/servers",
					Location: "eastus",
					Tags:     map[string]string{"contact": "dba"},
				},
				{
					ID:       "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/networkSecurityGroups/nsg-a",
					Name:     "nsg-a",
					Type:     "Microsoft.Network/networkSecurityGroups",
					Location: "westus",
				},
				{
					ID:       "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/publicIPAddresses/pip-a",
					Name:     "pip-a",
					Type:     "Microsoft.Network/publicIPAddresses",
					Location: "westus",
					Tags:     map[string]string{"managed-by": "netops", "stage": "prod"},
				},
				{
					ID:       vaultEnabledID,
					Name:     "vault-a",
					Type:     "Microsoft.RecoveryServices/vaults",
					Location: "eastus",
					Tags:     map[string]string{"Business Owner": "ops", "Environment": "prod"},
				},
			},
		},
		resourceErrs: map[string]error{},
		secureScores: map[string]*microsoft.ARMSecureScore{
			subscriptionID: {
				Name: "ascScore",
				Properties: microsoft.ARMSecureScoreProperties{
					Score: microsoft.ARMScore{Current: 42, Max: 60, Percentage: 0.7},
				},
			},
		},
		secureScoreErrs: map[string]error{},
		defenderAssessments: map[string][]microsoft.SecurityAssessment{
			subscriptionID: {
				{Name: "vm-vulnerability-a", Properties: microsoft.SecurityAssessmentProperties{DisplayName: "Machines should have vulnerability findings resolved", Status: microsoft.SecurityAssessmentStatus{Code: "Unhealthy"}}},
				{Name: "vm-vulnerability-b", Properties: microsoft.SecurityAssessmentProperties{DisplayName: "Machines should have vulnerability findings resolved", Status: microsoft.SecurityAssessmentStatus{Code: "Healthy"}}},
				{Name: "sql-baseline", Properties: microsoft.SecurityAssessmentProperties{DisplayName: "SQL servers should have an Azure Active Directory administrator provisioned", Status: microsoft.SecurityAssessmentStatus{Code: "Unhealthy"}}},
			},
		},
		defenderAssessmentErrs: map[string]error{},
		roleAssignments: map[string][]microsoft.ARMRoleAssignment{
			subscriptionID: {
				{
					ID: "owner-user",
					Properties: microsoft.ARMRoleAssignmentProperties{
						RoleDefinitionID: "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + azureOwnerRoleDefinitionID,
						PrincipalType:    "User",
					},
				},
				{
					ID: "owner-sp",
					Properties: microsoft.ARMRoleAssignmentProperties{
						RoleDefinitionID: "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + azureOwnerRoleDefinitionID,
						PrincipalType:    "ServicePrincipal",
					},
				},
				{
					ID: "reader-sp",
					Properties: microsoft.ARMRoleAssignmentProperties{
						RoleDefinitionID: "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
						PrincipalType:    "ServicePrincipal",
					},
				},
			},
		},
		roleAssignmentErrs: map[string]error{},
		policyAssignments: map[string][]microsoft.PolicyAssignment{
			subscriptionID: {
				{ID: "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/policyAssignments/security-baseline", Name: "security-baseline"},
				{ID: "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/policyAssignments/tagging", Name: "tagging"},
			},
		},
		policyAssignmentErrs: map[string]error{},
		policyStateSummaries: map[string]*microsoft.PolicyStateSummaryResult{
			subscriptionID: {
				Value: []microsoft.PolicyStateSummary{
					{
						Results: microsoft.PolicyStateSummaryResults{
							NonCompliantResources: 2,
							ResourceDetails: []microsoft.ComplianceDetail{
								{ComplianceState: "compliant", Count: 6},
								{ComplianceState: "noncompliant", Count: 2},
							},
						},
					},
				},
			},
		},
		policyStateSummaryErrs: map[string]error{},
		storageAccounts: map[string][]microsoft.StorageAccount{
			subscriptionID: {
				{
					ID:   "/subscriptions/" + subscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea",
					Name: "storagea",
					Properties: microsoft.StorageAccountProperties{
						SupportsHTTPSTrafficOnly: &trueValue,
						MinimumTLSVersion:        "TLS1_2",
						Encryption:               microsoft.StorageEncryption{KeySource: "Microsoft.Keyvault", RequireInfrastructureEncryption: &trueValue},
						AllowBlobPublicAccess:    &falseValue,
						PublicNetworkAccess:      "Disabled",
					},
				},
				{
					ID:   "/subscriptions/" + subscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storageb",
					Name: "storageb",
					Properties: microsoft.StorageAccountProperties{
						SupportsHTTPSTrafficOnly: &falseValue,
						MinimumTLSVersion:        "TLS1_0",
						Encryption:               microsoft.StorageEncryption{KeySource: "Microsoft.Storage", RequireInfrastructureEncryption: &falseValue},
						AllowBlobPublicAccess:    &trueValue,
						PublicNetworkAccess:      "Enabled",
					},
				},
			},
		},
		storageAccountErrs: map[string]error{},
		keyVaults: map[string][]microsoft.KeyVault{
			subscriptionID: {
				{ID: "/subscriptions/" + subscriptionID + "/resourceGroups/security/providers/Microsoft.KeyVault/vaults/kv-a", Name: "kv-a", Properties: microsoft.KeyVaultProperties{EnablePurgeProtection: &trueValue, EnableRBACAuthorization: &trueValue}},
				{ID: "/subscriptions/" + subscriptionID + "/resourceGroups/security/providers/Microsoft.KeyVault/vaults/kv-b", Name: "kv-b", Properties: microsoft.KeyVaultProperties{EnablePurgeProtection: &falseValue, EnableRBACAuthorization: &falseValue}},
			},
		},
		keyVaultErrs: map[string]error{},
		sqlServers: map[string][]microsoft.SQLServer{
			subscriptionID: {
				{ID: serverID, Name: "sql-a", Properties: microsoft.SQLServerProperties{MinimalTLSVersion: "1.2", PublicNetworkAccess: "Disabled"}},
			},
		},
		sqlServerErrs: map[string]error{},
		sqlDatabases: map[string][]microsoft.SQLDatabase{
			serverID: {
				{ID: dbProtectedID, Name: "appdb"},
				{ID: dbUnprotectedID, Name: "logdb"},
				{ID: serverID + "/databases/master", Name: "master"},
			},
		},
		sqlDatabaseErrs: map[string]error{},
		sqlTDE: map[string]*microsoft.SQLTransparentDataEncryption{
			dbProtectedID:   {Name: "current", Properties: microsoft.SQLTransparentDataEncryptionProperties{State: "Enabled"}},
			dbUnprotectedID: {Name: "current", Properties: microsoft.SQLTransparentDataEncryptionProperties{State: "Disabled"}},
		},
		sqlTDEErrs: map[string]error{},
		virtualMachines: map[string][]microsoft.VirtualMachine{
			subscriptionID: {
				{
					ID:   vmProtectedID,
					Name: "vm-a",
					Properties: microsoft.VirtualMachineProperties{
						StorageProfile: microsoft.VirtualMachineStorageProfile{
							OSDisk: microsoft.VirtualMachineDisk{ManagedDisk: &microsoft.ManagedDiskReference{ID: vmProtectedID + "/disks/os"}},
						},
						NetworkProfile: microsoft.VirtualMachineNetworkProfile{
							NetworkInterfaces: []microsoft.NetworkInterfaceReference{{ID: nicID}},
						},
					},
				},
				{
					ID:   vmUnprotectedID,
					Name: "vm-b",
					Properties: microsoft.VirtualMachineProperties{
						StorageProfile: microsoft.VirtualMachineStorageProfile{
							OSDisk: microsoft.VirtualMachineDisk{},
						},
					},
				},
			},
		},
		virtualMachineErrs: map[string]error{},
		publicIPs: map[string][]microsoft.PublicIPAddress{
			subscriptionID: {
				{ID: "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/publicIPAddresses/pip-a", Name: "pip-a", Properties: microsoft.PublicIPAddressProperties{IPConfiguration: &microsoft.SubResource{ID: nicID + "/ipConfigurations/ipconfig1"}}},
			},
		},
		publicIPErrs: map[string]error{},
		networkSecurityGroups: map[string][]microsoft.NetworkSecurityGroup{
			subscriptionID: {
				{
					ID:   "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/networkSecurityGroups/nsg-a",
					Name: "nsg-a",
					Properties: microsoft.NetworkSecurityGroupProperties{
						SecurityRules: []microsoft.SecurityRule{
							{
								Name: "allow-ssh-world",
								Properties: microsoft.SecurityRuleProperties{
									Access:               "Allow",
									Direction:            "Inbound",
									Protocol:             "Tcp",
									SourceAddressPrefix:  "*",
									DestinationPortRange: "22",
								},
							},
						},
					},
				},
				{
					ID:   "/subscriptions/" + subscriptionID + "/resourceGroups/network/providers/Microsoft.Network/networkSecurityGroups/nsg-b",
					Name: "nsg-b",
					Properties: microsoft.NetworkSecurityGroupProperties{
						SecurityRules: []microsoft.SecurityRule{
							{
								Name: "allow-rdp-private",
								Properties: microsoft.SecurityRuleProperties{
									Access:               "Allow",
									Direction:            "Inbound",
									Protocol:             "Tcp",
									SourceAddressPrefix:  "10.0.0.0/8",
									DestinationPortRange: "3389",
								},
							},
						},
					},
				},
			},
		},
		networkSecurityGroupErrs: map[string]error{},
		diagnosticSettings: map[string][]microsoft.DiagnosticSetting{
			"/subscriptions/" + subscriptionID: {enabledDiagnosticSetting()},
			"/subscriptions/" + subscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea": {enabledDiagnosticSetting()},
			"/subscriptions/" + subscriptionID + "/resourceGroups/security/providers/Microsoft.KeyVault/vaults/kv-a":         {enabledDiagnosticSetting()},
			serverID:      {enabledDiagnosticSetting()},
			dbProtectedID: {enabledDiagnosticSetting()},
			vmProtectedID: {enabledDiagnosticSetting()},
		},
		diagnosticSettingErrs: map[string]error{},
		recoveryVaults: map[string][]microsoft.RecoveryServicesVault{
			subscriptionID: {
				{
					ID:   vaultEnabledID,
					Name: "vault-a",
					Properties: microsoft.RecoveryServicesVaultProperties{
						SecuritySettings: microsoft.VaultSecuritySettings{
							SoftDeleteSettings:   microsoft.VaultSoftDeleteSettings{SoftDeleteState: "Enabled"},
							ImmutabilitySettings: microsoft.VaultImmutabilitySettings{State: "Locked"},
						},
					},
				},
				{
					ID:   vaultDisabledID,
					Name: "vault-b",
					Properties: microsoft.RecoveryServicesVaultProperties{
						SecuritySettings: microsoft.VaultSecuritySettings{
							SoftDeleteSettings:   microsoft.VaultSoftDeleteSettings{SoftDeleteState: "Disabled"},
							ImmutabilitySettings: microsoft.VaultImmutabilitySettings{State: "Disabled"},
						},
					},
				},
			},
		},
		recoveryVaultErrs: map[string]error{},
		backupProtectedItems: map[string][]microsoft.BackupProtectedItem{
			vaultEnabledID: {
				{ID: "protected-vm", Properties: microsoft.BackupProtectedItemProperties{SourceResourceID: vmProtectedID, ProtectionState: "Protected"}},
				{ID: "protected-db", Properties: microsoft.BackupProtectedItemProperties{SourceResourceID: dbProtectedID, ProtectionState: "Protected"}},
			},
			vaultDisabledID: nil,
		},
		backupProtectedItemErrs: map[string]error{},
		backupPolicies: map[string][]microsoft.BackupPolicy{
			vaultEnabledID: {
				{
					ID: "policy-30d",
					Properties: map[string]any{
						"retentionPolicy": map[string]any{
							"dailySchedule": map[string]any{
								"retentionDuration": map[string]any{"count": float64(30), "durationType": "Days"},
							},
						},
					},
				},
				{
					ID: "policy-90d",
					Properties: map[string]any{
						"retentionPolicy": map[string]any{
							"weeklySchedule": map[string]any{
								"retentionDuration": map[string]any{"count": float64(13), "durationType": "Weeks"},
							},
						},
					},
				},
			},
			vaultDisabledID: nil,
		},
		backupPolicyErrs: map[string]error{},
		backupJobs: map[string][]microsoft.BackupJob{
			vaultEnabledID: {
				{ID: "job-success-recent", Properties: microsoft.BackupJobProperties{Operation: "Backup", Status: "Completed", EndTime: "2026-05-25T14:12:09Z"}},
				{ID: "job-success-old", Properties: microsoft.BackupJobProperties{Operation: "Backup", Status: "Completed", EndTime: "2026-05-20T14:12:09Z"}},
				{ID: "job-failed", Properties: microsoft.BackupJobProperties{Operation: "Backup", Status: "Failed", StartTime: "2026-05-24T14:12:09Z"}},
			},
			vaultDisabledID: nil,
		},
		backupJobErrs: map[string]error{},
	}
}

func (f *fakeGraph) Organization(context.Context) (*microsoft.Organization, error) {
	return f.org, nil
}

func (f *fakeGraph) Users(context.Context) ([]microsoft.User, error) {
	return f.users, nil
}

func (f *fakeGraph) UsersWithSignInActivity(context.Context) ([]microsoft.User, error) {
	return f.signInUsers, nil
}

func (f *fakeGraph) UserRegistrationDetails(context.Context) ([]microsoft.UserRegistrationDetail, error) {
	return f.registrations, f.regErr
}

func (f *fakeGraph) ConditionalAccessPolicies(context.Context) ([]microsoft.ConditionalAccessPolicy, error) {
	return f.policies, f.policiesErr
}

func (f *fakeGraph) SecurityDefaults(context.Context) (*microsoft.IdentitySecurityDefaultsEnforcementPolicy, error) {
	return f.securityDefaults, f.securityDefErr
}

func (f *fakeGraph) RoleAssignments(context.Context) ([]microsoft.UnifiedRoleAssignment, error) {
	return f.roleAssignments, f.roleAssignmentsErr
}

func (f *fakeGraph) RoleEligibilitySchedules(context.Context) ([]microsoft.UnifiedRoleEligibilitySchedule, error) {
	return f.roleSchedules, f.roleSchedulesErr
}

func (f *fakeGraph) ServicePrincipals(context.Context) ([]microsoft.ServicePrincipal, error) {
	return f.servicePrincipals, f.servicePrincipalsErr
}

func (f *fakeGraph) Applications(context.Context) ([]microsoft.Application, error) {
	return f.applications, f.applicationsErr
}

func (f *fakeGraph) SecureScores(context.Context) ([]microsoft.SecureScore, error) {
	return f.secureScores, f.secureScoresErr
}

func (f *fakeGraph) SignIns(context.Context, time.Time) ([]microsoft.SignIn, error) {
	return f.signIns, f.signInsErr
}

func (f *fakeGraph) DirectoryAudits(context.Context, time.Time) ([]microsoft.DirectoryAudit, error) {
	return f.directoryAudits, f.directoryAuditsErr
}

func (f *fakeARM) Subscription(_ context.Context, subscriptionID string) (*microsoft.Subscription, error) {
	if err := f.subscriptionErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.subscriptions[subscriptionID], nil
}

func (f *fakeARM) Resources(_ context.Context, subscriptionID string) ([]microsoft.ARMResource, error) {
	if err := f.resourceErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.resources[subscriptionID], nil
}

func (f *fakeARM) DefenderSecureScore(_ context.Context, subscriptionID string) (*microsoft.ARMSecureScore, error) {
	if err := f.secureScoreErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.secureScores[subscriptionID], nil
}

func (f *fakeARM) DefenderAssessments(_ context.Context, subscriptionID string) ([]microsoft.SecurityAssessment, error) {
	if err := f.defenderAssessmentErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.defenderAssessments[subscriptionID], nil
}

func (f *fakeARM) RoleAssignments(_ context.Context, subscriptionID string) ([]microsoft.ARMRoleAssignment, error) {
	if err := f.roleAssignmentErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.roleAssignments[subscriptionID], nil
}

func (f *fakeARM) PolicyAssignments(_ context.Context, subscriptionID string) ([]microsoft.PolicyAssignment, error) {
	if err := f.policyAssignmentErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.policyAssignments[subscriptionID], nil
}

func (f *fakeARM) PolicyStateSummary(_ context.Context, subscriptionID string) (*microsoft.PolicyStateSummaryResult, error) {
	if err := f.policyStateSummaryErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.policyStateSummaries[subscriptionID], nil
}

func (f *fakeARM) StorageAccounts(_ context.Context, subscriptionID string) ([]microsoft.StorageAccount, error) {
	if err := f.storageAccountErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.storageAccounts[subscriptionID], nil
}

func (f *fakeARM) KeyVaults(_ context.Context, subscriptionID string) ([]microsoft.KeyVault, error) {
	if err := f.keyVaultErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.keyVaults[subscriptionID], nil
}

func (f *fakeARM) SQLServers(_ context.Context, subscriptionID string) ([]microsoft.SQLServer, error) {
	if err := f.sqlServerErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.sqlServers[subscriptionID], nil
}

func (f *fakeARM) SQLDatabases(_ context.Context, serverID string) ([]microsoft.SQLDatabase, error) {
	if err := f.sqlDatabaseErrs[serverID]; err != nil {
		return nil, err
	}
	return f.sqlDatabases[serverID], nil
}

func (f *fakeARM) SQLTransparentDataEncryption(_ context.Context, databaseID string) (*microsoft.SQLTransparentDataEncryption, error) {
	if err := f.sqlTDEErrs[databaseID]; err != nil {
		return nil, err
	}
	return f.sqlTDE[databaseID], nil
}

func (f *fakeARM) VirtualMachines(_ context.Context, subscriptionID string) ([]microsoft.VirtualMachine, error) {
	if err := f.virtualMachineErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.virtualMachines[subscriptionID], nil
}

func (f *fakeARM) PublicIPAddresses(_ context.Context, subscriptionID string) ([]microsoft.PublicIPAddress, error) {
	if err := f.publicIPErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.publicIPs[subscriptionID], nil
}

func (f *fakeARM) NetworkSecurityGroups(_ context.Context, subscriptionID string) ([]microsoft.NetworkSecurityGroup, error) {
	if err := f.networkSecurityGroupErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.networkSecurityGroups[subscriptionID], nil
}

func (f *fakeARM) DiagnosticSettings(_ context.Context, resourceID string) ([]microsoft.DiagnosticSetting, error) {
	if err := f.diagnosticSettingErrs[resourceID]; err != nil {
		return nil, err
	}
	return f.diagnosticSettings[resourceID], nil
}

func (f *fakeARM) SubscriptionDiagnosticSettings(_ context.Context, subscriptionID string) ([]microsoft.DiagnosticSetting, error) {
	resourceID := "/subscriptions/" + subscriptionID
	if err := f.diagnosticSettingErrs[resourceID]; err != nil {
		return nil, err
	}
	return f.diagnosticSettings[resourceID], nil
}

func (f *fakeARM) RecoveryServicesVaults(_ context.Context, subscriptionID string) ([]microsoft.RecoveryServicesVault, error) {
	if err := f.recoveryVaultErrs[subscriptionID]; err != nil {
		return nil, err
	}
	return f.recoveryVaults[subscriptionID], nil
}

func (f *fakeARM) BackupProtectedItems(_ context.Context, vaultID string) ([]microsoft.BackupProtectedItem, error) {
	if err := f.backupProtectedItemErrs[vaultID]; err != nil {
		return nil, err
	}
	return f.backupProtectedItems[vaultID], nil
}

func (f *fakeARM) BackupPolicies(_ context.Context, vaultID string) ([]microsoft.BackupPolicy, error) {
	if err := f.backupPolicyErrs[vaultID]; err != nil {
		return nil, err
	}
	return f.backupPolicies[vaultID], nil
}

func (f *fakeARM) BackupJobs(_ context.Context, vaultID, _ string) ([]microsoft.BackupJob, error) {
	if err := f.backupJobErrs[vaultID]; err != nil {
		return nil, err
	}
	return f.backupJobs[vaultID], nil
}

func TestCollectorScaffold(t *testing.T) {
	c, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entra == nil {
		t.Fatal("expected detailed Entra artifact")
	}
	if result.Azure == nil || result.AzureCloudPosture == nil {
		t.Fatal("expected Azure artifacts in Slice C")
	}
}

func TestTenantIdentity(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	if artifact.TenantID != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Fatalf("unexpected tenant_id: %s", artifact.TenantID)
	}
	if artifact.OrgDomain != "contoso.com" {
		t.Fatalf("unexpected org_domain: %s", artifact.OrgDomain)
	}
}

func TestEnabledMemberCount(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	if artifact.Users.TotalCount != 4 {
		t.Fatalf("unexpected total count: %d", artifact.Users.TotalCount)
	}
	if artifact.Users.EnabledMemberUsersCount != 2 {
		t.Fatalf("unexpected enabled member count: %d", artifact.Users.EnabledMemberUsersCount)
	}
}

func TestMfaRegistrationReport(t *testing.T) {
	graph := fakeGraphClient()
	graph.regErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/reports/authenticationMethods/userRegistrationDetails"}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Posture.MFACoverage != nil {
		t.Fatalf("expected null MFA coverage, got %v", *artifact.Posture.MFACoverage)
	}
	if len(artifact.Diagnostics.Warnings) != 1 {
		t.Fatalf("expected warning, got %v", artifact.Diagnostics.Warnings)
	}
}

func TestMfaRegistrationReportPremiumLicenseFailure(t *testing.T) {
	graph := fakeGraphClient()
	graph.regErr = &microsoft.APIError{
		StatusCode: http.StatusForbidden,
		Route:      "/reports/authenticationMethods/userRegistrationDetails",
		Code:       "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
		Message:    "The tenant does not have a Premium license.",
	}
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Posture.MFACoverage != nil {
		t.Fatalf("expected null MFA coverage, got %v", *artifact.Posture.MFACoverage)
	}
	if got := artifact.Diagnostics.License.CapabilitiesUnavailable; len(got) != 1 || got[0] != "mfa_registration_report" {
		t.Fatalf("unexpected unavailable capabilities: %v", got)
	}
}

func TestMfaCoverage(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	if artifact.Posture.MFACoverage == nil {
		t.Fatal("expected MFA coverage")
	}
	if *artifact.Posture.MFACoverage != 50 {
		t.Fatalf("expected 50, got %d", *artifact.Posture.MFACoverage)
	}
	if artifact.Posture.MFAPhishingResistant == nil || *artifact.Posture.MFAPhishingResistant != 50 {
		t.Fatalf("unexpected phishing-resistant coverage: %#v", artifact.Posture.MFAPhishingResistant)
	}
	if artifact.Posture.DenominatorEnabledMemberUsers != 2 {
		t.Fatalf("unexpected denominator: %d", artifact.Posture.DenominatorEnabledMemberUsers)
	}
}

func TestMfaCoverageZeroDenominator(t *testing.T) {
	graph := fakeGraphClient()
	graph.users = nil
	cfg := testConfig()
	cfg.GraphClient = graph

	artifact := collectTestArtifact(t, cfg)
	if artifact.Posture.MFACoverage != nil {
		t.Fatalf("expected null MFA coverage, got %v", *artifact.Posture.MFACoverage)
	}
}

func TestClock(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: time.Date(2026, 5, 26, 14, 12, 9, 0, time.UTC)}
	artifact := collectTestArtifact(t, cfg)
	if artifact.CollectedAt != "2026-05-26T14:12:09Z" {
		t.Fatalf("unexpected collected_at: %s", artifact.CollectedAt)
	}
}

func TestNormalizedIdp(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	idp := artifact.ToIDPPosture()
	if idp == nil {
		t.Fatal("expected normalized artifact")
	}
	if idp.Provider != "entra" {
		t.Fatalf("unexpected provider: %s", idp.Provider)
	}
	if idp.UserSecurity.MFACoveragePct == nil || *idp.UserSecurity.MFACoveragePct != 50 {
		t.Fatalf("unexpected MFA coverage: %#v", idp.UserSecurity.MFACoveragePct)
	}

	artifact.Posture.MFACoverage = nil
	artifact.Posture.MFAPhishingResistant = nil
	artifact.Posture.SSOCoverage = nil
	artifact.Users.InactivePct = nil
	artifact.Users.DisabledPct = nil
	artifact.Policy = nil
	artifact.PrivilegedAccess = nil
	if idp := artifact.ToIDPPosture(); idp != nil {
		t.Fatal("expected nil normalized artifact without normalized source fields")
	}
}

func TestSliceAGolden(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: time.Date(2026, 5, 26, 14, 12, 9, 0, time.UTC)}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	assertGoldenJSON(t, "../../testdata/golden/slice_a/entra.json", result.Entra)
	assertGoldenJSON(t, "../../testdata/golden/slice_a/idp-posture.json", result.EntraIDPPosture)

	artifacts := result.Artifacts()
	if len(artifacts) != 4 {
		t.Fatalf("expected 4 artifacts, got %d", len(artifacts))
	}
}

func collectTestArtifact(t *testing.T, cfg Config) *EntraArtifact {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entra == nil {
		t.Fatal("expected Entra artifact")
	}
	return result.Entra
}

func assertGoldenJSON(t *testing.T, relPath string, actual any) {
	t.Helper()
	got, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := filepath.Clean(relPath)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", path, want, got)
	}
}

func TestConfigErrorTypeIsPreserved(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error")
	}
	var configErr componentsdk.ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected config error, got %T", err)
	}
}
