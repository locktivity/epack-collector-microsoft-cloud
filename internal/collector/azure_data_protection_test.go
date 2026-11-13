package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestStorageTrust(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	storage := artifact.Accounts[0].Storage
	if storage == nil {
		t.Fatal("expected storage posture")
	}
	assertInt(t, "storage account count", storage.StorageAccountsCount, 2)
	assertPtrInt(t, "https only", storage.HTTPSOnlyPct, 50)
	assertPtrInt(t, "minimum TLS 1.2", storage.MinTLS12Pct, 50)
	assertPtrInt(t, "CMK encryption", storage.EncryptionCMKPct, 50)
	assertPtrInt(t, "infrastructure encryption", storage.InfrastructureEncryptionPct, 50)
	assertPtrInt(t, "public access blocked", storage.PublicAccessBlockedPct, 50)
	assertPtrInt(t, "network restricted", storage.NetworkRestrictedPct, 50)
}

// Anonymous access and network access are separate settings. An account
// reachable from the internet still refuses anonymous reads when
// allowBlobPublicAccess is false. An account without allowBlobPublicAccess
// allows anonymous access.
func TestStorageCountsAnonymousAccessApartFromNetworkAccess(t *testing.T) {
	falseValue, trueValue := false, true
	account := func(name string, allow *bool, publicNetwork, defaultAction string) microsoft.StorageAccount {
		props := microsoft.StorageAccountProperties{AllowBlobPublicAccess: allow, PublicNetworkAccess: publicNetwork}
		if defaultAction != "" {
			props.NetworkACLs = &microsoft.StorageNetworkACLs{DefaultAction: defaultAction}
		}
		return microsoft.StorageAccount{ID: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/" + name, Name: name, Properties: props}
	}
	arm := fakeARMClient()
	arm.storageAccounts["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = []microsoft.StorageAccount{
		account("open", &falseValue, "Enabled", ""),
		account("firewalled", &falseValue, "Enabled", "Deny"),
		account("unset", nil, "Disabled", ""),
		account("anonymous", &trueValue, "Enabled", "Allow"),
		account("legacy", &falseValue, "", ""),
	}
	cfg := testConfig()
	cfg.ARMClient = arm
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	storage := result.Azure.Accounts[0].Storage
	assertPtrInt(t, "public access blocked", storage.PublicAccessBlockedPct, 60)
	assertPtrInt(t, "network restricted", storage.NetworkRestrictedPct, 40)
	assertPtrInt(t, "normalized public access blocked", result.AzureCloudPosture.Accounts[0].Storage.PublicAccessBlockedPct.Value, 60)
	assertPtrInt(t, "normalized network restricted", result.AzureCloudPosture.Accounts[0].Storage.NetworkRestrictedPct.Value, 40)
}

// Azure encrypts every storage account at rest with its own key unless the
// account names a customer-managed one, so the normalized encryption counts
// every account, one with no key source too, since Azure's key is the
// default. The azure artifact's encryption_cmk_pct counts the
// customer-managed ones.
func TestStorageEncryptionAtRestCountsAnyKeySource(t *testing.T) {
	account := func(name, keySource string) microsoft.StorageAccount {
		return microsoft.StorageAccount{
			ID:         "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/" + name,
			Name:       name,
			Properties: microsoft.StorageAccountProperties{Encryption: microsoft.StorageEncryption{KeySource: keySource}},
		}
	}
	arm := fakeARMClient()
	arm.storageAccounts["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = []microsoft.StorageAccount{
		account("customer", "Microsoft.Keyvault"),
		account("azure", "Microsoft.Storage"),
		account("unreported", ""),
	}
	cfg := testConfig()
	cfg.ARMClient = arm
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}

	assertPtrInt(t, "customer-managed keys", result.Azure.Accounts[0].Storage.EncryptionCMKPct, 33)
	normalized := result.AzureCloudPosture.Accounts[0].Storage
	assertPtrInt(t, "normalized encrypted count", normalized.EncryptedStorageResourceCount, 3)
	assertPtrInt(t, "normalized encryption", normalized.EncryptionPct.Value, 100)
}

func TestStorageTrustZeroDenominator(t *testing.T) {
	arm := fakeARMClient()
	arm.storageAccounts["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	storage := artifact.Accounts[0].Storage
	if storage == nil || storage.StorageAccountsCount != 0 {
		t.Fatalf("unexpected storage posture: %#v", storage)
	}
	if storage.HTTPSOnlyPct != nil || storage.PublicAccessBlockedPct != nil {
		t.Fatalf("expected null storage percentages, got %#v", storage)
	}
}

func TestKeyVaultTrust(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	keyVault := artifact.Accounts[0].KeyVault
	if keyVault == nil {
		t.Fatal("expected key vault posture")
	}
	assertInt(t, "vault count", keyVault.VaultsCount, 2)
	assertPtrInt(t, "purge protection", keyVault.PurgeProtectionPct, 50)
	assertPtrInt(t, "RBAC authorization", keyVault.RBACAuthorizationPct, 50)
}

func TestSQLTrust(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	sql := artifact.Accounts[0].SQL
	if sql == nil {
		t.Fatal("expected SQL posture")
	}
	assertInt(t, "server count", sql.ServersCount, 1)
	assertPtrInt(t, "database count", sql.DatabasesCount, 2)
	assertPtrInt(t, "TDE enabled", sql.TDEEnabledPct, 50)
	assertPtrInt(t, "minimum TLS 1.2", sql.MinTLS12Pct, 100)
	assertPtrInt(t, "public access disabled", sql.PublicAccessDisabledPct, 100)
}

func TestComputeTrust(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	compute := artifact.Accounts[0].Compute
	if compute == nil {
		t.Fatal("expected compute posture")
	}
	assertInt(t, "VM count", compute.VirtualMachinesCount, 2)
	assertPtrInt(t, "disk encryption", compute.DiskEncryptionPct, 50)
	assertPtrInt(t, "public IP", compute.PublicIPPct, 50)
}

func TestBackupTrust(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}

	artifact := collectTestAzureArtifact(t, cfg)
	backup := artifact.Accounts[0].Backup
	if backup == nil {
		t.Fatal("expected backup posture")
	}
	assertPtrInt(t, "protected resource", backup.ProtectedResourcePct, 50)
	assertPtrInt(t, "retention days min", backup.RetentionDaysMin, 30)
	assertPtrInt(t, "latest successful backup age", backup.LatestSuccessfulBackupAgeHoursMax, 144)
	assertPtrInt(t, "failed jobs", backup.FailedJobs7dCount, 1)
	assertPtrInt(t, "vault soft delete", backup.VaultSoftDeletePct, 50)
	assertPtrInt(t, "vault immutability", backup.VaultImmutabilityPct, 50)
}

// Azure's vault list leaves out each vault's security settings, so each
// vault is read on its own. A vault that can't be read leaves the soft delete
// and immutability shares out rather than counting as off.
func TestVaultSharesLeftOutWhenAVaultCantBeRead(t *testing.T) {
	arm := fakeARMClient()
	vaultID := arm.recoveryVaults["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"][0].ID
	arm.recoveryVaultReadErrs = map[string]error{vaultID: &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: vaultID, Code: "AuthorizationFailed"}}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec

	backup := collectTestAzureArtifact(t, cfg).Accounts[0].Backup
	if backup.VaultSoftDeletePct != nil || backup.VaultImmutabilityPct != nil {
		t.Fatalf("vault shares = %v, %v, want both left out", backup.VaultSoftDeletePct, backup.VaultImmutabilityPct)
	}
	assertGap(t, rec, azurePath, "/accounts/0/backup/vault_soft_delete_pct", componentsdk.CodePermissionDenied)
	assertGap(t, rec, azurePath, "/accounts/0/backup/vault_immutability_pct", componentsdk.CodePermissionDenied)
	assertPtrInt(t, "retention days min", backup.RetentionDaysMin, 30)
}

func TestBackupJobHistoryUnavailable(t *testing.T) {
	arm := fakeARMClient()
	arm.backupJobErrs["/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/backupJobs"}
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	backup := artifact.Accounts[0].Backup
	if backup == nil {
		t.Fatal("expected backup posture")
	}
	if backup.LatestSuccessfulBackupAgeHoursMax != nil || backup.FailedJobs7dCount != nil {
		t.Fatalf("expected null job metrics, got %#v", backup)
	}
	if len(artifact.Diagnostics.Warnings) == 0 {
		t.Fatal("expected job history warning")
	}
}

func TestNormalizedCloudSliceD(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	account := result.AzureCloudPosture.Accounts[0]
	if account.Storage == nil {
		t.Fatal("expected normalized storage")
	}
	assertPtrInt(t, "normalized storage encryption", account.Storage.EncryptionPct.Value, 100)
	assertPtrInt(t, "normalized storage network restricted", account.Storage.NetworkRestrictedPct.Value, 50)
	assertPtrInt(t, "normalized storage public access", account.Storage.PublicAccessBlockedPct.Value, 50)
	if account.Backup == nil {
		t.Fatal("expected normalized backup")
	}
	assertPtrInt(t, "normalized backup retention", account.Backup.RetentionDaysMin.Value, 30)
}

// With no Recovery Services vault, no backup policy sets a retention period.
// The cloud-posture schema has null for that.
func TestNormalizedBackupRetentionIsNullWithoutVaults(t *testing.T) {
	arm := fakeARMClient()
	arm.recoveryVaults[kitSubscriptionID] = nil
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result.AzureCloudPosture.Accounts[0])
	if err != nil {
		t.Fatal(err)
	}
	var account struct {
		Backup map[string]any `json:"backup"`
	}
	if err := json.Unmarshal(raw, &account); err != nil {
		t.Fatal(err)
	}
	if value, ok := account.Backup["retention_days_min"]; !ok || value != nil {
		t.Fatalf("backup = %s, want retention_days_min null", raw)
	}
	for _, gap := range rec.Gaps() {
		if gap.Path == cloudPosturePath {
			t.Fatalf("unexpected cloud-posture gap %#v", gap)
		}
	}
}

func TestNormalizedBackupRetentionLeftOutWhenPoliciesAreUnread(t *testing.T) {
	arm := fakeARMClient()
	arm.backupPolicyErrs["/subscriptions/"+kitSubscriptionID+"/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-b"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/backupPolicies"}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if backup := result.AzureCloudPosture.Accounts[0].Backup; backup != nil {
		t.Fatalf("expected the normalized backup left out, got %#v", backup)
	}
	assertGap(t, rec, cloudPosturePath, "/accounts/0/backup/retention_days_min", componentsdk.CodePermissionDenied)
}

// Every vault lists its built-in DefaultPolicy, whether or not a protected
// item uses it. The retention comes from the policies the items use.
func TestBackupRetentionCountsOnlyPoliciesInUse(t *testing.T) {
	const vaultID = "/subscriptions/" + kitSubscriptionID + "/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a"
	policy := func(name string, days int) microsoft.BackupPolicy {
		return microsoft.BackupPolicy{
			ID:   vaultID + "/backupPolicies/" + name,
			Name: name,
			Properties: map[string]any{
				"backupManagementType": "AzureIaasVM",
				"retentionPolicy": map[string]any{
					"retentionPolicyType": "LongTermRetentionPolicy",
					"dailySchedule": map[string]any{
						"retentionDuration": map[string]any{"count": float64(days), "durationType": "Days"},
					},
				},
			},
		}
	}
	item := func(vm, policyID string) microsoft.BackupProtectedItem {
		return microsoft.BackupProtectedItem{
			ID: vaultID + "/backupFabrics/Azure/protectionContainers/iaasvmcontainer;" + vm + "/protectedItems/vm;" + vm,
			Properties: microsoft.BackupProtectedItemProperties{
				SourceResourceID: "/subscriptions/" + kitSubscriptionID + "/resourceGroups/compute/providers/Microsoft.Compute/virtualMachines/" + vm,
				PolicyID:         policyID,
				ProtectionState:  "Protected",
			},
		}
	}
	cases := []struct {
		name     string
		policies []microsoft.BackupPolicy
		items    []microsoft.BackupProtectedItem
		want     *int
	}{
		{"unused shorter policy", []microsoft.BackupPolicy{policy("DefaultPolicy", 30), policy("prod", 365)},
			[]microsoft.BackupProtectedItem{item("vm-a", vaultID+"/backupPolicies/prod"), item("vm-b", vaultID+"/backupPolicies/prod")}, intPtr(365)},
		{"shortest policy in use", []microsoft.BackupPolicy{policy("DefaultPolicy", 30), policy("short", 14), policy("prod", 365)},
			[]microsoft.BackupProtectedItem{item("vm-a", vaultID+"/backupPolicies/short"), item("vm-b", vaultID+"/backupPolicies/prod")}, intPtr(14)},
		{"policy ID in another case", []microsoft.BackupPolicy{policy("DefaultPolicy", 30), policy("prod", 365)},
			[]microsoft.BackupProtectedItem{item("vm-a", strings.ToLower(vaultID+"/backupPolicies/prod"))}, intPtr(365)},
		{"nothing protected", []microsoft.BackupPolicy{policy("DefaultPolicy", 30)}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.recoveryVaults[kitSubscriptionID] = []microsoft.RecoveryServicesVault{{ID: vaultID, Name: "vault-a"}}
			arm.backupPolicies = map[string][]microsoft.BackupPolicy{vaultID: tc.policies}
			arm.backupProtectedItems = map[string][]microsoft.BackupProtectedItem{vaultID: tc.items}
			cfg := testConfig()
			cfg.ARMClient = arm
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
			if err != nil {
				t.Fatal(err)
			}
			got := result.Azure.Accounts[0].Backup.RetentionDaysMin
			normalized := result.AzureCloudPosture.Accounts[0].Backup.RetentionDaysMin
			if !normalized.Read {
				t.Fatal("normalized retention_days_min is left out, want it written")
			}
			if tc.want == nil {
				if got != nil || normalized.Value != nil {
					t.Fatalf("retention_days_min = %v and normalized %v, want null", got, normalized.Value)
				}
				return
			}
			assertPtrInt(t, "retention_days_min", got, *tc.want)
			assertPtrInt(t, "normalized retention_days_min", normalized.Value, *tc.want)
		})
	}
}

// TestBackupRetentionLeftOutWhenTheAnswersDisagree checks that an item under
// protection always names a policy the vault lists, with a retention
// period, and that a retention duration holds its count and durationType.
// An answer that breaks one leaves the retention out rather than reading as
// a longer one, or none.
func TestBackupRetentionLeftOutWhenTheAnswersDisagree(t *testing.T) {
	const vaultID = "/subscriptions/" + kitSubscriptionID + "/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a"
	policy := func(duration map[string]any) microsoft.BackupPolicy {
		return microsoft.BackupPolicy{ID: vaultID + "/backupPolicies/prod", Properties: map[string]any{
			"retentionPolicy": map[string]any{
				"dailySchedule":  map[string]any{"retentionDuration": duration},
				"weeklySchedule": map[string]any{"retentionDuration": map[string]any{"count": float64(13), "durationType": "Weeks"}},
			},
		}}
	}
	days := map[string]any{"count": float64(30), "durationType": "Days"}
	item := func(policyID string) microsoft.BackupProtectedItem {
		return microsoft.BackupProtectedItem{ID: "item", Properties: microsoft.BackupProtectedItemProperties{
			SourceResourceID: "/subscriptions/" + kitSubscriptionID + "/resourceGroups/compute/providers/Microsoft.Compute/virtualMachines/vm-a",
			PolicyID:         policyID,
			ProtectionState:  "Protected",
		}}
	}
	for name, tc := range map[string]struct {
		policies []microsoft.BackupPolicy
		items    []microsoft.BackupProtectedItem
	}{
		"an item with no policy":          {[]microsoft.BackupPolicy{policy(days)}, []microsoft.BackupProtectedItem{item("")}},
		"a policy the vault doesn't list": {nil, []microsoft.BackupProtectedItem{item(vaultID + "/backupPolicies/prod")}},
		"a policy with no retention": {[]microsoft.BackupPolicy{{ID: vaultID + "/backupPolicies/prod", Properties: map[string]any{}}},
			[]microsoft.BackupProtectedItem{item(vaultID + "/backupPolicies/prod")}},
		"a duration with no count": {[]microsoft.BackupPolicy{policy(map[string]any{"durationType": "Days"})},
			[]microsoft.BackupProtectedItem{item(vaultID + "/backupPolicies/prod")}},
		"a duration with no durationType": {[]microsoft.BackupPolicy{policy(map[string]any{"count": float64(30)})},
			[]microsoft.BackupProtectedItem{item(vaultID + "/backupPolicies/prod")}},
	} {
		t.Run(name, func(t *testing.T) {
			arm := fakeARMClient()
			arm.recoveryVaults[kitSubscriptionID] = []microsoft.RecoveryServicesVault{{ID: vaultID, Name: "vault-a"}}
			arm.backupPolicies = map[string][]microsoft.BackupPolicy{vaultID: tc.policies}
			arm.backupProtectedItems = map[string][]microsoft.BackupProtectedItem{vaultID: tc.items}
			rec := &componentsdk.Recorder{}
			cfg := testConfig()
			cfg.ARMClient = arm
			cfg.Recorder = rec
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Azure.Accounts[0].Backup.RetentionDaysMin; got != nil {
				t.Fatalf("retention_days_min = %d, want it left out", *got)
			}
			assertGap(t, rec, azurePath, "/accounts/0/backup/retention_days_min", componentsdk.CodeInvalidResponse)
			assertGap(t, rec, cloudPosturePath, "/accounts/0/backup/retention_days_min", componentsdk.CodeInvalidResponse)
		})
	}
}

// The policies in use are known only from the protected items.
func TestNormalizedBackupRetentionLeftOutWhenProtectedItemsAreUnread(t *testing.T) {
	arm := fakeARMClient()
	arm.backupProtectedItemErrs["/subscriptions/"+kitSubscriptionID+"/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-b"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/backupProtectedItems"}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Azure.Accounts[0].Backup.RetentionDaysMin; got != nil {
		t.Fatalf("retention_days_min = %d, want it left out", *got)
	}
	if backup := result.AzureCloudPosture.Accounts[0].Backup; backup != nil {
		t.Fatalf("expected the normalized backup left out, got %#v", backup)
	}
	assertGap(t, rec, azurePath, "/accounts/0/backup/retention_days_min", componentsdk.CodePermissionDenied)
	assertGap(t, rec, cloudPosturePath, "/accounts/0/backup/retention_days_min", componentsdk.CodePermissionDenied)
}

func TestSliceDGolden(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}

	assertGoldenJSON(t, "../../testdata/golden/slice_d/azure.json", result.Azure)
	assertGoldenJSON(t, "../../testdata/golden/slice_d/cloud-posture.json", result.AzureCloudPosture)
}

func assertPtrInt(t *testing.T, label string, got *int, want int) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("unexpected %s: got %#v want %d", label, got, want)
	}
}

func assertInt(t *testing.T, label string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("unexpected %s: got %d want %d", label, got, want)
	}
}
