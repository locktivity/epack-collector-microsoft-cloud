package collector

import (
	"context"
	"net/http"
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
	assertInt(t, "database count", sql.DatabasesCount, 2)
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
	assertPtrInt(t, "normalized storage encryption", account.Storage.EncryptionPct, 50)
	assertPtrInt(t, "normalized storage public access", account.Storage.PublicAccessBlockedPct, 50)
	if account.Backup == nil {
		t.Fatal("expected normalized backup")
	}
	assertPtrInt(t, "normalized backup retention", account.Backup.RetentionDaysMin, 30)
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
