//go:build e2e
// +build e2e

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

type e2eCacheEntry struct {
	result *Result
	err    error
}

var (
	e2eCacheMu sync.Mutex
	e2eCache   = map[componentsdk.Level]e2eCacheEntry{}
)

// E2E tests run against a real Microsoft Entra tenant and Azure subscription.
//
// Run with:
//
//	MICROSOFT_CLOUD_E2E_RUN=true go test -tags=e2e -v ./internal/collector/...
//
// Required environment variables:
//
//	MICROSOFT_CLOUD_E2E_RUN=true
//	MICROSOFT_CLOUD_E2E_TENANT_ID=00000000-0000-0000-0000-000000000000
//	MICROSOFT_CLOUD_E2E_CLIENT_ID=11111111-1111-1111-1111-111111111111
//	MICROSOFT_CLOUD_E2E_SUBSCRIPTION_IDS=22222222-2222-2222-2222-222222222222
//
// Authentication:
//
//	Client secret:
//	  MICROSOFT_CLOUD_E2E_AUTH_MODE=client_secret
//	  MICROSOFT_CLOUD_E2E_CLIENT_SECRET=<secret>
//
//	GitHub Actions OIDC:
//	  MICROSOFT_CLOUD_E2E_AUTH_MODE=oidc
//	  ACTIONS_ID_TOKEN_REQUEST_URL=<github-provided-url>
//	  ACTIONS_ID_TOKEN_REQUEST_TOKEN=<github-provided-token>
//
// Optional environment variables:
//
//	MICROSOFT_CLOUD_E2E_LEVEL=trust|audit|internal
//	AZURE_CLIENT_SECRET=<fallback secret for client_secret mode>

func TestE2E_RealMicrosoftCloudCollection(t *testing.T) {
	level := e2eLevel()
	cfg := getE2EConfig(t)
	result := collectE2E(t, level)

	if result.Entra == nil {
		t.Fatal("expected Entra artifact")
	}
	if result.Entra.SchemaVersion != SchemaVersion {
		t.Errorf("entra.schema_version = %q, want %q", result.Entra.SchemaVersion, SchemaVersion)
	}
	if result.Entra.CollectedAtLevel != string(level) {
		t.Errorf("entra.collected_at_level = %q, want %q", result.Entra.CollectedAtLevel, level)
	}
	assertRFC3339(t, "entra.collected_at", result.Entra.CollectedAt)
	if !strings.EqualFold(result.Entra.TenantID, cfg.TenantID) {
		t.Errorf("entra.tenant_id = %q, want %q", result.Entra.TenantID, cfg.TenantID)
	}
	if strings.TrimSpace(result.Entra.OrgDomain) == "" {
		t.Error("entra.org_domain should not be empty")
	}
	if result.Entra.Users.TotalCount < 0 {
		t.Errorf("users.total_count should be nonnegative, got %d", result.Entra.Users.TotalCount)
	}
	if result.Entra.Users.EnabledMemberUsersCount < 0 {
		t.Errorf("users.enabled_member_users_count should be nonnegative, got %d", result.Entra.Users.EnabledMemberUsersCount)
	}
	if result.Entra.Posture.DenominatorEnabledMemberUsers != result.Entra.Users.EnabledMemberUsersCount {
		t.Errorf("posture.denominator_enabled_member_users = %d, want users.enabled_member_users_count %d", result.Entra.Posture.DenominatorEnabledMemberUsers, result.Entra.Users.EnabledMemberUsersCount)
	}

	assertEntraPercentages(t, result.Entra)
	if result.EntraIDPPosture == nil {
		t.Error("expected normalized IDP posture artifact")
	}

	if result.Azure == nil {
		t.Fatal("expected Azure artifact")
	}
	if result.Azure.SchemaVersion != SchemaVersion {
		t.Errorf("azure.schema_version = %q, want %q", result.Azure.SchemaVersion, SchemaVersion)
	}
	if result.Azure.CollectedAtLevel != string(level) {
		t.Errorf("azure.collected_at_level = %q, want %q", result.Azure.CollectedAtLevel, level)
	}
	assertRFC3339(t, "azure.collected_at", result.Azure.CollectedAt)
	if len(result.Azure.Accounts) == 0 {
		t.Fatal("expected at least one Azure account")
	}

	subscriptions := configuredSubscriptions(cfg.SubscriptionIDs)
	for i, account := range result.Azure.Accounts {
		if _, ok := subscriptions[strings.ToLower(account.AccountID)]; !ok {
			t.Errorf("azure.accounts[%d].account_id = %q, not in configured subscription_ids", i, account.AccountID)
		}
		assertAzurePercentages(t, i, account)
	}
	if result.AzureCloudPosture == nil {
		t.Error("expected normalized cloud posture artifact")
	}

	data, _ := json.MarshalIndent(result.Artifacts(), "", "  ")
	t.Logf("collection complete at level=%s artifacts=%d\n%s", level, len(result.Artifacts()), string(data))
}

func TestE2E_OutputValidJSON(t *testing.T) {
	result := collectE2E(t, e2eLevel())

	artifacts := result.Artifacts()
	if len(artifacts) < 4 {
		t.Fatalf("expected four artifacts, got %d", len(artifacts))
	}

	seenPaths := map[string]bool{}
	for _, artifact := range artifacts {
		if strings.TrimSpace(artifact.Path) == "" {
			t.Error("artifact path should not be empty")
		}
		seenPaths[artifact.Path] = true

		data, err := json.Marshal(artifact.Data)
		if err != nil {
			t.Fatalf("failed to marshal %s: %v", artifact.Path, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s is not valid JSON: %v", artifact.Path, err)
		}
		for _, field := range []string{"schema_version", "collected_at"} {
			if _, ok := decoded[field]; !ok {
				t.Errorf("%s missing required top-level field %q", artifact.Path, field)
			}
		}
	}

	for _, path := range []string{
		"artifacts/microsoft-cloud.entra.json",
		"artifacts/microsoft-cloud.idp-posture.json",
		"artifacts/microsoft-cloud.azure.json",
		"artifacts/microsoft-cloud.cloud-posture.json",
	} {
		if !seenPaths[path] {
			t.Errorf("missing artifact path %s", path)
		}
	}
}

func TestE2E_LevelSpecificArtifacts(t *testing.T) {
	level := e2eLevel()
	result := collectE2E(t, level)

	if level == componentsdk.LevelTrust {
		if result.Entra.DirectoryActivity != nil {
			t.Fatalf("directory_activity should be omitted at trust level, got %#v", result.Entra.DirectoryActivity)
		}
		if result.Entra.SignInMonitoring != nil {
			t.Fatalf("sign_in_monitoring should be omitted at trust level, got %#v", result.Entra.SignInMonitoring)
		}
		for i, account := range result.Azure.Accounts {
			if account.Inventory != nil {
				t.Fatalf("azure.accounts[%d].inventory should be omitted at trust level, got %#v", i, account.Inventory)
			}
		}
	}
}

func TestE2E_NeverEmitsForbiddenData(t *testing.T) {
	result := collectE2E(t, componentsdk.LevelInternal)

	data, err := json.Marshal(result.Artifacts())
	if err != nil {
		t.Fatalf("failed to marshal artifacts: %v", err)
	}
	raw := string(data)
	lowerRaw := strings.ToLower(raw)

	for _, secret := range []string{
		os.Getenv("MICROSOFT_CLOUD_E2E_CLIENT_SECRET"),
		os.Getenv("AZURE_CLIENT_SECRET"),
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
	} {
		secret = strings.TrimSpace(secret)
		if len(secret) >= 8 && strings.Contains(raw, secret) {
			t.Errorf("artifact output contains a configured secret value")
		}
	}

	for _, forbidden := range []string{
		`"userPrincipalName"`,
		`"user_principal_name"`,
		`"mail"`,
		`"email"`,
		`"displayName"`,
		`"display_name"`,
		`"ipAddress"`,
		`"ip_address"`,
		`"deviceDetail"`,
		`"resourceDisplayName"`,
		`"appDisplayName"`,
		`"appliedConditionalAccessPolicies"`,
		`"keyId"`,
		`"clientSecret"`,
		`"access_token"`,
		`"refresh_token"`,
	} {
		if strings.Contains(lowerRaw, strings.ToLower(forbidden)) {
			t.Errorf("artifact output contains forbidden key %s", forbidden)
		}
	}
}

func e2eLevel() componentsdk.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MICROSOFT_CLOUD_E2E_LEVEL"))) {
	case "audit":
		return componentsdk.LevelAudit
	case "internal":
		return componentsdk.LevelInternal
	default:
		return componentsdk.LevelTrust
	}
}

func getE2EConfig(t *testing.T) Config {
	t.Helper()

	if strings.ToLower(strings.TrimSpace(os.Getenv("MICROSOFT_CLOUD_E2E_RUN"))) != "true" {
		t.Skip("MICROSOFT_CLOUD_E2E_RUN=true not set, skipping e2e test")
	}

	cfg := Config{
		TenantID:         requiredE2EEnv(t, "MICROSOFT_CLOUD_E2E_TENANT_ID"),
		ClientID:         requiredE2EEnv(t, "MICROSOFT_CLOUD_E2E_CLIENT_ID"),
		AuthMode:         strings.ToLower(strings.TrimSpace(os.Getenv("MICROSOFT_CLOUD_E2E_AUTH_MODE"))),
		SubscriptionIDs:  splitCSV(requiredE2EEnv(t, "MICROSOFT_CLOUD_E2E_SUBSCRIPTION_IDS")),
		ClientSecret:     strings.TrimSpace(os.Getenv("MICROSOFT_CLOUD_E2E_CLIENT_SECRET")),
		OIDCRequestURL:   strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")),
		OIDCRequestToken: strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
		AzureEnvironment: strings.TrimSpace(os.Getenv("MICROSOFT_CLOUD_E2E_AZURE_ENVIRONMENT")),
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = "client_secret"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET"))
	}

	switch cfg.AuthMode {
	case "client_secret":
		if cfg.ClientSecret == "" {
			t.Fatal("client_secret e2e mode requires MICROSOFT_CLOUD_E2E_CLIENT_SECRET or AZURE_CLIENT_SECRET")
		}
	case "oidc":
		if cfg.OIDCRequestURL == "" || cfg.OIDCRequestToken == "" {
			t.Fatal("oidc e2e mode requires ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		}
	default:
		t.Fatalf("MICROSOFT_CLOUD_E2E_AUTH_MODE must be client_secret or oidc, got %q", cfg.AuthMode)
	}

	return cfg
}

func collectE2E(t *testing.T, level componentsdk.Level) *Result {
	t.Helper()

	cfg := getE2EConfig(t)
	e2eCacheMu.Lock()
	entry, ok := e2eCache[level]
	e2eCacheMu.Unlock()
	if ok {
		if entry.err != nil {
			t.Fatalf("cached Collect(%s) error: %v", level, entry.err)
		}
		return entry.result
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	result, err := c.Collect(ctx, level)
	e2eCacheMu.Lock()
	e2eCache[level] = e2eCacheEntry{result: result, err: err}
	e2eCacheMu.Unlock()

	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return result
}

func requiredE2EEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required when MICROSOFT_CLOUD_E2E_RUN=true", name)
	}
	return value
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func configuredSubscriptions(subscriptionIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(subscriptionIDs))
	for _, subscriptionID := range subscriptionIDs {
		out[strings.ToLower(subscriptionID)] = struct{}{}
	}
	return out
}

func assertRFC3339(t *testing.T, name, value string) {
	t.Helper()
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		t.Errorf("%s %q is not RFC3339: %v", name, value, err)
	}
}

func assertEntraPercentages(t *testing.T, artifact *EntraArtifact) {
	t.Helper()
	assertOptionalPercent(t, "posture.mfa_coverage", artifact.Posture.MFACoverage)
	assertOptionalPercent(t, "posture.mfa_phishing_resistant", artifact.Posture.MFAPhishingResistant)
	assertOptionalPercent(t, "posture.mfa_weak_method_only", artifact.Posture.MFAWeakMethodOnly)
	assertOptionalPercent(t, "posture.sspr_registered", artifact.Posture.SSPRRegistered)
	assertOptionalPercent(t, "posture.sso_coverage", artifact.Posture.SSOCoverage)
	assertOptionalPercent(t, "users.guest_pct", artifact.Users.GuestPct)
	assertOptionalPercent(t, "users.disabled_pct", artifact.Users.DisabledPct)
	assertOptionalPercent(t, "users.inactive_pct", artifact.Users.InactivePct)
	assertOptionalPercent(t, "users.inactive_guest_pct", artifact.Users.InactiveGuestPct)
	if artifact.Policy != nil {
		assertOptionalPercent(t, "policy.mfa_required_coverage_pct", artifact.Policy.MFARequiredCoveragePct)
	}
	if artifact.PrivilegedAccess != nil {
		assertOptionalPercent(t, "privileged_access.privileged_mfa_coverage_pct", artifact.PrivilegedAccess.PrivilegedMFACoveragePct)
		assertOptionalPercent(t, "privileged_access.privileged_phishing_resistant_pct", artifact.PrivilegedAccess.PrivilegedPhishingResistantPct)
		assertOptionalPercent(t, "privileged_access.pim_eligible_pct", artifact.PrivilegedAccess.PIMEligiblePct)
	}
	if artifact.Apps != nil {
		assertOptionalPercent(t, "apps.assignment_required_pct", artifact.Apps.AssignmentRequiredPct)
		assertOptionalPercent(t, "apps.password_credentials_pct", artifact.Apps.PasswordCredentialsPct)
	}
	if artifact.SecureScore != nil {
		assertOptionalPercent(t, "secure_score.identity_pct", artifact.SecureScore.IdentityPct)
	}
}

func assertAzurePercentages(t *testing.T, index int, account AzureAccount) {
	t.Helper()
	prefix := "azure.accounts[" + strconv.Itoa(index) + "]."
	if account.Defender != nil {
		assertOptionalPercent(t, prefix+"defender.secure_score_pct", account.Defender.SecureScorePct)
		assertOptionalPercent(t, prefix+"defender.unpatched_pct", account.Defender.UnpatchedPct)
	}
	if account.Policy != nil {
		assertOptionalPercent(t, prefix+"policy.compliant_pct", account.Policy.CompliantPct)
	}
	if account.Storage != nil {
		assertOptionalPercent(t, prefix+"storage.https_only_pct", account.Storage.HTTPSOnlyPct)
		assertOptionalPercent(t, prefix+"storage.min_tls12_pct", account.Storage.MinTLS12Pct)
		assertOptionalPercent(t, prefix+"storage.encryption_cmk_pct", account.Storage.EncryptionCMKPct)
		assertOptionalPercent(t, prefix+"storage.infrastructure_encryption_pct", account.Storage.InfrastructureEncryptionPct)
		assertOptionalPercent(t, prefix+"storage.public_access_blocked_pct", account.Storage.PublicAccessBlockedPct)
	}
	if account.KeyVault != nil {
		assertOptionalPercent(t, prefix+"keyvault.purge_protection_pct", account.KeyVault.PurgeProtectionPct)
		assertOptionalPercent(t, prefix+"keyvault.rbac_authorization_pct", account.KeyVault.RBACAuthorizationPct)
	}
	if account.SQL != nil {
		assertOptionalPercent(t, prefix+"sql.tde_enabled_pct", account.SQL.TDEEnabledPct)
		assertOptionalPercent(t, prefix+"sql.min_tls12_pct", account.SQL.MinTLS12Pct)
		assertOptionalPercent(t, prefix+"sql.public_access_disabled_pct", account.SQL.PublicAccessDisabledPct)
	}
	if account.Compute != nil {
		assertOptionalPercent(t, prefix+"compute.disk_encryption_pct", account.Compute.DiskEncryptionPct)
		assertOptionalPercent(t, prefix+"compute.public_ip_pct", account.Compute.PublicIPPct)
	}
	if account.Backup != nil {
		assertOptionalPercent(t, prefix+"backup.protected_resource_pct", account.Backup.ProtectedResourcePct)
		assertOptionalPercent(t, prefix+"backup.vault_soft_delete_pct", account.Backup.VaultSoftDeletePct)
		assertOptionalPercent(t, prefix+"backup.vault_immutability_pct", account.Backup.VaultImmutabilityPct)
	}
	if account.Network != nil {
		assertOptionalPercent(t, prefix+"network.ssh_open_to_world_pct", account.Network.SSHOpenToWorldPct)
		assertOptionalPercent(t, prefix+"network.rdp_open_to_world_pct", account.Network.RDPOpenToWorldPct)
	}
	if account.Logging != nil {
		assertOptionalPercent(t, prefix+"logging.diagnostic_settings_coverage_pct", account.Logging.DiagnosticSettingsCoveragePct)
	}
	if account.Inventory != nil {
		assertOptionalPercent(t, prefix+"inventory.owner_tag_coverage_pct", account.Inventory.OwnerTagCoveragePct)
		assertOptionalPercent(t, prefix+"inventory.environment_tag_coverage_pct", account.Inventory.EnvironmentTagCoveragePct)
		assertOptionalPercent(t, prefix+"inventory.production_resources_pct", account.Inventory.ProductionResourcesPct)
	}
}

func assertOptionalPercent(t *testing.T, name string, value *int) {
	t.Helper()
	if value == nil {
		return
	}
	if *value < 0 || *value > 100 {
		t.Errorf("%s should be in [0,100], got %d", name, *value)
	}
}
