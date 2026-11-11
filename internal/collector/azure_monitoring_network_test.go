package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestNetworkExposure(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	network := artifact.Accounts[0].Network
	if network == nil {
		t.Fatal("expected network posture")
	}
	assertPtrInt(t, "network security group count", network.NetworkSecurityGroupsCount, 2)
	assertPtrInt(t, "public IP address count", network.PublicIPAddressesCount, 1)
	assertPtrInt(t, "SSH open to world", network.SSHOpenToWorldPct, 50)
	assertPtrInt(t, "RDP open to world", network.RDPOpenToWorldPct, 0)
}

// Azure applies a group's rules in priority order, lowest first, and the
// first rule that matches decides. A deny rule only closes the port when its
// source is any address.
func TestNetworkExposureAppliesRulesInPriorityOrder(t *testing.T) {
	rule := func(access, source string, priority int) microsoft.SecurityRule {
		return microsoft.SecurityRule{Properties: microsoft.SecurityRuleProperties{
			Priority: priority, Access: access, Direction: "Inbound", Protocol: "Tcp",
			SourceAddressPrefix: source, DestinationPortRange: "22",
		}}
	}
	cases := []struct {
		name  string
		rules []microsoft.SecurityRule
		want  bool
	}{
		{"allow from anywhere", []microsoft.SecurityRule{rule("Allow", "*", 200)}, true},
		{"deny from anywhere first", []microsoft.SecurityRule{rule("Allow", "*", 200), rule("Deny", "Internet", 100)}, false},
		{"deny from anywhere after", []microsoft.SecurityRule{rule("Allow", "Internet", 100), rule("Deny", "*", 200)}, true},
		{"deny from one network first", []microsoft.SecurityRule{rule("Allow", "*", 200), rule("Deny", "203.0.113.0/24", 100)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsg := microsoft.NetworkSecurityGroup{Properties: microsoft.NetworkSecurityGroupProperties{SecurityRules: tc.rules}}
			if got := nsgOpenToWorld(nsg, 22); got != tc.want {
				t.Fatalf("open to SSH = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNetworkExposureZeroDenominator(t *testing.T) {
	arm := fakeARMClient()
	arm.networkSecurityGroups["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	network := artifact.Accounts[0].Network
	if network == nil || network.NetworkSecurityGroupsCount == nil || *network.NetworkSecurityGroupsCount != 0 {
		t.Fatalf("unexpected network posture: %#v", network)
	}
	if network.SSHOpenToWorldPct != nil || network.RDPOpenToWorldPct != nil {
		t.Fatalf("expected null network percentages, got %#v", network)
	}
}

func TestLoggingCoverage(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	logging := artifact.Accounts[0].Logging
	if logging == nil {
		t.Fatal("expected logging posture")
	}
	if logging.SubscriptionDiagnosticSettingsEnabled == nil || !*logging.SubscriptionDiagnosticSettingsEnabled {
		t.Fatalf("unexpected subscription diagnostic settings: %#v", logging.SubscriptionDiagnosticSettingsEnabled)
	}
	if logging.ActivityLogAdministrativeExported == nil || !*logging.ActivityLogAdministrativeExported {
		t.Fatalf("unexpected administrative activity log export: %#v", logging.ActivityLogAdministrativeExported)
	}
	assertPtrInt(t, "monitored resource count", logging.MonitoredResourcesCount, 9)
	assertPtrInt(t, "diagnostic settings coverage", logging.DiagnosticSettingsCoveragePct, 56)
	assertPtrInt(t, "resources without diagnostics", logging.ResourcesWithoutDiagnosticsCount, 4)
}

// A storage account's own diagnostic setting carries only metrics. Its logs
// are on its blob, file, queue and table services.
// https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/logs-index
func TestLoggingCoverageReadsStorageServiceSettings(t *testing.T) {
	arm := fakeARMClient()
	storageA := "/subscriptions/" + kitSubscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea"
	storageB := "/subscriptions/" + kitSubscriptionID + "/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storageb"
	delete(arm.diagnosticSettings, storageA)
	arm.diagnosticSettings[storageA+"/blobServices/default"] = []microsoft.DiagnosticSetting{storageLogsSetting()}
	arm.diagnosticSettings[storageB+"/tableServices/default"] = []microsoft.DiagnosticSetting{storageLogsSetting()}
	cfg := testConfig()
	cfg.ARMClient = arm

	logging := collectTestAzureArtifact(t, cfg).Accounts[0].Logging
	assertPtrInt(t, "monitored resource count", logging.MonitoredResourcesCount, 9)
	assertPtrInt(t, "diagnostic settings coverage", logging.DiagnosticSettingsCoveragePct, 67)
	assertPtrInt(t, "resources without diagnostics", logging.ResourcesWithoutDiagnosticsCount, 3)
}

// A SQL server has no diagnostic settings of its own. Its audit logs go
// through a diagnostic setting on its master database.
func TestLoggingCoverageMeasuresSQLServersByTheirMasterDatabase(t *testing.T) {
	serverID := "/subscriptions/" + kitSubscriptionID + "/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a"
	cases := []struct {
		name    string
		setting string
		want    int
	}{
		{"master database logged", serverID + "/databases/master", 4},
		{"setting on the server only", serverID, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := fakeARMClient()
			delete(arm.diagnosticSettings, serverID+"/databases/master")
			arm.diagnosticSettings[tc.setting] = []microsoft.DiagnosticSetting{{
				Properties: microsoft.DiagnosticSettingProperties{
					WorkspaceID: "/subscriptions/" + kitSubscriptionID + "/resourceGroups/monitor/providers/Microsoft.OperationalInsights/workspaces/law-a",
					Logs:        []microsoft.DiagnosticLogSetting{{Category: "SQLSecurityAuditEvents", Enabled: true}},
				},
			}}
			cfg := testConfig()
			cfg.ARMClient = arm

			logging := collectTestAzureArtifact(t, cfg).Accounts[0].Logging
			assertPtrInt(t, "monitored resource count", logging.MonitoredResourcesCount, 9)
			assertPtrInt(t, "resources without diagnostics", logging.ResourcesWithoutDiagnosticsCount, tc.want)
		})
	}
}

func storageLogsSetting() microsoft.DiagnosticSetting {
	return microsoft.DiagnosticSetting{
		Properties: microsoft.DiagnosticSettingProperties{
			WorkspaceID: "/subscriptions/" + kitSubscriptionID + "/resourceGroups/monitor/providers/Microsoft.OperationalInsights/workspaces/law-a",
			Logs: []microsoft.DiagnosticLogSetting{
				{Category: "StorageRead", Enabled: true},
				{Category: "StorageWrite", Enabled: true},
				{Category: "StorageDelete", Enabled: true},
			},
		},
	}
}

func TestLoggingCoverageUnavailable(t *testing.T) {
	arm := fakeARMClient()
	arm.diagnosticSettingErrs["/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/diagnosticSettings"}
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	logging := artifact.Accounts[0].Logging
	if logging == nil {
		t.Fatal("expected logging posture")
	}
	if logging.DiagnosticSettingsCoveragePct != nil || logging.ResourcesWithoutDiagnosticsCount != nil {
		t.Fatalf("expected unknown resource diagnostic settings coverage, got %#v", logging)
	}
	if len(artifact.Diagnostics.Warnings) == 0 {
		t.Fatal("expected diagnostic settings warning")
	}
}

func TestActivityLogAdministrativeExported(t *testing.T) {
	administrative := microsoft.DiagnosticLogSetting{Category: "Administrative", Enabled: true}
	cases := []struct {
		name     string
		settings []microsoft.DiagnosticSetting
		want     bool
	}{
		{name: "no settings"},
		{name: "administrative without destination", settings: []microsoft.DiagnosticSetting{{Properties: microsoft.DiagnosticSettingProperties{Logs: []microsoft.DiagnosticLogSetting{administrative}}}}},
		{name: "administrative disabled", settings: []microsoft.DiagnosticSetting{{Properties: microsoft.DiagnosticSettingProperties{WorkspaceID: "law-a", Logs: []microsoft.DiagnosticLogSetting{{Category: "Administrative"}}}}}},
		{name: "health category only", settings: []microsoft.DiagnosticSetting{{Properties: microsoft.DiagnosticSettingProperties{WorkspaceID: "law-a", Logs: []microsoft.DiagnosticLogSetting{{Category: "ServiceHealth", Enabled: true}}}}}},
		{name: "administrative exported", settings: []microsoft.DiagnosticSetting{{Properties: microsoft.DiagnosticSettingProperties{StorageAccountID: "storage-a", Logs: []microsoft.DiagnosticLogSetting{{Category: "ServiceHealth", Enabled: true}, administrative}}}}, want: true},
		{name: "all logs group exported", settings: []microsoft.DiagnosticSetting{{Properties: microsoft.DiagnosticSettingProperties{EventHubAuthorizationRuleID: "hub-a", Logs: []microsoft.DiagnosticLogSetting{{CategoryGroup: "allLogs", Enabled: true}}}}}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := activityLogAdministrativeExported(tc.settings); got != tc.want {
				t.Fatalf("activityLogAdministrativeExported = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoggingHealthOnlyExportIsNotAnAuditTrail(t *testing.T) {
	arm := fakeARMClient()
	arm.diagnosticSettings["/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = []microsoft.DiagnosticSetting{{
		Properties: microsoft.DiagnosticSettingProperties{
			WorkspaceID: "law-a",
			Logs:        []microsoft.DiagnosticLogSetting{{Category: "ServiceHealth", Enabled: true}},
		},
	}}
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
	logging := result.Azure.Accounts[0].Logging
	if logging.SubscriptionDiagnosticSettingsEnabled == nil || !*logging.SubscriptionDiagnosticSettingsEnabled {
		t.Fatalf("expected subscription diagnostic settings enabled, got %#v", logging.SubscriptionDiagnosticSettingsEnabled)
	}
	if logging.ActivityLogAdministrativeExported == nil || *logging.ActivityLogAdministrativeExported {
		t.Fatalf("expected administrative export false, got %#v", logging.ActivityLogAdministrativeExported)
	}
	normalized := result.AzureCloudPosture.Accounts[0].Logging
	if normalized == nil || normalized.CloudTrailEnabled == nil || *normalized.CloudTrailEnabled || normalized.CloudTrailMultiregion == nil || *normalized.CloudTrailMultiregion {
		t.Fatalf("expected normalized logging false, got %#v", normalized)
	}
}

func TestNormalizedCloudLoggingOmittedWhenSubscriptionSettingsUnavailable(t *testing.T) {
	arm := fakeARMClient()
	arm.diagnosticSettingErrs["/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/diagnosticSettings"}
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
	logging := result.Azure.Accounts[0].Logging
	if logging == nil || logging.SubscriptionDiagnosticSettingsEnabled != nil || logging.ActivityLogAdministrativeExported != nil {
		t.Fatalf("expected unknown subscription logging, got %#v", logging)
	}
	if result.AzureCloudPosture.Accounts[0].Logging != nil {
		t.Fatalf("expected normalized logging omitted, got %#v", result.AzureCloudPosture.Accounts[0].Logging)
	}
	if len(result.Azure.Diagnostics.Warnings) == 0 {
		t.Fatal("expected subscription diagnostic settings warning")
	}
}

func TestNormalizedCloudSliceF(t *testing.T) {
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
	network := result.AzureCloudPosture.Accounts[0].Network
	if network == nil {
		t.Fatal("expected normalized network posture")
	}
	assertPtrInt(t, "normalized SSH exposure", network.SSHOpenToWorldPct.Value, 50)
	assertPtrInt(t, "normalized RDP exposure", network.RDPOpenToWorldPct.Value, 0)
	logging := result.AzureCloudPosture.Accounts[0].Logging
	if logging == nil || logging.CloudTrailEnabled == nil || !*logging.CloudTrailEnabled || logging.CloudTrailMultiregion == nil || !*logging.CloudTrailMultiregion {
		t.Fatalf("expected normalized logging enabled across regions, got %#v", logging)
	}
}

func TestSliceFGolden(t *testing.T) {
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

	assertGoldenJSON(t, "../../testdata/golden/slice_f/azure.json", result.Azure)
	assertGoldenJSON(t, "../../testdata/golden/slice_f/cloud-posture.json", result.AzureCloudPosture)
}
