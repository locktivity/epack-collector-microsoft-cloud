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
	assertInt(t, "network security group count", network.NetworkSecurityGroupsCount, 2)
	assertInt(t, "public IP address count", network.PublicIPAddressesCount, 1)
	assertPtrInt(t, "SSH open to world", network.SSHOpenToWorldPct, 50)
	assertPtrInt(t, "RDP open to world", network.RDPOpenToWorldPct, 0)
}

func TestNetworkExposureZeroDenominator(t *testing.T) {
	arm := fakeARMClient()
	arm.networkSecurityGroups["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	network := artifact.Accounts[0].Network
	if network == nil || network.NetworkSecurityGroupsCount != 0 {
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
	assertInt(t, "monitored resource count", logging.MonitoredResourcesCount, 9)
	assertPtrInt(t, "diagnostic settings coverage", logging.DiagnosticSettingsCoveragePct, 56)
	assertPtrInt(t, "resources without diagnostics", logging.ResourcesWithoutDiagnosticsCount, 4)
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
	assertPtrInt(t, "normalized SSH exposure", network.SSHOpenToWorldPct, 50)
	assertPtrInt(t, "normalized RDP exposure", network.RDPOpenToWorldPct, 0)
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
