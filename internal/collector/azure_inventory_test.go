package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestInventoryAudit(t *testing.T) {
	result := collectTestResultAtLevel(t, testConfig(), componentsdk.LevelAudit)
	inventory := result.Azure.Accounts[0].Inventory
	if inventory == nil {
		t.Fatal("expected audit inventory")
	}
	assertInt(t, "resource count", inventory.ResourcesCount, 7)
	assertInt(t, "resource group count", inventory.ResourceGroupsCount, 5)
	assertInt(t, "region count", inventory.RegionsCount, 2)
	assertPtrInt(t, "owner tag coverage", inventory.OwnerTagCoveragePct, 71)
	assertPtrInt(t, "environment tag coverage", inventory.EnvironmentTagCoveragePct, 71)
	assertPtrInt(t, "production resources", inventory.ProductionResourcesPct, 57)
	if len(inventory.TopResourceTypes) != 7 {
		t.Fatalf("expected seven top resource types, got %#v", inventory.TopResourceTypes)
	}
	if inventory.TopResourceTypes[0] != (AzureResourceTypeCount{Type: "Microsoft.Compute/virtualMachines", Count: 1}) {
		t.Fatalf("unexpected top resource type ordering: %#v", inventory.TopResourceTypes)
	}
}

func TestInventoryTrustOmitted(t *testing.T) {
	result := collectTestResultAtLevel(t, testConfig(), componentsdk.LevelTrust)
	if result.Azure.Accounts[0].Inventory != nil {
		t.Fatalf("expected inventory to be omitted at trust level, got %#v", result.Azure.Accounts[0].Inventory)
	}
}

func TestInventoryZeroResources(t *testing.T) {
	arm := fakeARMClient()
	arm.resources["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	result := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit)
	inventory := result.Azure.Accounts[0].Inventory
	if inventory == nil {
		t.Fatal("expected empty inventory")
	}
	assertInt(t, "resource count", inventory.ResourcesCount, 0)
	assertInt(t, "resource group count", inventory.ResourceGroupsCount, 0)
	assertInt(t, "region count", inventory.RegionsCount, 0)
	if inventory.OwnerTagCoveragePct != nil || inventory.EnvironmentTagCoveragePct != nil || inventory.ProductionResourcesPct != nil {
		t.Fatalf("expected null inventory percentages, got %#v", inventory)
	}
	if len(inventory.TopResourceTypes) != 0 {
		t.Fatalf("expected no top resource types, got %#v", inventory.TopResourceTypes)
	}
}

func TestInventoryUnavailable(t *testing.T) {
	arm := fakeARMClient()
	arm.resourceErrs["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/resources"}
	cfg := testConfig()
	cfg.ARMClient = arm

	result := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit)
	if result.Azure.Accounts[0].Inventory != nil {
		t.Fatalf("expected inventory omission on unavailable surface, got %#v", result.Azure.Accounts[0].Inventory)
	}
	if len(result.Azure.Diagnostics.Warnings) == 0 {
		t.Fatal("expected inventory warning")
	}
}

func TestSliceHGolden(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	result := collectTestResultAtLevel(t, cfg, componentsdk.LevelAudit)

	assertGoldenJSON(t, "../../testdata/golden/slice_h/azure.json", result.Azure)
}

func collectTestResultAtLevel(t *testing.T, cfg Config, level componentsdk.Level) *Result {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatal(err)
	}
	if result.Azure == nil {
		t.Fatal("expected Azure artifact")
	}
	return result
}
