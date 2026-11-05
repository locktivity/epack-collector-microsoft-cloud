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

// Resources that are not tied to a region, such as DNS zones, have the
// location global.
// https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/considerations/regions
func TestInventoryRegionsLeaveOutGlobal(t *testing.T) {
	inventory := inventoryPosture([]microsoft.ARMResource{
		{ID: "/subscriptions/s/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/sa", Location: "eastus"},
		{ID: "/subscriptions/s/resourceGroups/b/providers/Microsoft.Compute/virtualMachines/vm", Location: "westus"},
		{ID: "/subscriptions/s/resourceGroups/c/providers/Microsoft.Network/dnszones/contoso.com", Location: "global"},
	})
	assertInt(t, "region count", inventory.RegionsCount, 2)
}

// A nonempty tag counts when another owner or environment tag is empty. The
// answer is the same on every run.
func TestInventoryTagCoverageSkipsEmptyTags(t *testing.T) {
	resources := []microsoft.ARMResource{
		{ID: "/subscriptions/s/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/one", Tags: map[string]string{"Owner": "alice", "ManagedBy": ""}},
		{ID: "/subscriptions/s/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/two", Tags: map[string]string{"env": "", "stage": "prod"}},
		{ID: "/subscriptions/s/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/three", Tags: map[string]string{"environment": "dev", "stage": "prod"}},
		{ID: "/subscriptions/s/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/four"},
	}
	for range 100 {
		inventory := inventoryPosture(resources)
		assertPtrInt(t, "owner tag coverage", inventory.OwnerTagCoveragePct, 25)
		assertPtrInt(t, "environment tag coverage", inventory.EnvironmentTagCoveragePct, 50)
		// An environment tag is read before a stage tag.
		assertPtrInt(t, "production resources", inventory.ProductionResourcesPct, 25)
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
