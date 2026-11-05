package collector

import (
	"context"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestNormalizedCloudSliceC(t *testing.T) {
	c, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	cloud := result.AzureCloudPosture
	if cloud == nil {
		t.Fatal("expected normalized cloud posture")
	}
	if cloud.Provider != "azure" {
		t.Fatalf("unexpected provider: %s", cloud.Provider)
	}
	if len(cloud.Accounts) != 1 || cloud.Accounts[0].AccountID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("unexpected accounts: %#v", cloud.Accounts)
	}
	if cloud.Accounts[0].Storage == nil || cloud.Accounts[0].Network == nil {
		t.Fatalf("expected storage and network posture: %#v", cloud.Accounts[0])
	}
}
