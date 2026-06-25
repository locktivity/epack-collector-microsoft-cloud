package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestNormalizedCloudSliceC(t *testing.T) {
	c, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
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
	if cloud.Accounts[0].IAM == nil || cloud.Accounts[0].IAM.MFACoveragePct == nil || *cloud.Accounts[0].IAM.MFACoveragePct != 50 {
		t.Fatalf("unexpected IAM MFA coverage: %#v", cloud.Accounts[0].IAM)
	}
	if cloud.Accounts[0].IAM.RootMFAEnabled == nil || !*cloud.Accounts[0].IAM.RootMFAEnabled {
		t.Fatalf("unexpected root MFA mapping: %#v", cloud.Accounts[0].IAM)
	}
	if cloud.Accounts[0].IAM.RootAccessProtected == nil || !*cloud.Accounts[0].IAM.RootAccessProtected {
		t.Fatalf("unexpected root access protection mapping: %#v", cloud.Accounts[0].IAM)
	}
}

func TestNormalizedCloudOmitsRootMFAWithoutMFAReport(t *testing.T) {
	graph := fakeGraphClient()
	graph.regErr = errForbidden()
	cfg := testConfig()
	cfg.GraphClient = graph

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if result.AzureCloudPosture.Accounts[0].IAM != nil && result.AzureCloudPosture.Accounts[0].IAM.RootMFAEnabled != nil {
		t.Fatalf("expected root MFA omitted without MFA report, got %#v", result.AzureCloudPosture.Accounts[0].IAM)
	}
	if result.AzureCloudPosture.Accounts[0].IAM != nil && result.AzureCloudPosture.Accounts[0].IAM.RootAccessProtected != nil {
		t.Fatalf("expected root access protection omitted without MFA report, got %#v", result.AzureCloudPosture.Accounts[0].IAM)
	}
}

func errForbidden() error {
	return &microsoft.APIError{Service: "graph", StatusCode: http.StatusForbidden, Route: "/reports/authenticationMethods/userRegistrationDetails"}
}
