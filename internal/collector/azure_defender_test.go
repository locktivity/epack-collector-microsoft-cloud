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

func TestSubscriptionProbe(t *testing.T) {
	arm := fakeARMClient()
	arm.subscriptions["bbbbbbbb-1111-2222-3333-cccccccccccc"] = &microsoft.Subscription{SubscriptionID: "bbbbbbbb-1111-2222-3333-cccccccccccc", State: "Enabled"}
	arm.secureScores["bbbbbbbb-1111-2222-3333-cccccccccccc"] = &microsoft.ARMSecureScore{Properties: microsoft.ARMSecureScoreProperties{Score: microsoft.ARMScore{Current: 9, Max: 10}}}
	arm.roleAssignments["bbbbbbbb-1111-2222-3333-cccccccccccc"] = nil
	arm.subscriptionErrs["cccccccc-1111-2222-3333-dddddddddddd"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/subscriptions/cccccccc-1111-2222-3333-dddddddddddd"}

	cfg := testConfig()
	cfg.SubscriptionIDs = []string{
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"bbbbbbbb-1111-2222-3333-cccccccccccc",
		"cccccccc-1111-2222-3333-dddddddddddd",
	}
	cfg.ARMClient = arm

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if result.Azure == nil || len(result.Azure.Accounts) != 2 {
		t.Fatalf("expected two successful Azure accounts, got %#v", result.Azure)
	}
	if len(result.Azure.Diagnostics.SubscriptionErrors) != 1 {
		t.Fatalf("expected one subscription error, got %#v", result.Azure.Diagnostics.SubscriptionErrors)
	}
}

func TestSubscriptionProbeErrorsAreEmittedWithoutAccounts(t *testing.T) {
	subscriptionID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	arm := fakeARMClient()
	arm.subscriptionErrs[subscriptionID] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/subscriptions/" + subscriptionID, Code: "AuthorizationFailed", Message: "denied"}
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
	if result.Azure == nil {
		t.Fatal("expected Azure artifact with subscription diagnostics")
	}
	if len(result.Azure.Accounts) != 0 {
		t.Fatalf("expected no Azure accounts, got %#v", result.Azure.Accounts)
	}
	if len(result.Azure.Diagnostics.SubscriptionErrors) != 1 {
		t.Fatalf("expected Azure subscription error, got %#v", result.Azure.Diagnostics.SubscriptionErrors)
	}
	if len(result.Entra.Diagnostics.SubscriptionErrors) != 1 {
		t.Fatalf("expected final diagnostics on Entra artifact, got %#v", result.Entra.Diagnostics.SubscriptionErrors)
	}
}

func TestDefenderSecureScore(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	if artifact.Accounts[0].Defender == nil || artifact.Accounts[0].Defender.SecureScorePct == nil || *artifact.Accounts[0].Defender.SecureScorePct != 70 {
		t.Fatalf("unexpected defender score: %#v", artifact.Accounts[0].Defender)
	}

	arm := fakeARMClient()
	arm.secureScoreErrs["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusNotFound, Route: "/secureScores/ascScore"}
	cfg := testConfig()
	cfg.ARMClient = arm
	artifact = collectTestAzureArtifact(t, cfg)
	if artifact.Accounts[0].Defender == nil || artifact.Accounts[0].Defender.SecureScorePct != nil {
		t.Fatalf("expected null defender score, got %#v", artifact.Accounts[0].Defender)
	}
	if len(artifact.Diagnostics.Warnings) == 0 {
		t.Fatal("expected defender warning")
	}
}

func TestSliceCGolden(t *testing.T) {
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

	assertGoldenJSON(t, "../../testdata/golden/slice_c/azure.json", result.Azure)
	assertGoldenJSON(t, "../../testdata/golden/slice_c/cloud-posture.json", result.AzureCloudPosture)
}

func TestCrossTenantIsolation(t *testing.T) {
	tenantA := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	tenantB := "99999999-8888-7777-6666-555555555555"
	subscriptionA := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	subscriptionB := "bbbbbbbb-1111-2222-3333-cccccccccccc"

	resultA := collectTenantIsolationResult(t, tenantA, subscriptionA)
	resultB := collectTenantIsolationResult(t, tenantB, subscriptionB)
	assertNotContainsJSON(t, resultA, tenantB, subscriptionB)
	assertNotContainsJSON(t, resultB, tenantA, subscriptionA)
}

func collectTenantIsolationResult(t *testing.T, tenantID, subscriptionID string) *Result {
	t.Helper()
	graph := fakeGraphClient()
	graph.org.ID = tenantID
	arm := fakeARMClient()
	arm.subscriptions = map[string]*microsoft.Subscription{
		subscriptionID: {SubscriptionID: subscriptionID, State: "Enabled"},
	}
	arm.secureScores = map[string]*microsoft.ARMSecureScore{
		subscriptionID: {Properties: microsoft.ARMSecureScoreProperties{Score: microsoft.ARMScore{Current: 1, Max: 2}}},
	}
	arm.roleAssignments = map[string][]microsoft.ARMRoleAssignment{
		subscriptionID: nil,
	}
	cfg := testConfig()
	cfg.TenantID = tenantID
	cfg.SubscriptionIDs = []string{subscriptionID}
	cfg.GraphClient = graph
	cfg.ARMClient = arm

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertNotContainsJSON(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range forbidden {
		if strings.Contains(string(payload), needle) {
			t.Fatalf("output leaked forbidden value %s: %s", needle, payload)
		}
	}
}

func collectTestAzureArtifact(t *testing.T, cfg Config) *AzureArtifact {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if result.Azure == nil {
		t.Fatal("expected Azure artifact")
	}
	return result.Azure
}
