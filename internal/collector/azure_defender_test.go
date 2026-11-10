package collector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"syscall"
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

	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.SubscriptionIDs = []string{
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"bbbbbbbb-1111-2222-3333-cccccccccccc",
		"cccccccc-1111-2222-3333-dddddddddddd",
	}
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
	if result.Azure == nil || len(result.Azure.Accounts) != 3 {
		t.Fatalf("expected an account for each configured subscription, got %#v", result.Azure)
	}
	if result.Azure.Accounts[1].Defender == nil || result.Azure.Accounts[1].RBAC == nil {
		t.Fatalf("expected the readable subscriptions to be collected, got %#v", result.Azure.Accounts[1])
	}
	unreadable := result.Azure.Accounts[2]
	if unreadable.AccountID != "" || unreadable.Defender != nil || unreadable.Storage != nil || unreadable.Logging != nil {
		t.Fatalf("expected the unreadable subscription to carry nothing at trust, got %#v", unreadable)
	}
	if errs := result.Azure.Diagnostics.SubscriptionErrors; len(errs) != 1 || errs[0] != "subscription 3: status=403" {
		t.Fatalf("expected one subscription error naming the third subscription, got %#v", errs)
	}
	assertGap(t, rec, azurePath, "/accounts/2/storage", componentsdk.CodePermissionDenied)
	assertGap(t, rec, cloudPosturePath, "/accounts/2/storage", componentsdk.CodePermissionDenied)
	if cloud := result.AzureCloudPosture.Accounts[2]; cloud.Storage != nil || cloud.Network != nil {
		t.Fatalf("expected the unreadable subscription's cloud posture to carry only its ID, got %#v", cloud)
	}
}

func TestUnreadableSubscriptionKeepsItsAccountEntry(t *testing.T) {
	subscriptionID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	arm := fakeARMClient()
	arm.subscriptionErrs[subscriptionID] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusNotFound, Route: "/subscriptions/" + subscriptionID, Code: "SubscriptionNotFound", Message: "not found"}
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
	if result.Azure == nil || len(result.Azure.Accounts) != 1 || result.Azure.Accounts[0].Defender != nil {
		t.Fatalf("expected one account carrying only its ID, got %#v", result.Azure)
	}
	if errs := result.Azure.Diagnostics.SubscriptionErrors; len(errs) != 1 || errs[0] != "subscription 1: status=404 code=SubscriptionNotFound" {
		t.Fatalf("expected Azure subscription error, got %#v", errs)
	}
	if len(result.Entra.Diagnostics.SubscriptionErrors) != 1 {
		t.Fatalf("expected final diagnostics on Entra artifact, got %#v", result.Entra.Diagnostics.SubscriptionErrors)
	}
	gap := assertGap(t, rec, azurePath, "/accounts/0/defender", componentsdk.CodeConfigInvalid)
	if gap.VendorCode != "SubscriptionNotFound" {
		t.Fatalf("expected the ARM error code on the gap, got %#v", gap)
	}
}

// Below the audit level a subscription error gives the subscription's place
// and the HTTP status and Azure's error code, or the SDK's code when Azure
// sent no answer, and none of Azure's message. From the audit level it gives
// the ID and the error's text.
func TestSubscriptionErrorText(t *testing.T) {
	scope := subscriptionScope{index: 1, id: "bbbbbbbb-1111-2222-3333-cccccccccccc", name: "2"}
	refused := &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/subscriptions/" + scope.id, Code: "AuthorizationFailed",
		Message: "The client '11111111-2222-3333-4444-555555555555' cannot read scope '/subscriptions/" + scope.id + "/resourceGroups/prod-rg'."}
	cases := []struct {
		name  string
		level componentsdk.Level
		err   error
		want  string
	}{
		{"refused", componentsdk.LevelTrust, refused, "subscription 2: status=403 code=AuthorizationFailed"},
		{"no code", componentsdk.LevelTrust, &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden}, "subscription 2: status=403"},
		{"no answer", componentsdk.LevelTrust, &microsoft.RequestError{Service: "arm", Route: "/subscriptions/" + scope.id, Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}, "subscription 2: failed with vendor_error"},
		{"audit", componentsdk.LevelAudit, refused, scope.id + ": " + refused.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := subscriptionError(tc.level, scope, tc.err); got != tc.want {
				t.Fatalf("subscriptionError = %q, want %q", got, tc.want)
			}
		})
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

func TestDefenderExhaustedRetriesReportNotCollected(t *testing.T) {
	subscriptionID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	arm := fakeARMClient()
	arm.secureScoreErrs[subscriptionID] = &microsoft.RequestError{Service: "arm", Route: "/secureScores/ascScore", Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}
	arm.defenderAssessmentErrs[subscriptionID] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusInternalServerError, Route: "/assessments"}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec

	artifact := collectTestAzureArtifact(t, cfg)
	account := artifact.Accounts[0]
	if account.Defender == nil || account.Defender.SecureScorePct != nil || account.Defender.UnpatchedPct != nil {
		t.Fatalf("expected null defender metrics, got %#v", account.Defender)
	}
	if account.RBAC == nil || account.RBAC.OwnerCount == 0 || account.Logging == nil {
		t.Fatalf("expected the rest of the subscription to be collected, got %#v", account)
	}
	for _, expected := range []string{
		"Defender secure score request failed after retries (no response) for subscription 1, defender.secure_score_pct reported as not_collected",
		"Defender assessments request failed after retries (status 500) for subscription 1, defender.unpatched_pct reported as not_collected",
	} {
		if !containsString(artifact.Diagnostics.Warnings, expected) {
			t.Fatalf("expected warning %q, got %#v", expected, artifact.Diagnostics.Warnings)
		}
	}
	assertGap(t, rec, azurePath, "/accounts/0/defender/secure_score_pct", componentsdk.CodeVendorError)
	assertGap(t, rec, azurePath, "/accounts/0/defender/unpatched_pct", componentsdk.CodeVendorError)
}

func TestDefenderBadRequestLeavesMetricOut(t *testing.T) {
	arm := fakeARMClient()
	arm.defenderAssessmentErrs["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusBadRequest, Route: "/assessments"}
	rec := &componentsdk.Recorder{}
	cfg := testConfig()
	cfg.ARMClient = arm
	cfg.Recorder = rec

	artifact := collectTestAzureArtifact(t, cfg)
	if artifact.Accounts[0].Defender.UnpatchedPct != nil {
		t.Fatalf("expected null unpatched percentage, got %#v", artifact.Accounts[0].Defender)
	}
	assertGap(t, rec, azurePath, "/accounts/0/defender/unpatched_pct", componentsdk.CodeInvalidResponse)
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
