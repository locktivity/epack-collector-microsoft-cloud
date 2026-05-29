package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestSignInMonitoringInternalOnly(t *testing.T) {
	trustArtifact := collectTestArtifact(t, testConfig())
	if trustArtifact.SignInMonitoring != nil {
		t.Fatalf("expected sign-in monitoring omitted at trust level, got %#v", trustArtifact.SignInMonitoring)
	}

	result := collectTestResultAtLevel(t, testConfig(), componentsdk.LevelInternal)
	monitoring := result.Entra.SignInMonitoring
	if monitoring == nil {
		t.Fatal("expected sign-in monitoring")
	}
	assertInt(t, "sign-in lookback hours", monitoring.LookbackHours, 168)
	assertInt(t, "sign-ins", monitoring.SignInsCount, 4)
	assertInt(t, "failed sign-ins", monitoring.FailureCount, 2)
	assertInt(t, "unique users", monitoring.UniqueUsersCount, 3)
	assertInt(t, "unique apps", monitoring.UniqueAppsCount, 2)
	assertInt(t, "legacy client sign-ins", monitoring.LegacyClientSignInsCount, 1)
	assertInt(t, "risky sign-ins", monitoring.RiskySignInsCount, 2)
	assertInt(t, "CA success", monitoring.ConditionalAccessSuccessCount, 2)
	assertInt(t, "CA failure", monitoring.ConditionalAccessFailureCount, 1)
	assertInt(t, "CA not applied", monitoring.ConditionalAccessNotAppliedCount, 1)
	assertInt(t, "applied policies", monitoring.AppliedPoliciesCount, 3)
	assertInt(t, "applied policy evaluations", monitoring.AppliedPolicyEvaluationsCount, 4)
	assertInt(t, "applied policy successes", monitoring.AppliedPolicySuccessCount, 1)
	assertInt(t, "applied policy failures", monitoring.AppliedPolicyFailureCount, 1)
	assertInt(t, "applied policy not applied", monitoring.AppliedPolicyNotAppliedCount, 1)
	assertInt(t, "applied policy report-only failures", monitoring.AppliedPolicyReportOnlyFailCount, 1)
	if len(monitoring.TopFailureCodes) != 2 || monitoring.TopFailureCodes[0].Code != 50053 || monitoring.TopFailureCodes[1].Code != 50126 {
		t.Fatalf("unexpected top failure codes: %#v", monitoring.TopFailureCodes)
	}
}

func TestSignInMonitoringUnavailable(t *testing.T) {
	graph := fakeGraphClient()
	graph.signInsErr = &microsoft.APIError{Service: "graph", StatusCode: http.StatusForbidden, Route: "/auditLogs/signIns", Code: "Authorization_RequestDenied"}
	cfg := testConfig()
	cfg.GraphClient = graph

	result := collectTestResultAtLevel(t, cfg, componentsdk.LevelInternal)
	if result.Entra.SignInMonitoring != nil {
		t.Fatalf("expected sign-in monitoring omitted without permission, got %#v", result.Entra.SignInMonitoring)
	}
	if len(result.Entra.Diagnostics.Warnings) == 0 {
		t.Fatal("expected sign-in monitoring warning")
	}
	if got := result.Entra.Diagnostics.License.CapabilitiesUnavailable; got[len(got)-1] != "sign_in_logs" {
		t.Fatalf("expected sign_in_logs unavailable capability, got %#v", got)
	}
}

func TestSliceIGolden(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = FixedClock{Time: goldenTime}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatal(err)
	}

	assertGoldenJSON(t, "../../testdata/golden/slice_i/entra.json", result.Entra)
}
