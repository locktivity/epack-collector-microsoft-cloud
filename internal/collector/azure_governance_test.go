package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestDefenderUnpatchedPct(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	defender := artifact.Accounts[0].Defender
	if defender == nil {
		t.Fatal("expected defender posture")
	}
	assertPtrInt(t, "unpatched", defender.UnpatchedPct, 50)
}

func TestDefenderUnpatchedPctNoAssessments(t *testing.T) {
	arm := fakeARMClient()
	arm.defenderAssessments["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	if got := artifact.Accounts[0].Defender.UnpatchedPct; got != nil {
		t.Fatalf("expected null unpatched percentage, got %#v", got)
	}
}

func TestAzurePolicyCompliance(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	policy := artifact.Accounts[0].Policy
	if policy == nil {
		t.Fatal("expected policy posture")
	}
	assertInt(t, "policy assignment count", policy.AssignmentsCount, 2)
	assertPtrInt(t, "policy compliant", policy.CompliantPct, 75)
	assertPtrInt(t, "policy noncompliant resource count", policy.NoncompliantResourcesCount, 2)
}

func TestAzurePolicyNoAssignments(t *testing.T) {
	arm := fakeARMClient()
	arm.policyAssignments["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = nil
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	policy := artifact.Accounts[0].Policy
	if policy == nil {
		t.Fatal("expected policy posture")
	}
	if policy.AssignmentsCount != 0 {
		t.Fatalf("expected zero assignments, got %d", policy.AssignmentsCount)
	}
	if policy.CompliantPct != nil || policy.NoncompliantResourcesCount != nil {
		t.Fatalf("expected null compliance with zero assignments, got %#v", policy)
	}
}

func TestAzurePolicySummaryUnavailable(t *testing.T) {
	arm := fakeARMClient()
	arm.policyStateSummaryErrs["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = &microsoft.APIError{Service: "arm", StatusCode: http.StatusForbidden, Route: "/policyStates/latest/summarize"}
	cfg := testConfig()
	cfg.ARMClient = arm

	artifact := collectTestAzureArtifact(t, cfg)
	policy := artifact.Accounts[0].Policy
	if policy == nil || policy.AssignmentsCount != 2 {
		t.Fatalf("unexpected policy posture: %#v", policy)
	}
	if policy.CompliantPct != nil || policy.NoncompliantResourcesCount != nil {
		t.Fatalf("expected null policy compliance, got %#v", policy)
	}
	if len(artifact.Diagnostics.Warnings) == 0 {
		t.Fatal("expected policy warning")
	}
}

func TestSliceEGolden(t *testing.T) {
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

	assertGoldenJSON(t, "../../testdata/golden/slice_e/azure.json", result.Azure)
	assertGoldenJSON(t, "../../testdata/golden/slice_e/cloud-posture.json", result.AzureCloudPosture)
}
