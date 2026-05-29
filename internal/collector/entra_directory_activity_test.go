package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func TestDirectoryActivityInternalOnly(t *testing.T) {
	trustArtifact := collectTestArtifact(t, testConfig())
	if trustArtifact.DirectoryActivity != nil {
		t.Fatalf("expected directory activity omitted at trust level, got %#v", trustArtifact.DirectoryActivity)
	}

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

	activity := result.Entra.DirectoryActivity
	if activity == nil {
		t.Fatal("expected directory activity at internal level")
	}
	assertInt(t, "lookback hours", activity.LookbackHours, 168)
	assertInt(t, "events", activity.EventsCount, 6)
	assertInt(t, "failure", activity.FailureCount, 2)
	assertInt(t, "delete", activity.DeleteEventsCount, 1)
	assertInt(t, "user changes", activity.UserChangeEventsCount, 1)
	assertInt(t, "group changes", activity.GroupChangeEventsCount, 1)
	assertInt(t, "app changes", activity.AppChangeEventsCount, 1)
	assertInt(t, "role changes", activity.RoleChangeEventsCount, 2)
	assertInt(t, "policy changes", activity.PolicyChangeEventsCount, 1)
	assertInt(t, "PIM events", activity.PIMEventsCount, 1)
}

func TestDirectoryActivityUnavailable(t *testing.T) {
	graph := fakeGraphClient()
	graph.directoryAuditsErr = &microsoft.APIError{Service: "graph", StatusCode: http.StatusForbidden, Route: "/auditLogs/directoryAudits"}
	cfg := testConfig()
	cfg.GraphClient = graph

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entra.DirectoryActivity != nil {
		t.Fatalf("expected directory activity omitted without permission, got %#v", result.Entra.DirectoryActivity)
	}
	if !containsString(result.Entra.Diagnostics.License.CapabilitiesUnavailable, "directory_audit_activity") {
		t.Fatalf("expected directory_audit_activity unavailable, got %#v", result.Entra.Diagnostics.License.CapabilitiesUnavailable)
	}
}

func TestSliceGGolden(t *testing.T) {
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

	assertGoldenJSON(t, "../../testdata/golden/slice_g/entra.json", result.Entra)
}
