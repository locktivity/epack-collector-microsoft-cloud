package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func TestSecureScore(t *testing.T) {
	artifact := collectTestArtifact(t, testConfig())
	if artifact.SecureScore == nil || artifact.SecureScore.IdentityPct == nil || *artifact.SecureScore.IdentityPct != 74 {
		t.Fatalf("unexpected secure score: %#v", artifact.SecureScore)
	}

	graph := fakeGraphClient()
	graph.secureScoresErr = &microsoft.APIError{StatusCode: http.StatusForbidden, Route: "/security/secureScores"}
	cfg := testConfig()
	cfg.GraphClient = graph
	artifact = collectTestArtifact(t, cfg)
	if artifact.SecureScore == nil || artifact.SecureScore.IdentityPct != nil {
		t.Fatalf("expected null secure score without permission, got %#v", artifact.SecureScore)
	}
	if !containsString(artifact.Diagnostics.License.CapabilitiesUnavailable, "identity_secure_score") {
		t.Fatalf("expected identity_secure_score unavailable, got %#v", artifact.Diagnostics.License.CapabilitiesUnavailable)
	}
}
