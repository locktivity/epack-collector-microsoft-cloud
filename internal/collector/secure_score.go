package collector

import (
	"context"
	"errors"
	"net/http"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectSecureScore(ctx context.Context, diagnostics *Diagnostics) (*SecureScore, error) {
	scores, err := c.graph.SecureScores(ctx)
	if err == nil {
		if len(scores) == 0 || scores[0].MaxScore <= 0 {
			diagnostics.Warn("identity secure score unavailable, secure_score.identity_pct reported as not_collected")
			diagnostics.MarkCapabilityUnavailable("identity_secure_score")
			return &SecureScore{}, nil
		}
		return &SecureScore{IdentityPct: PercentFloat(scores[0].CurrentScore, scores[0].MaxScore)}, nil
	}

	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusForbidden {
			diagnostics.Warn("graph permission SecurityEvents.Read.All not granted, identity secure score skipped")
			diagnostics.MarkCapabilityUnavailable("identity_secure_score")
			return &SecureScore{}, nil
		}
		if apiErr.StatusCode == http.StatusNotFound {
			diagnostics.Warn("identity secure score API unavailable, secure_score.identity_pct reported as not_collected")
			diagnostics.MarkCapabilityUnavailable("identity_secure_score")
			return &SecureScore{}, nil
		}
	}
	return nil, err
}
