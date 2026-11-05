package collector

import (
	"context"
	"net/http"
)

func (c *Collector) collectSecureScore(ctx context.Context, diagnostics *Diagnostics) *SecureScore {
	const identityPct = "/secure_score/identity_pct"
	out := &SecureScore{}
	scores, err := c.graph.SecureScores(ctx)
	switch {
	case err == nil && (len(scores) == 0 || scores[0].MaxScore <= 0):
		diagnostics.Warn("identity secure score unavailable, secure_score.identity_pct reported as not_collected")
		diagnostics.MarkCapabilityUnavailable("identity_secure_score")
		c.gaps.leaveOut(entraPath, unlicensed("The tenant reports no identity secure score."), identityPct)
	case err == nil:
		out.IdentityPct = PercentFloat(scores[0].CurrentScore, scores[0].MaxScore)
	case permissionDenied(err):
		diagnostics.Warn("graph permission SecurityEvents.Read.All not granted, identity secure score skipped")
		diagnostics.MarkCapabilityUnavailable("identity_secure_score")
		c.gaps.leaveOut(entraPath, failed(err), identityPct)
	case apiStatus(err) == http.StatusNotFound:
		diagnostics.Warn("identity secure score API unavailable, secure_score.identity_pct reported as not_collected")
		diagnostics.MarkCapabilityUnavailable("identity_secure_score")
		c.gaps.leaveOut(entraPath, unlicensed("The tenant has no identity secure score."), identityPct)
	default:
		diagnostics.warnNotCollected("Identity secure score", err)
		c.gaps.leaveOut(entraPath, failed(err), identityPct)
	}
	return out
}
