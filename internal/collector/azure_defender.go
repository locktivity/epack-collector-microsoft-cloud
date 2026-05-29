package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

func (c *Collector) collectAzure(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) (*AzureArtifact, error) {
	if c.config.OnStatus != nil {
		c.config.OnStatus("Collecting Azure subscription posture")
	}

	artifact := &AzureArtifact{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      c.clock.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CollectedAtLevel: string(level),
		Diagnostics:      *diagnostics,
	}

	for i, subscriptionID := range c.config.SubscriptionIDs {
		if c.config.OnProgress != nil {
			c.config.OnProgress(int64(i+1), int64(len(c.config.SubscriptionIDs)), "Collecting Azure subscription "+subscriptionID)
		}
		account, ok, err := c.collectAzureSubscription(ctx, level, subscriptionID, diagnostics)
		if err != nil {
			return nil, err
		}
		if ok {
			artifact.Accounts = append(artifact.Accounts, *account)
		}
	}
	artifact.Diagnostics = *diagnostics
	if len(artifact.Accounts) == 0 {
		if len(diagnostics.SubscriptionErrors) > 0 {
			return artifact, nil
		}
		return nil, nil
	}
	return artifact, nil
}

func (c *Collector) collectAzureSubscription(ctx context.Context, level componentsdk.Level, subscriptionID string, diagnostics *Diagnostics) (*AzureAccount, bool, error) {
	if _, err := c.arm.Subscription(ctx, subscriptionID); err != nil {
		if subscriptionError(err) {
			diagnostics.SubscriptionErrors = append(diagnostics.SubscriptionErrors, fmt.Sprintf("%s: %s", subscriptionID, err.Error()))
			return nil, false, nil
		}
		return nil, false, err
	}

	account := &AzureAccount{AccountID: subscriptionID}
	defender, err := c.collectDefender(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Defender = defender

	rbac, err := c.collectRBAC(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.RBAC = rbac

	policy, err := c.collectAzurePolicy(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Policy = policy

	storage, storageAccounts, err := c.collectStorage(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Storage = storage

	keyVault, keyVaults, err := c.collectKeyVault(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.KeyVault = keyVault

	sql, sqlServers, sqlDatabases, err := c.collectSQL(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.SQL = sql

	compute, virtualMachines, publicIPs, err := c.collectCompute(ctx, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Compute = compute

	backup, err := c.collectBackup(ctx, subscriptionID, virtualMachines, sqlDatabases, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Backup = backup

	network, err := c.collectNetwork(ctx, subscriptionID, publicIPs, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Network = network

	logging, err := c.collectLogging(ctx, subscriptionID, monitoredResourceIDs(storageAccounts, keyVaults, sqlServers, sqlDatabases, virtualMachines), diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Logging = logging

	inventory, err := c.collectInventory(ctx, level, subscriptionID, diagnostics)
	if err != nil {
		return nil, false, err
	}
	account.Inventory = inventory

	return account, true, nil
}

func (c *Collector) collectDefender(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzureDefender, error) {
	out := &AzureDefender{}
	score, err := c.arm.DefenderSecureScore(ctx, subscriptionID)
	if err == nil {
		out.SecureScorePct = defenderSecureScorePct(score)
	} else if surfaceUnavailable(err) {
		diagnostics.Warn("Defender secure score unavailable for subscription " + subscriptionID)
	} else {
		return nil, err
	}

	assessments, err := c.arm.DefenderAssessments(ctx, subscriptionID)
	if err == nil {
		out.UnpatchedPct = defenderUnpatchedPct(assessments)
	} else if surfaceUnavailable(err) {
		diagnostics.Warn("Defender assessments unavailable for subscription " + subscriptionID)
	} else {
		return nil, err
	}
	return out, nil
}

func defenderSecureScorePct(score *microsoft.ARMSecureScore) *int {
	if score == nil {
		return nil
	}
	if score.Properties.Score.Percentage > 0 {
		return PercentFloat(score.Properties.Score.Percentage, 1)
	}
	return PercentFloat(score.Properties.Score.Current, score.Properties.Score.Max)
}

func defenderUnpatchedPct(assessments []microsoft.SecurityAssessment) *int {
	unhealthy := 0
	denominator := 0
	for _, assessment := range assessments {
		if !patchOrVulnerabilityAssessment(assessment) {
			continue
		}
		status := strings.ToLower(assessment.Properties.Status.Code)
		switch status {
		case "healthy":
			denominator++
		case "unhealthy":
			denominator++
			unhealthy++
		}
	}
	return PercentInt(unhealthy, denominator)
}

func patchOrVulnerabilityAssessment(assessment microsoft.SecurityAssessment) bool {
	haystack := strings.ToLower(assessment.Name + " " + assessment.Properties.DisplayName + " " + strings.Join(assessment.Properties.Metadata.Categories, " "))
	return strings.Contains(haystack, "vulnerab") ||
		strings.Contains(haystack, "patch") ||
		strings.Contains(haystack, "update")
}

func subscriptionError(err error) bool {
	var apiErr *microsoft.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func surfaceUnavailable(err error) bool {
	var apiErr *microsoft.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}
