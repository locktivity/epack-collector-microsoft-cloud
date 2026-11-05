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

func (c *Collector) collectAzure(ctx context.Context, level componentsdk.Level, diagnostics *Diagnostics) *AzureArtifact {
	if c.config.OnStatus != nil {
		c.config.OnStatus("Collecting Azure subscription posture")
	}

	artifact := &AzureArtifact{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      c.clock.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CollectedAtLevel: string(level),
		Accounts:         make([]AzureAccount, 0, len(c.config.SubscriptionIDs)),
	}
	for i, subscriptionID := range c.config.SubscriptionIDs {
		if c.config.OnProgress != nil {
			c.config.OnProgress(int64(i+1), int64(len(c.config.SubscriptionIDs)), "Collecting Azure subscription "+subscriptionID)
		}
		artifact.Accounts = append(artifact.Accounts, c.collectAzureSubscription(ctx, level, i, subscriptionID, diagnostics))
	}
	artifact.Diagnostics = *diagnostics
	return artifact
}

var azureAccountBlocks = []string{"defender", "rbac", "policy", "storage", "keyvault", "sql", "compute", "backup", "network", "logging"}

// Every configured subscription keeps its index in the accounts list, so a
// subscription that cannot be read never shifts the gap pointers of the ones
// after it.
func (c *Collector) collectAzureSubscription(ctx context.Context, level componentsdk.Level, index int, subscriptionID string, diagnostics *Diagnostics) AzureAccount {
	account := AzureAccount{AccountID: subscriptionID}
	if _, err := c.arm.Subscription(ctx, subscriptionID); err != nil {
		diagnostics.SubscriptionErrors = append(diagnostics.SubscriptionErrors, fmt.Sprintf("%s: %s", subscriptionID, err.Error()))
		if apiStatus(err) == http.StatusNotFound {
			err = componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
		}
		account.unreadable = failed(err)
		blocks := azureAccountBlocks
		if level.AtLeast(componentsdk.LevelAudit) {
			blocks = append(append([]string{}, blocks...), "inventory")
		}
		for _, block := range blocks {
			c.gaps.leaveOut(azurePath, account.unreadable, accountPointer(index, block))
		}
		return account
	}

	scope := subscriptionScope{index: index, id: subscriptionID}
	account.Defender = c.collectDefender(ctx, scope, diagnostics)
	account.RBAC, account.roleAssignments, account.rbacMiss = c.collectRBAC(ctx, scope, diagnostics)
	account.Policy = c.collectAzurePolicy(ctx, scope, diagnostics)

	storage, storageAccounts, storageMiss := c.collectStorage(ctx, scope, diagnostics)
	account.Storage = storage
	keyVault, keyVaults, keyVaultsMiss := c.collectKeyVault(ctx, scope, diagnostics)
	account.KeyVault = keyVault
	sql, sqlReads := c.collectSQL(ctx, scope, diagnostics)
	account.SQL = sql
	compute, computeReads := c.collectCompute(ctx, scope, diagnostics)
	account.Compute = compute

	account.Backup = c.collectBackup(ctx, scope, backupPopulation{
		virtualMachines: computeReads.virtualMachines,
		databases:       sqlReads.databases,
		why:             firstMissing(computeReads.virtualMachinesMiss, sqlReads.serversMiss, sqlReads.databasesMiss),
	}, diagnostics)
	account.Network = c.collectNetwork(ctx, scope, computeReads.publicIPs, computeReads.publicIPsMiss, diagnostics)
	account.Logging = c.collectLogging(ctx, scope, monitoredResources{
		list: monitoredResourceList(storageAccounts, keyVaults, sqlReads.masters, sqlReads.databases, computeReads.virtualMachines),
		why:  firstMissing(storageMiss, keyVaultsMiss, sqlReads.serversMiss, sqlReads.databasesMiss, computeReads.virtualMachinesMiss),
	}, diagnostics)
	account.Inventory = c.collectInventory(ctx, level, scope, diagnostics)
	return account
}

type subscriptionScope struct {
	index int
	id    string
}

func (s subscriptionScope) pointer(field string) string {
	return accountPointer(s.index, field)
}

func (c *Collector) collectDefender(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) *AzureDefender {
	out := &AzureDefender{}
	score, err := c.arm.DefenderSecureScore(ctx, scope.id)
	switch {
	case err == nil:
		out.SecureScorePct = defenderSecureScorePct(score)
	case apiStatus(err) == http.StatusNotFound:
		diagnostics.Warn("Defender secure score unavailable for subscription " + scope.id)
		c.gaps.leaveOut(azurePath, unlicensed("Defender for Cloud has no secure score for the subscription."), scope.pointer("defender/secure_score_pct"))
	default:
		warnDefender(diagnostics, "Defender secure score", scope.id, "defender.secure_score_pct", err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("defender/secure_score_pct"))
	}

	assessments, err := c.arm.DefenderAssessments(ctx, scope.id)
	if err == nil {
		out.UnpatchedPct = defenderUnpatchedPct(assessments)
	} else {
		warnDefender(diagnostics, "Defender assessments", scope.id, "defender.unpatched_pct", err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("defender/unpatched_pct"))
	}
	return out
}

// warnDefender keeps the warning older readers know for a Defender call that
// still failed after the SDK's retries.
func warnDefender(diagnostics *Diagnostics, surface, subscriptionID, metric string, err error) {
	switch componentsdk.Classify(err) {
	case componentsdk.CodeRateLimited, componentsdk.CodeVendorError, componentsdk.CodeTimeout:
		if !surfaceUnavailable(err) {
			diagnostics.Warn(notCollectedAfterRetries(surface, subscriptionID, metric, err))
			return
		}
	}
	diagnostics.warnSubscription(surface, subscriptionID, err)
}

func notCollectedAfterRetries(surface, subscriptionID, metric string, err error) string {
	reason := "no response"
	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		reason = fmt.Sprintf("status %d", apiErr.StatusCode)
	}
	return fmt.Sprintf("%s request failed after retries (%s) for subscription %s, %s reported as not_collected", surface, reason, subscriptionID, metric)
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
