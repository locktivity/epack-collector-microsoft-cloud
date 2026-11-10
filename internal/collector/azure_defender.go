package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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
	account := AzureAccount{}
	if level.AtLeast(componentsdk.LevelAudit) {
		account.AccountID = subscriptionID
	}
	scope := subscriptionScope{index: index, id: subscriptionID, name: subscriptionName(level, index, subscriptionID)}
	if _, err := c.arm.Subscription(ctx, subscriptionID); err != nil {
		diagnostics.SubscriptionErrors = append(diagnostics.SubscriptionErrors, subscriptionError(level, scope, err))
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

// subscriptionScope is one configured subscription. name is how diagnostics
// text names it.
type subscriptionScope struct {
	index int
	id    string
	name  string
}

// subscriptionName names a subscription by its ID from the audit level, and
// below it by its place in subscription_ids, since a trust run writes no
// subscription IDs.
func subscriptionName(level componentsdk.Level, index int, subscriptionID string) string {
	if level.AtLeast(componentsdk.LevelAudit) {
		return subscriptionID
	}
	return strconv.Itoa(index + 1)
}

// subscriptionError is the subscription_errors line for a subscription that
// could not be read. Below the audit level it names the subscription by its
// place and gives only the HTTP status and Azure's error code, or the SDK's
// code when Azure sent no answer, since Azure's message can name the
// subscription, the tenant, the app, and resource groups.
func subscriptionError(level componentsdk.Level, scope subscriptionScope, err error) string {
	if level.AtLeast(componentsdk.LevelAudit) {
		return fmt.Sprintf("%s: %s", scope.id, err.Error())
	}
	var apiErr *microsoft.APIError
	switch {
	case !errors.As(err, &apiErr):
		return fmt.Sprintf("subscription %s: failed with %s", scope.name, componentsdk.Classify(err))
	case apiErr.Code == "":
		return fmt.Sprintf("subscription %s: status=%d", scope.name, apiErr.StatusCode)
	default:
		return fmt.Sprintf("subscription %s: status=%d code=%s", scope.name, apiErr.StatusCode, microsoft.SanitizeErrorText(apiErr.Code))
	}
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
		diagnostics.Warn("Defender secure score unavailable for subscription " + scope.name)
		c.gaps.leaveOut(azurePath, unlicensed("Defender for Cloud has no secure score for the subscription."), scope.pointer("defender/secure_score_pct"))
	default:
		warnDefender(diagnostics, "Defender secure score", scope.name, "defender.secure_score_pct", err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("defender/secure_score_pct"))
	}

	assessments, err := c.arm.DefenderAssessments(ctx, scope.id)
	if err == nil {
		out.UnpatchedPct = defenderUnpatchedPct(assessments)
	} else {
		warnDefender(diagnostics, "Defender assessments", scope.name, "defender.unpatched_pct", err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("defender/unpatched_pct"))
	}
	return out
}

// warnDefender keeps the warning older readers know for a Defender call that
// still failed after the SDK's retries. subscription is the subscription's
// name in diagnostics text.
func warnDefender(diagnostics *Diagnostics, surface, subscription, metric string, err error) {
	switch componentsdk.Classify(err) {
	case componentsdk.CodeRateLimited, componentsdk.CodeVendorError, componentsdk.CodeTimeout:
		if !surfaceUnavailable(err) {
			diagnostics.Warn(notCollectedAfterRetries(surface, subscription, metric, err))
			return
		}
	}
	diagnostics.warnSubscription(surface, subscription, err)
}

func notCollectedAfterRetries(surface, subscription, metric string, err error) string {
	reason := "no response"
	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		reason = fmt.Sprintf("status %d", apiErr.StatusCode)
	}
	return fmt.Sprintf("%s request failed after retries (%s) for subscription %s, %s reported as not_collected", surface, reason, subscription, metric)
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
