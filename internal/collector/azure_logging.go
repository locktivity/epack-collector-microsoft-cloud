package collector

import (
	"context"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectLogging(ctx context.Context, subscriptionID string, resourceIDs []string, diagnostics *Diagnostics) (*AzureLogging, error) {
	out := &AzureLogging{MonitoredResourcesCount: len(resourceIDs)}
	subscriptionSettings, err := c.arm.SubscriptionDiagnosticSettings(ctx, subscriptionID)
	if err == nil {
		out.SubscriptionDiagnosticSettingsEnabled = boolPtr(diagnosticSettingsEnabled(subscriptionSettings))
	} else if surfaceUnavailable(err) {
		diagnostics.Warn("Subscription diagnostic settings unavailable for subscription " + subscriptionID)
	} else {
		return nil, err
	}

	if len(resourceIDs) == 0 {
		return out, nil
	}

	known := true
	enabled := 0
	warned := false
	for _, resourceID := range resourceIDs {
		settings, err := c.arm.DiagnosticSettings(ctx, resourceID)
		if err != nil {
			if surfaceUnavailable(err) {
				known = false
				if !warned {
					diagnostics.Warn("Resource diagnostic settings unavailable for subscription " + subscriptionID)
					warned = true
				}
				continue
			}
			return nil, err
		}
		if diagnosticSettingsEnabled(settings) {
			enabled++
		}
	}
	if known {
		out.DiagnosticSettingsCoveragePct = PercentInt(enabled, len(resourceIDs))
		out.ResourcesWithoutDiagnosticsCount = intPtr(len(resourceIDs) - enabled)
	}
	return out, nil
}

func monitoredResourceIDs(storageAccounts []microsoft.StorageAccount, keyVaults []microsoft.KeyVault, sqlServers []microsoft.SQLServer, sqlDatabases []microsoft.SQLDatabase, virtualMachines []microsoft.VirtualMachine) []string {
	resourceIDs := make([]string, 0, len(storageAccounts)+len(keyVaults)+len(sqlServers)+len(sqlDatabases)+len(virtualMachines))
	for _, account := range storageAccounts {
		resourceIDs = appendResourceID(resourceIDs, account.ID)
	}
	for _, vault := range keyVaults {
		resourceIDs = appendResourceID(resourceIDs, vault.ID)
	}
	for _, server := range sqlServers {
		resourceIDs = appendResourceID(resourceIDs, server.ID)
	}
	for _, database := range sqlDatabases {
		resourceIDs = appendResourceID(resourceIDs, database.ID)
	}
	for _, vm := range virtualMachines {
		resourceIDs = appendResourceID(resourceIDs, vm.ID)
	}
	return resourceIDs
}

func appendResourceID(resourceIDs []string, resourceID string) []string {
	if resourceID == "" {
		return resourceIDs
	}
	return append(resourceIDs, resourceID)
}

func diagnosticSettingsEnabled(settings []microsoft.DiagnosticSetting) bool {
	for _, setting := range settings {
		if !diagnosticSettingHasDestination(setting) {
			continue
		}
		for _, logSetting := range setting.Properties.Logs {
			if logSetting.Enabled {
				return true
			}
		}
		for _, metricSetting := range setting.Properties.Metrics {
			if metricSetting.Enabled {
				return true
			}
		}
	}
	return false
}

func diagnosticSettingHasDestination(setting microsoft.DiagnosticSetting) bool {
	props := setting.Properties
	return props.WorkspaceID != "" ||
		props.StorageAccountID != "" ||
		props.EventHubAuthorizationRuleID != "" ||
		props.MarketplacePartnerID != ""
}
