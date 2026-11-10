package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type monitoredResources struct {
	list []monitoredResource
	why  *missing
}

// monitoredResource is a resource whose logging coverage is measured. Its
// logs and metrics can be in the diagnostic settings of any of settingIDs.
type monitoredResource struct {
	settingIDs []string
}

func (c *Collector) collectLogging(ctx context.Context, scope subscriptionScope, resources monitoredResources, diagnostics *Diagnostics) *AzureLogging {
	out := &AzureLogging{}
	subscriptionSettings, err := c.arm.SubscriptionDiagnosticSettings(ctx, scope.id)
	if err == nil {
		out.SubscriptionDiagnosticSettingsEnabled = boolPtr(diagnosticSettingsEnabled(subscriptionSettings))
		out.ActivityLogAdministrativeExported = boolPtr(activityLogAdministrativeExported(subscriptionSettings))
	} else {
		diagnostics.warnSubscription("Subscription diagnostic settings", scope.name, err)
		c.gaps.leaveOut(azurePath, failed(err),
			scope.pointer("logging/subscription_diagnostic_settings_enabled"),
			scope.pointer("logging/activity_log_administrative_exported"))
	}

	coverage := scope.pointer("logging/diagnostic_settings_coverage_pct")
	withoutDiagnostics := scope.pointer("logging/resources_without_diagnostics_count")
	if resources.why != nil {
		c.gaps.leaveOut(azurePath, resources.why, scope.pointer("logging/monitored_resources_count"), coverage, withoutDiagnostics)
		return out
	}
	out.MonitoredResourcesCount = intPtr(len(resources.list))
	if len(resources.list) == 0 {
		return out
	}

	enabled := 0
	unread := 0
	var firstErr error
	for _, resource := range resources.list {
		logged, err := c.resourceLogged(ctx, resource)
		if err != nil {
			if unread == 0 {
				diagnostics.warnSubscription("Resource diagnostic settings", scope.name, err)
				firstErr = err
			}
			unread++
			continue
		}
		if logged {
			enabled++
		}
	}
	if unread > 0 {
		c.gaps.partial(azurePath, unread, failed(firstErr), coverage, withoutDiagnostics)
		return out
	}
	out.DiagnosticSettingsCoveragePct = PercentInt(enabled, len(resources.list))
	out.ResourcesWithoutDiagnosticsCount = intPtr(len(resources.list) - enabled)
	return out
}

// resourceLogged reports whether a diagnostic setting sends the resource's
// logs or metrics to a destination. It returns an error only when a read
// failed and none of the settings read do.
func (c *Collector) resourceLogged(ctx context.Context, resource monitoredResource) (bool, error) {
	var firstErr error
	for _, id := range resource.settingIDs {
		settings, err := c.arm.DiagnosticSettings(ctx, id)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if diagnosticSettingsEnabled(settings) {
			return true, nil
		}
	}
	return false, firstErr
}

// storageServices are the services of a storage account that hold its
// resource logs. The account's own diagnostic setting carries only metrics.
// https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/logs-index
var storageServices = []string{"blobServices", "fileServices", "queueServices", "tableServices"}

// monitoredResourceList lists the resources whose logging is measured. A
// SQL server has no diagnostic settings of its own. Its audit logs are sent
// through a diagnostic setting on its master database, so the server is
// measured by that database.
func monitoredResourceList(storageAccounts []microsoft.StorageAccount, keyVaults []microsoft.KeyVault, sqlMasters, sqlDatabases []microsoft.SQLDatabase, virtualMachines []microsoft.VirtualMachine) []monitoredResource {
	var list []monitoredResource
	add := func(ids ...string) {
		if ids[0] != "" {
			list = append(list, monitoredResource{settingIDs: ids})
		}
	}
	for _, account := range storageAccounts {
		ids := []string{account.ID}
		for _, service := range storageServices {
			ids = append(ids, account.ID+"/"+service+"/default")
		}
		add(ids...)
	}
	for _, vault := range keyVaults {
		add(vault.ID)
	}
	for _, master := range sqlMasters {
		add(master.ID)
	}
	for _, database := range sqlDatabases {
		add(database.ID)
	}
	for _, vm := range virtualMachines {
		add(vm.ID)
	}
	return list
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

// Only the Administrative category records control-plane writes, so a setting
// that exports other categories does not count as an Activity Log export.
func activityLogAdministrativeExported(settings []microsoft.DiagnosticSetting) bool {
	for _, setting := range settings {
		if !diagnosticSettingHasDestination(setting) {
			continue
		}
		for _, logSetting := range setting.Properties.Logs {
			if !logSetting.Enabled {
				continue
			}
			if strings.EqualFold(logSetting.Category, "Administrative") || strings.EqualFold(logSetting.CategoryGroup, "allLogs") {
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
