package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectSQL(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzureSQL, []microsoft.SQLServer, []microsoft.SQLDatabase, error) {
	servers, err := c.arm.SQLServers(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("SQL server inventory unavailable for subscription " + subscriptionID)
			return &AzureSQL{}, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	out := &AzureSQL{ServersCount: len(servers)}
	if len(servers) == 0 {
		return out, servers, nil, nil
	}

	minTLS12 := 0
	publicAccessDisabled := 0
	var databases []microsoft.SQLDatabase
	tdeKnown := true
	tdeEnabled := 0
	for _, server := range servers {
		if minTLSAtLeast12(server.Properties.MinimalTLSVersion) {
			minTLS12++
		}
		if strings.EqualFold(server.Properties.PublicNetworkAccess, "Disabled") {
			publicAccessDisabled++
		}

		serverDatabases, err := c.arm.SQLDatabases(ctx, server.ID)
		if err != nil {
			if surfaceUnavailable(err) {
				diagnostics.Warn("SQL database inventory unavailable for subscription " + subscriptionID)
				tdeKnown = false
				continue
			}
			return nil, nil, nil, err
		}
		for _, database := range serverDatabases {
			if strings.EqualFold(database.Name, "master") {
				continue
			}
			databases = append(databases, database)
			tde, err := c.arm.SQLTransparentDataEncryption(ctx, database.ID)
			if err != nil {
				if surfaceUnavailable(err) {
					diagnostics.Warn("SQL transparent data encryption unavailable for subscription " + subscriptionID)
					tdeKnown = false
					continue
				}
				return nil, nil, nil, err
			}
			if tdeEnabledState(tde) {
				tdeEnabled++
			}
		}
	}

	out.MinTLS12Pct = PercentInt(minTLS12, len(servers))
	out.PublicAccessDisabledPct = PercentInt(publicAccessDisabled, len(servers))
	out.DatabasesCount = len(databases)
	if tdeKnown {
		out.TDEEnabledPct = PercentInt(tdeEnabled, len(databases))
	}
	return out, servers, databases, nil
}

func tdeEnabledState(tde *microsoft.SQLTransparentDataEncryption) bool {
	return tde != nil && strings.EqualFold(tde.Properties.State, "Enabled")
}
