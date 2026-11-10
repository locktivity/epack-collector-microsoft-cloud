package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

// sqlReads are the SQL servers and databases read. databases leaves out
// each server's master database, which is in masters.
type sqlReads struct {
	servers       []microsoft.SQLServer
	serversMiss   *missing
	databases     []microsoft.SQLDatabase
	masters       []microsoft.SQLDatabase
	databasesMiss *missing
}

func (c *Collector) collectSQL(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) (*AzureSQL, sqlReads) {
	servers, err := c.arm.SQLServers(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("SQL server inventory", scope.name, err)
		why := failed(err)
		c.gaps.leaveOut(azurePath, why, scope.pointer("sql"))
		return nil, sqlReads{serversMiss: why}
	}

	reads := sqlReads{servers: servers}
	out := &AzureSQL{ServersCount: len(servers)}
	if len(servers) == 0 {
		out.DatabasesCount = intPtr(0)
		return out, reads
	}

	minTLS12 := 0
	publicAccessDisabled := 0
	tdeEnabled := 0
	unlistedServers, unreadTDE := 0, 0
	var listErr, tdeErr error
	for _, server := range servers {
		if minTLSAtLeast12(server.Properties.MinimalTLSVersion) {
			minTLS12++
		}
		if strings.EqualFold(server.Properties.PublicNetworkAccess, "Disabled") {
			publicAccessDisabled++
		}

		serverDatabases, err := c.arm.SQLDatabases(ctx, server.ID)
		if err != nil {
			diagnostics.warnSubscription("SQL database inventory", scope.name, err)
			unlistedServers++
			if listErr == nil {
				listErr = err
			}
			continue
		}
		for _, database := range serverDatabases {
			if strings.EqualFold(database.Name, "master") {
				reads.masters = append(reads.masters, database)
				continue
			}
			reads.databases = append(reads.databases, database)
			tde, err := c.arm.SQLTransparentDataEncryption(ctx, database.ID)
			if err != nil {
				diagnostics.warnSubscription("SQL transparent data encryption", scope.name, err)
				unreadTDE++
				if tdeErr == nil {
					tdeErr = err
				}
				continue
			}
			if tdeEnabledState(tde) {
				tdeEnabled++
			}
		}
	}

	out.MinTLS12Pct = PercentInt(minTLS12, len(servers))
	out.PublicAccessDisabledPct = PercentInt(publicAccessDisabled, len(servers))
	switch {
	case unlistedServers > 0:
		reads.databasesMiss = failed(listErr)
		c.gaps.partial(azurePath, unlistedServers, reads.databasesMiss, scope.pointer("sql/databases_count"))
		c.gaps.leaveOut(azurePath, reads.databasesMiss, scope.pointer("sql/tde_enabled_pct"))
	case unreadTDE > 0:
		out.DatabasesCount = intPtr(len(reads.databases))
		c.gaps.partial(azurePath, unreadTDE, failed(tdeErr), scope.pointer("sql/tde_enabled_pct"))
	default:
		out.DatabasesCount = intPtr(len(reads.databases))
		out.TDEEnabledPct = PercentInt(tdeEnabled, len(reads.databases))
	}
	return out, reads
}

func tdeEnabledState(tde *microsoft.SQLTransparentDataEncryption) bool {
	return tde != nil && strings.EqualFold(tde.Properties.State, "Enabled")
}
