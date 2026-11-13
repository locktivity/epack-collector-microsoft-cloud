package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectStorage(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) (*AzureStorage, []microsoft.StorageAccount, *missing) {
	accounts, err := c.arm.StorageAccounts(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Storage accounts", scope.name, err)
		why := failed(err)
		c.gaps.leaveOut(azurePath, why, scope.pointer("storage"))
		return nil, nil, why
	}
	return storagePosture(accounts), accounts, nil
}

func storagePosture(accounts []microsoft.StorageAccount) *AzureStorage {
	out := &AzureStorage{StorageAccountsCount: len(accounts)}
	if len(accounts) == 0 {
		return out
	}

	httpsOnly := 0
	minTLS12 := 0
	cmk := 0
	infrastructureEncryption := 0
	publicAccessBlocked := 0
	networkRestricted := 0
	for _, account := range accounts {
		props := account.Properties
		if props.SupportsHTTPSTrafficOnly != nil && *props.SupportsHTTPSTrafficOnly {
			httpsOnly++
		}
		if minTLSAtLeast12(props.MinimumTLSVersion) {
			minTLS12++
		}
		if storageUsesCMK(props.Encryption) {
			cmk++
		}
		if props.Encryption.RequireInfrastructureEncryption != nil && *props.Encryption.RequireInfrastructureEncryption {
			infrastructureEncryption++
		}
		// allowBlobPublicAccess false turns off anonymous access for every
		// container in the account. An account without the setting allows it.
		if props.AllowBlobPublicAccess != nil && !*props.AllowBlobPublicAccess {
			publicAccessBlocked++
		}
		if networkRestrictedAccount(props) {
			networkRestricted++
		}
	}
	out.HTTPSOnlyPct = PercentInt(httpsOnly, len(accounts))
	out.MinTLS12Pct = PercentInt(minTLS12, len(accounts))
	out.EncryptionCMKPct = PercentInt(cmk, len(accounts))
	out.InfrastructureEncryptionPct = PercentInt(infrastructureEncryption, len(accounts))
	out.PublicAccessBlockedPct = PercentInt(publicAccessBlocked, len(accounts))
	out.NetworkRestrictedPct = PercentInt(networkRestricted, len(accounts))
	// Azure encrypts every storage account at rest, with its own key unless
	// the account names a customer-managed one. An account with no key
	// source uses Azure's, which is the default.
	// https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption
	out.encryptedAtRestCount = len(accounts)
	out.publicAccessBlockedCount = publicAccessBlocked
	out.networkRestrictedCount = networkRestricted
	return out
}

// networkRestrictedAccount reports whether the account refuses public
// network traffic, either with public network access disabled or with a
// firewall that denies by default.
func networkRestrictedAccount(props microsoft.StorageAccountProperties) bool {
	if strings.EqualFold(props.PublicNetworkAccess, "Disabled") {
		return true
	}
	return props.NetworkACLs != nil && strings.EqualFold(props.NetworkACLs.DefaultAction, "Deny")
}

func storageUsesCMK(encryption microsoft.StorageEncryption) bool {
	keySource := strings.ReplaceAll(encryption.KeySource, " ", "")
	return strings.EqualFold(keySource, "Microsoft.Keyvault") || strings.EqualFold(keySource, "Microsoft.KeyVault")
}

func minTLSAtLeast12(version string) bool {
	switch strings.ToUpper(strings.ReplaceAll(version, ".", "_")) {
	case "TLS1_2", "TLS1_3", "1_2", "1_3":
		return true
	default:
		return false
	}
}
