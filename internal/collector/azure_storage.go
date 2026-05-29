package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectStorage(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzureStorage, []microsoft.StorageAccount, error) {
	accounts, err := c.arm.StorageAccounts(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("Storage accounts unavailable for subscription " + subscriptionID)
			return &AzureStorage{}, nil, nil
		}
		return nil, nil, err
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
		if props.AllowBlobPublicAccess != nil && !*props.AllowBlobPublicAccess && strings.EqualFold(props.PublicNetworkAccess, "Disabled") {
			publicAccessBlocked++
		}
	}
	out.HTTPSOnlyPct = PercentInt(httpsOnly, len(accounts))
	out.MinTLS12Pct = PercentInt(minTLS12, len(accounts))
	out.EncryptionCMKPct = PercentInt(cmk, len(accounts))
	out.InfrastructureEncryptionPct = PercentInt(infrastructureEncryption, len(accounts))
	out.PublicAccessBlockedPct = PercentInt(publicAccessBlocked, len(accounts))
	return out
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
