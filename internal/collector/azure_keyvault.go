package collector

import (
	"context"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectKeyVault(ctx context.Context, subscriptionID string, diagnostics *Diagnostics) (*AzureKeyVault, []microsoft.KeyVault, error) {
	vaults, err := c.arm.KeyVaults(ctx, subscriptionID)
	if err != nil {
		if surfaceUnavailable(err) {
			diagnostics.Warn("Key Vault inventory unavailable for subscription " + subscriptionID)
			return &AzureKeyVault{}, nil, nil
		}
		return nil, nil, err
	}
	return keyVaultPosture(vaults), vaults, nil
}

func keyVaultPosture(vaults []microsoft.KeyVault) *AzureKeyVault {
	out := &AzureKeyVault{VaultsCount: len(vaults)}
	if len(vaults) == 0 {
		return out
	}

	purgeProtection := 0
	rbacAuthorization := 0
	for _, vault := range vaults {
		if vault.Properties.EnablePurgeProtection != nil && *vault.Properties.EnablePurgeProtection {
			purgeProtection++
		}
		if vault.Properties.EnableRBACAuthorization != nil && *vault.Properties.EnableRBACAuthorization {
			rbacAuthorization++
		}
	}
	out.PurgeProtectionPct = PercentInt(purgeProtection, len(vaults))
	out.RBACAuthorizationPct = PercentInt(rbacAuthorization, len(vaults))
	return out
}
