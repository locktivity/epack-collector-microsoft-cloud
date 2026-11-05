package collector

import (
	"context"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectKeyVault(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) (*AzureKeyVault, []microsoft.KeyVault, *missing) {
	vaults, err := c.arm.KeyVaults(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Key Vault inventory", scope.id, err)
		why := failed(err)
		c.gaps.leaveOut(azurePath, why, scope.pointer("keyvault"))
		return nil, nil, why
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
