package collector

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

var ownerTagKeys = map[string]struct{}{
	"owner":            {},
	"applicationowner": {},
	"businessowner":    {},
	"serviceowner":     {},
	"contact":          {},
	"managedby":        {},
}

var environmentTagKeys = map[string]struct{}{
	"environment": {},
	"env":         {},
	"stage":       {},
}

func (c *Collector) collectInventory(ctx context.Context, level componentsdk.Level, subscriptionID string, diagnostics *Diagnostics) (*AzureInventory, error) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil, nil
	}

	resources, err := c.arm.Resources(ctx, subscriptionID)
	if err == nil {
		return inventoryPosture(resources), nil
	}
	if surfaceUnavailable(err) {
		diagnostics.Warn("Azure resource inventory unavailable for subscription " + subscriptionID)
		return nil, nil
	}
	return nil, err
}

func inventoryPosture(resources []microsoft.ARMResource) *AzureInventory {
	out := &AzureInventory{
		ResourcesCount:   len(resources),
		TopResourceTypes: topResourceTypes(resources, 10),
	}
	if len(resources) == 0 {
		return out
	}

	resourceGroups := map[string]struct{}{}
	regions := map[string]struct{}{}
	ownerTagged := 0
	environmentTagged := 0
	productionResources := 0
	for _, resource := range resources {
		if resourceGroup := resourceGroupFromID(resource.ID); resourceGroup != "" {
			resourceGroups[strings.ToLower(resourceGroup)] = struct{}{}
		}
		if location := strings.TrimSpace(resource.Location); location != "" {
			regions[strings.ToLower(location)] = struct{}{}
		}
		if hasNormalizedTagKey(resource.Tags, ownerTagKeys) {
			ownerTagged++
		}
		envValue, hasEnvTag := normalizedTagValue(resource.Tags, environmentTagKeys)
		if hasEnvTag {
			environmentTagged++
			if envValue == "prod" || envValue == "production" {
				productionResources++
			}
		}
	}

	out.ResourceGroupsCount = len(resourceGroups)
	out.RegionsCount = len(regions)
	out.OwnerTagCoveragePct = PercentInt(ownerTagged, len(resources))
	out.EnvironmentTagCoveragePct = PercentInt(environmentTagged, len(resources))
	out.ProductionResourcesPct = PercentInt(productionResources, len(resources))
	return out
}

func topResourceTypes(resources []microsoft.ARMResource, limit int) []AzureResourceTypeCount {
	if limit <= 0 {
		return nil
	}
	counts := map[string]int{}
	for _, resource := range resources {
		resourceType := strings.TrimSpace(resource.Type)
		if resourceType == "" {
			continue
		}
		counts[resourceType]++
	}
	out := make([]AzureResourceTypeCount, 0, len(counts))
	for resourceType, count := range counts {
		out = append(out, AzureResourceTypeCount{Type: resourceType, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

func hasNormalizedTagKey(tags map[string]string, keys map[string]struct{}) bool {
	_, ok := normalizedTagValue(tags, keys)
	return ok
}

func normalizedTagValue(tags map[string]string, keys map[string]struct{}) (string, bool) {
	for key, value := range tags {
		if _, ok := keys[normalizedTagKey(key)]; ok {
			trimmed := strings.TrimSpace(value)
			return strings.ToLower(trimmed), trimmed != ""
		}
	}
	return "", false
}

func normalizedTagKey(key string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(key) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}
