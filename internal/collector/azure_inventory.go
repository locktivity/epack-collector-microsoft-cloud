package collector

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// ownerTagKeys and environmentTagKeys are the normalized tag keys for a
// resource's owner and environment, in the order they are read.
var (
	ownerTagKeys       = []string{"owner", "applicationowner", "businessowner", "serviceowner", "contact", "managedby"}
	environmentTagKeys = []string{"environment", "env", "stage"}
)

func (c *Collector) collectInventory(ctx context.Context, level componentsdk.Level, scope subscriptionScope, diagnostics *Diagnostics) *AzureInventory {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	resources, err := c.arm.Resources(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Azure resource inventory", scope.name, err)
		c.gaps.leaveOut(azurePath, failed(err), scope.pointer("inventory"))
		return nil
	}
	return inventoryPosture(resources)
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
		// Resources such as DNS zones have the location global, which is not
		// a region.
		if location := strings.ToLower(strings.TrimSpace(resource.Location)); location != "" && location != "global" {
			regions[location] = struct{}{}
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

func hasNormalizedTagKey(tags map[string]string, keys []string) bool {
	_, ok := normalizedTagValue(tags, keys)
	return ok
}

// normalizedTagValue returns the lowercased value of the first nonempty tag
// whose key is one of keys, taking keys in order. Empty tags are skipped.
// The result does not depend on map order.
func normalizedTagValue(tags map[string]string, keys []string) (string, bool) {
	tagKeys := slices.Sorted(maps.Keys(tags))
	for _, want := range keys {
		for _, key := range tagKeys {
			if normalizedTagKey(key) != want {
				continue
			}
			if value := strings.TrimSpace(tags[key]); value != "" {
				return strings.ToLower(value), true
			}
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
