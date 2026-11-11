package collector

import (
	"fmt"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// The Azure side of the simulator answers Resource Manager's role
// assignments, network security groups, and storage accounts for the
// roster's one subscription, in the shapes the REST reference gives, and
// the kit's empty answers for everything else.
//
// The roster's vendor extras give each Azure role's ID
// (cloud_role_ids) and where an account or group holds a role over the
// whole subscription (cloud_role_scopes, by role: subscription, the default,
// or management_group). An account's partial cloud roles are on a resource
// group. A security group or storage account extra named render
// lists equivalent ways to show it, and a storage account's extras give the
// settings the normalized values don't read.

const simResourceGroup = "/subscriptions/" + kitSubscriptionID + "/resourceGroups/rg-epack-sandbox"

func (s *entraSim) azure() []collectortest.Response {
	subscription := "/subscriptions/" + kitSubscriptionID
	provider := func(path, apiVersion string) string {
		return kitARMBase + subscription + "/providers/" + path + "?api-version=" + apiVersion
	}
	nsgURL := provider("Microsoft.Network/networkSecurityGroups", "2023-11-01")
	storageURL := provider("Microsoft.Storage/storageAccounts", "2024-01-01")
	out := slices.DeleteFunc(kitARMResponses(&fakeARM{
		subscriptions: map[string]*microsoft.Subscription{kitSubscriptionID: {SubscriptionID: kitSubscriptionID, State: "Enabled"}},
		secureScores:  map[string]*microsoft.ARMSecureScore{kitSubscriptionID: {Name: "ascScore"}},
	}), func(r collectortest.Response) bool {
		return r.URL == kitRoleAssignmentsURL || r.URL == nsgURL || r.URL == storageURL
	})
	out = append(out,
		collectortest.Response{URL: kitRoleAssignmentsURL, Body: armList(s.cloudRoleAssignments())},
		collectortest.Response{URL: nsgURL, Body: armList(s.securityGroups())},
	)
	var accounts []any
	for _, st := range s.r.Storage {
		account := s.storageAccount(st)
		accounts = append(accounts, account)
		id := account["id"].(string)
		for _, resource := range append([]string{id}, storageServiceIDs(id)...) {
			out = append(out, collectortest.Response{URL: kitARMBase + resource + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", Body: armList(nil)})
		}
	}
	return append(out, collectortest.Response{URL: storageURL, Body: armList(accounts)})
}

func storageServiceIDs(account string) []string {
	var out []string
	for _, service := range storageServices {
		out = append(out, account+"/"+service+"/default")
	}
	return out
}

func armList(items []any) string {
	if items == nil {
		items = []any{}
	}
	return kitJSON(map[string]any{"value": items})
}

// cloudRoleAssignments lists the assignments that apply to the
// subscription, as the list does without a filter: those on it, above it,
// and on its resource groups.
// https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription
func (s *entraSim) cloudRoleAssignments() []any {
	var roleIDs map[string]string
	if _, err := s.r.Extra.Get("cloud_role_ids", &roleIDs); err != nil {
		panic(err)
	}
	var items []any
	assign := func(principal, principalType string, roles []string, extra roster.Extra, partial bool) {
		scopes := map[string]string{}
		if _, err := extra.Get("cloud_role_scopes", &scopes); err != nil {
			panic(err)
		}
		for _, role := range roles {
			if roleIDs[role] == "" {
				panic("entraSim: cloud_role_ids has no ID for " + role)
			}
			var scope string
			switch {
			case partial:
				scope = simResourceGroup
			case scopes[role] == "" || scopes[role] == "subscription":
				scope = "/subscriptions/" + kitSubscriptionID
			case scopes[role] == "management_group":
				scope = "/providers/Microsoft.Management/managementGroups/" + kitTenantID
			default:
				panic("entraSim: no scope " + scopes[role])
			}
			name := simID("cloud-assignment", principal+role)
			items = append(items, map[string]any{
				"id": scope + "/providers/Microsoft.Authorization/roleAssignments/" + name, "name": name, "type": "Microsoft.Authorization/roleAssignments",
				"properties": map[string]any{
					"roleDefinitionId": "/subscriptions/" + kitSubscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + roleIDs[role],
					"principalId":      principal, "principalType": principalType, "scope": scope,
					"condition": nil, "conditionVersion": nil, "description": nil, "delegatedManagedIdentityResourceId": nil,
					"createdOn": "2026-03-01T00:00:00Z", "updatedOn": "2026-03-01T00:00:00Z",
					"createdBy": simID("user", "creator"), "updatedBy": simID("user", "creator"),
				},
			})
		}
	}
	for _, a := range s.r.Accounts {
		assign(simID("user", a.Key), "User", a.CloudRoles, a.Extra, false)
		assign(simID("user", a.Key), "User", a.PartialCloudRoles, a.Extra, true)
	}
	for _, g := range s.r.Groups {
		assign(simID("group", g.Key), "Group", g.CloudRoles, g.Extra, false)
	}
	return items
}

// simDefaultRules are the rules Azure puts in every network security group.
var simDefaultRules = []struct {
	name, direction, access, source string
	priority                        int
}{
	{"AllowVnetInBound", "Inbound", "Allow", "VirtualNetwork", 65000},
	{"AllowAzureLoadBalancerInBound", "Inbound", "Allow", "AzureLoadBalancer", 65001},
	{"DenyAllInBound", "Inbound", "Deny", "*", 65500},
	{"AllowVnetOutBound", "Outbound", "Allow", "VirtualNetwork", 65000},
	{"AllowInternetOutBound", "Outbound", "Allow", "*", 65001},
	{"DenyAllOutBound", "Outbound", "Deny", "*", 65500},
}

// securityGroups renders each security group as a networkSecurityGroup. A
// rule with one port or source uses the single property, and one with more
// the list, unless the group's render extra holds lists, which puts even
// one in the list.
// https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all
func (s *entraSim) securityGroups() []any {
	var items []any
	for _, g := range s.r.SecurityGroups {
		var renderings []string
		if _, err := g.Extra.Get("render", &renderings); err != nil {
			panic(err)
		}
		lists := slices.Contains(renderings, "lists")
		id := simResourceGroup + "/providers/Microsoft.Network/networkSecurityGroups/nsg-" + g.Key
		rule := func(name, direction, access, protocol string, ports, sources []string, priority int, kind string) map[string]any {
			props := map[string]any{
				"provisioningState": "Succeeded", "protocol": protocol, "sourcePortRange": "*", "destinationAddressPrefix": "*",
				"access": access, "priority": priority, "direction": direction,
				"sourcePortRanges": []string{}, "destinationPortRanges": []string{}, "sourceAddressPrefixes": []string{}, "destinationAddressPrefixes": []string{},
			}
			if len(ports) == 1 && !lists {
				props["destinationPortRange"] = ports[0]
			} else {
				props["destinationPortRanges"] = ports
			}
			if len(sources) == 1 && !lists {
				props["sourceAddressPrefix"] = sources[0]
			} else {
				props["sourceAddressPrefixes"] = sources
			}
			return map[string]any{
				"id": id + "/" + kind + "/" + name, "name": name, "etag": `W/"` + simID("etag", g.Key+name) + `"`,
				"type": "Microsoft.Network/networkSecurityGroups/" + kind, "properties": props,
			}
		}
		var rules, defaults []any
		for i, r := range g.Rules {
			priority := r.Priority
			if priority == 0 {
				priority = 100 + 10*i
			}
			rules = append(rules, rule(r.Key, strings.ToUpper(r.Direction[:1])+r.Direction[1:], strings.ToUpper(r.Access[:1])+r.Access[1:], r.Protocol, r.Ports, r.Sources, priority, "securityRules"))
		}
		for _, d := range simDefaultRules {
			defaults = append(defaults, rule(d.name, d.direction, d.access, "*", []string{"*"}, []string{d.source}, d.priority, "defaultSecurityRules"))
		}
		items = append(items, map[string]any{
			"id": id, "name": "nsg-" + g.Key, "type": "Microsoft.Network/networkSecurityGroups", "location": "eastus2",
			"etag": `W/"` + simID("etag", g.Key) + `"`, "tags": map[string]string{"environment": "sandbox"},
			"properties": map[string]any{
				"provisioningState": "Succeeded", "resourceGuid": simID("nsg", g.Key),
				"securityRules": append([]any{}, rules...), "defaultSecurityRules": defaults,
			},
		})
	}
	return items
}

// storageAccount renders a storage account. Anonymous access shows as
// allowBlobPublicAccess true, or as the property left out when the render
// extra holds unset, which Microsoft treats the same way. The extras
// https_only, public_network_access, and infrastructure_encryption give the
// settings no derived value reads.
// https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list
func (s *entraSim) storageAccount(st roster.Storage) map[string]any {
	var renderings []string
	httpsOnly, infrastructure, network := true, false, "Enabled"
	for name, v := range map[string]any{"render": &renderings, "https_only": &httpsOnly, "infrastructure_encryption": &infrastructure, "public_network_access": &network} {
		if _, err := st.Extra.Get(name, v); err != nil {
			panic(err)
		}
	}
	name := strings.ReplaceAll("st"+st.Key, "_", "")
	id := simResourceGroup + "/providers/Microsoft.Storage/storageAccounts/" + name
	service := map[string]any{"enabled": true, "keyType": "Account", "lastEnabledTime": "2026-03-01T00:00:00Z"}
	encryption := map[string]any{
		"keySource": st.KeySource, "requireInfrastructureEncryption": infrastructure,
		"services": map[string]any{"blob": service, "file": service},
	}
	if s.r.Terms.KeySources[st.KeySource] == roster.CustomerKey {
		encryption["keyvaultproperties"] = map[string]any{"keyname": "storage", "keyvaulturi": "https://kv-rbac.vault.azure.net/", "keyversion": ""}
		encryption["identity"] = map[string]any{"userAssignedIdentity": simResourceGroup + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-storage-cmk"}
	}
	props := map[string]any{
		"provisioningState": "Succeeded", "creationTime": "2026-03-01T00:00:00Z", "supportsHttpsTrafficOnly": httpsOnly,
		"minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": st.AnonymousAccess, "allowSharedKeyAccess": true,
		"publicNetworkAccess": network, "encryption": encryption, "accessTier": "Hot",
		"networkAcls":      map[string]any{"bypass": "AzureServices", "defaultAction": "Allow", "ipRules": []any{}, "virtualNetworkRules": []any{}},
		"primaryEndpoints": map[string]any{"blob": fmt.Sprintf("https://%s.blob.core.windows.net/", name)},
	}
	if slices.Contains(renderings, "unset") {
		if !st.AnonymousAccess {
			panic("entraSim: storage " + st.Key + " leaves allowBlobPublicAccess unset, which allows anonymous access")
		}
		delete(props, "allowBlobPublicAccess")
	}
	return map[string]any{
		"id": id, "name": name, "type": "Microsoft.Storage/storageAccounts", "location": "eastus2", "kind": "StorageV2",
		"sku": map[string]any{"name": "Standard_LRS", "tier": "Standard"}, "tags": map[string]string{"environment": "sandbox"},
		"properties": props,
	}
}
