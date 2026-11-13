package microsoft

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestLackingNamesTheFirstMissingField(t *testing.T) {
	item := json.RawMessage(`{"id": "a", "enabled": false, "count": 0, "empty": "", "none": null, "list": [{"id": "x"}, {"id": ""}], "nolist": []}`)
	for paths, want := range map[string]string{
		"id enabled count":      "",
		"id empty":              "empty",
		"none":                  "none",
		"absent":                "absent",
		"list":                  "",
		"list/*/id":             "list/*/id",
		"nolist/*/id":           "",
		"absent/*/id":           "",
		"none/*/id":             "",
		"id/*/id":               "id/*/id",
		"enabled absent/nested": "absent/nested",
	} {
		if got := lacking(item, strings.Fields(paths)); got != want {
			t.Errorf("lacking(%q) = %q, want %q", paths, got, want)
		}
	}
}

// TestListsRejectItemsTheyCannotRead checks that an answer missing a field
// Microsoft always sends, or breaking a rule Microsoft's own objects meet,
// is an invalid response rather than a list the collector would read as
// holding no such thing.
func TestListsRejectItemsTheyCannotRead(t *testing.T) {
	graph := func(body string) *GraphClient {
		return NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(answering(body)))
	}
	arm := func(body string) *ARMClient {
		return NewARMClient(StaticTokenSource("token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(answering(body)))
	}
	ctx := context.Background()
	const serverID = "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a"
	policy := func(conditions, grant string) string {
		return `{"value": [{"id": "p1", "state": "enabled", "conditions": ` + conditions + `, "grantControls": ` + grant + `}]}`
	}
	allApps := `"applications": {"includeApplications": ["All"]}`
	sp := func(credentials string) string {
		return `{"value": [{"id": "sp1", "appId": "a1", "accountEnabled": true, "appRoleAssignmentRequired": false, ` + credentials + `}]}`
	}
	vm := func(properties string) string { return `{"value": [{"id": "vm-a", "properties": ` + properties + `}]}` }
	nic := `"networkProfile": {"networkInterfaces": [{"id": "nic-a"}]}`
	rule := func(properties string) string {
		return `{"value": [{"id": "nsg-a", "properties": {"securityRules": [{"properties": {"priority": 100, "access": "Allow", "direction": "Inbound", "protocol": "Tcp", ` + properties + `}}]}}]}`
	}
	summary := func(summaries string) string { return `{"@odata.count": 1, "value": [` + summaries + `]}` }
	results := func(noncompliant int) string {
		b, _ := json.Marshal(map[string]any{"results": map[string]any{"nonCompliantResources": noncompliant,
			"resourceDetails": []map[string]any{{"complianceState": "compliant", "count": 3}, {"complianceState": "noncompliant", "count": 1}}}})
		return string(b)
	}
	for name, tc := range map[string]struct {
		read  func() error
		valid bool
	}{
		"a user with no accountEnabled": {read: func() error { _, err := graph(`{"value": [{"id": "u1"}]}`).Users(ctx); return err }},
		"no service principals": {read: func() error {
			_, err := graph(`{"value": []}`).ServicePrincipals(ctx)
			return err
		}},
		"a secret with no startDateTime": {read: func() error {
			_, err := graph(sp(`"passwordCredentials": [{"endDateTime": "2027-01-01T00:00:00Z"}], "keyCredentials": []`)).ServicePrincipals(ctx)
			return err
		}},
		"a secret with no endDateTime": {valid: true, read: func() error {
			_, err := graph(sp(`"passwordCredentials": [{"startDateTime": "2026-01-01T00:00:00Z"}], "keyCredentials": []`)).ServicePrincipals(ctx)
			return err
		}},
		"a certificate with no endDateTime": {read: func() error {
			_, err := graph(sp(`"passwordCredentials": [], "keyCredentials": [{"startDateTime": "2026-01-01T00:00:00Z"}]`)).ServicePrincipals(ctx)
			return err
		}},
		"a service principal with no keyCredentials": {read: func() error {
			_, err := graph(sp(`"passwordCredentials": []`)).ServicePrincipals(ctx)
			return err
		}},
		"a policy with no includeUsers": {read: func() error {
			_, err := graph(policy(`{`+allApps+`, "users": {"includeGroups": ["g1"]}}`, `{"builtInControls": ["mfa"]}`)).ConditionalAccessPolicies(ctx)
			return err
		}},
		"a policy with neither users nor clientApplications": {read: func() error {
			_, err := graph(policy(`{`+allApps+`}`, `{"builtInControls": ["mfa"]}`)).ConditionalAccessPolicies(ctx)
			return err
		}},
		"a policy for workload identities": {valid: true, read: func() error {
			_, err := graph(policy(`{`+allApps+`, "clientApplications": {"includeServicePrincipals": ["All"]}}`, `{"builtInControls": ["block"]}`)).ConditionalAccessPolicies(ctx)
			return err
		}},
		"grant controls with no builtInControls": {read: func() error {
			_, err := graph(policy(`{`+allApps+`, "users": {"includeUsers": ["All"]}}`, `{"operator": "OR"}`)).ConditionalAccessPolicies(ctx)
			return err
		}},
		"a policy with session controls alone": {valid: true, read: func() error {
			_, err := graph(policy(`{`+allApps+`, "users": {"includeUsers": ["All"]}}`, `null`)).ConditionalAccessPolicies(ctx)
			return err
		}},
		"a role permission with no actions": {read: func() error {
			_, err := graph(`{"value": [{"id": "r1", "rolePermissions": [{"allowedResourceActions": null}]}]}`).RoleDefinitions(ctx)
			return err
		}},
		"a role assignment with no principalType": {read: func() error {
			_, err := arm(`{"value": [{"id": "ra1", "properties": {"roleDefinitionId": "r", "principalId": "p", "scope": "/subscriptions/sub-1"}}]}`).RoleAssignments(ctx, "sub-1")
			return err
		}},
		"no master database": {read: func() error {
			_, err := arm(`{"value": [{"id": "`+serverID+`/databases/appdb", "name": "appdb"}]}`).SQLDatabases(ctx, serverID)
			return err
		}},
		"two policy summaries": {read: func() error {
			_, err := arm(summary(results(1)+","+results(1))).PolicyStateSummary(ctx, "sub-1")
			return err
		}},
		"a summary whose counts disagree": {read: func() error { _, err := arm(summary(results(2))).PolicyStateSummary(ctx, "sub-1"); return err }},
		"a summary whose counts agree":    {valid: true, read: func() error { _, err := arm(summary(results(1))).PolicyStateSummary(ctx, "sub-1"); return err }},
		"a virtual machine with no network interface": {read: func() error {
			_, err := arm(vm(`{"storageProfile": {"osDisk": {"managedDisk": {"id": "d"}}}, "networkProfile": {"networkInterfaces": []}}`)).VirtualMachines(ctx, "sub-1")
			return err
		}},
		"a disk that is neither managed nor a VHD": {read: func() error {
			_, err := arm(vm(`{"storageProfile": {"osDisk": {}}, `+nic+`}`)).VirtualMachines(ctx, "sub-1")
			return err
		}},
		"an unmanaged disk": {valid: true, read: func() error {
			_, err := arm(vm(`{"storageProfile": {"osDisk": {"vhd": {"uri": "https://a.blob.core.windows.net/vhds/os.vhd"}}}, `+nic+`}`)).VirtualMachines(ctx, "sub-1")
			return err
		}},
		"a security rule with no source": {read: func() error {
			_, err := arm(rule(`"destinationPortRange": "22"`)).NetworkSecurityGroups(ctx, "sub-1")
			return err
		}},
		"a security rule from application security groups": {valid: true, read: func() error {
			_, err := arm(rule(`"sourceApplicationSecurityGroups": [{"id": "asg-a"}], "destinationPortRanges": ["22", "3389"]`)).NetworkSecurityGroups(ctx, "sub-1")
			return err
		}},
		"a security rule with no destination ports": {read: func() error {
			_, err := arm(rule(`"sourceAddressPrefix": "*"`)).NetworkSecurityGroups(ctx, "sub-1")
			return err
		}},
		"an attached public IP with no configuration ID": {read: func() error {
			_, err := arm(`{"value": [{"id": "pip-a", "properties": {"ipConfiguration": {}}}]}`).PublicIPAddresses(ctx, "sub-1")
			return err
		}},
		"a log setting with neither category nor group": {read: func() error {
			_, err := arm(`{"value": [{"id": "d", "properties": {"logs": [{"enabled": true}]}}]}`).DiagnosticSettings(ctx, "/subscriptions/sub-1")
			return err
		}},
		"a log setting with no enabled": {read: func() error {
			_, err := arm(`{"value": [{"id": "d", "properties": {"logs": [{"category": "Administrative"}]}}]}`).SubscriptionDiagnosticSettings(ctx, "sub-1")
			return err
		}},
		"a protected VM with no sourceResourceId": {read: func() error {
			_, err := arm(`{"value": [{"id": "i", "properties": {"backupManagementType": "AzureIaasVM", "protectionState": "Protected", "policyId": "p"}}]}`).BackupProtectedItems(ctx, "/subscriptions/sub-1/resourceGroups/b/providers/Microsoft.RecoveryServices/vaults/v")
			return err
		}},
		"an agent's item with no sourceResourceId": {valid: true, read: func() error {
			_, err := arm(`{"value": [{"id": "i", "properties": {"backupManagementType": "MAB", "protectionState": "Protected", "policyId": "p"}}]}`).BackupProtectedItems(ctx, "/subscriptions/sub-1/resourceGroups/b/providers/Microsoft.RecoveryServices/vaults/v")
			return err
		}},
		"a finished backup job with no endTime": {read: func() error {
			_, err := arm(`{"value": [{"id": "j", "properties": {"status": "Failed", "startTime": "2026-05-24T14:12:09Z"}}]}`).BackupJobs(ctx, "/subscriptions/sub-1/resourceGroups/b/providers/Microsoft.RecoveryServices/vaults/v", "")
			return err
		}},
		"a backup job in progress": {valid: true, read: func() error {
			_, err := arm(`{"value": [{"id": "j", "properties": {"status": "InProgress", "startTime": "2026-05-24T14:12:09Z"}}]}`).BackupJobs(ctx, "/subscriptions/sub-1/resourceGroups/b/providers/Microsoft.RecoveryServices/vaults/v", "")
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.read()
			switch {
			case tc.valid && err != nil:
				t.Errorf("read with error %v, want it read", err)
			case !tc.valid && componentsdk.Classify(err) != componentsdk.CodeInvalidResponse:
				t.Errorf("read with error %v, coded %q, want invalid_response", err, componentsdk.Classify(err))
			}
		})
	}
}

// answering is a client whose every request gets body.
func answering(body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, body, map[string]string{"Content-Type": "application/json"}), nil
	})}
}
