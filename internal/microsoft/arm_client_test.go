package microsoft

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestARM(t *testing.T) {
	var roleCalls int
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer arm-token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		switch r.URL.Path {
		case "/subscriptions/sub-1":
			return jsonResponse(http.StatusOK, map[string]any{"subscriptionId": "sub-1", "state": "Enabled"}), nil
		case "/subscriptions/sub-1/resources":
			if got := r.URL.Query().Get("api-version"); got != "2021-04-01" {
				t.Fatalf("unexpected resources api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{"id": "resource-a", "type": "Microsoft.Storage/storageAccounts", "location": "eastus", "tags": map[string]string{"owner": "platform"}},
				},
			}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Security/secureScores/ascScore":
			if got := r.URL.Query().Get("api-version"); got != "2020-01-01" {
				t.Fatalf("unexpected secure score api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"name": "ascScore",
				"properties": map[string]any{
					"score": map[string]any{"current": 7.5, "max": 10, "percentage": 0.75},
				},
			}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			if got := r.URL.Query().Get("api-version"); got != "2022-04-01" {
				t.Fatalf("unexpected roleAssignments api-version: %s", got)
			}
			if r.URL.Query().Get("page") == "2" {
				return jsonResponse(http.StatusOK, map[string]any{
					"value": []map[string]any{{"id": "ra2"}},
				}), nil
			}
			if got := r.URL.Query().Get("$filter"); got != "atScope()" {
				t.Fatalf("unexpected roleAssignments filter: %s", got)
			}
			roleCalls++
			if roleCalls == 1 {
				return textResponse(http.StatusTooManyRequests, "retry", map[string]string{"Retry-After": "0"}), nil
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value":    []map[string]any{{"id": "ra1"}},
				"nextLink": "https://management.test/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&page=2",
			}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient), WithARMSleeper(func(context.Context, time.Duration) error { return nil }))
	subscription, err := client.Subscription(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if subscription.SubscriptionID != "sub-1" {
		t.Fatalf("unexpected subscription: %#v", subscription)
	}
	resources, err := client.Resources(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].Type != "Microsoft.Storage/storageAccounts" {
		t.Fatalf("unexpected resources: %#v", resources)
	}
	score, err := client.DefenderSecureScore(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if score.Properties.Score.Percentage != 0.75 {
		t.Fatalf("unexpected secure score: %#v", score)
	}
	assignments, err := client.RoleAssignments(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 2 {
		t.Fatalf("expected two assignments, got %d", len(assignments))
	}
	if roleCalls != 2 {
		t.Fatalf("expected retry, got %d calls", roleCalls)
	}
}

func TestARMClientRejectsCrossOriginNextLink(t *testing.T) {
	var calls int
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatalf("unexpected request to %s", r.URL.String())
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"value":    []map[string]any{{"id": "ra1"}},
			"nextLink": "https://evil.test/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments?page=2",
		}), nil
	})}

	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	_, err := client.RoleAssignments(context.Background(), "sub-1")
	if err == nil {
		t.Fatal("expected cross-origin nextLink to be rejected")
	}
	if strings.Contains(err.Error(), "evil.test") {
		t.Fatalf("expected sanitized nextLink error, got %s", err)
	}
	if !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestARMError(t *testing.T) {
	err := armAPIError(http.StatusForbidden, "/subscriptions/sub-1", []byte(`{"error":{"code":"AuthorizationFailed","message":"denied"}}`))
	if err.Service != "arm" || err.Code != "AuthorizationFailed" || !strings.Contains(err.Error(), "arm request") {
		t.Fatalf("unexpected ARM error: %#v message=%s", err, err.Error())
	}
}

func TestARMErrorRedactsResourceIdentifiers(t *testing.T) {
	err := armAPIError(
		http.StatusInternalServerError,
		"/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/sql-a/databases/appdb/transparentDataEncryption/current?api-version=2023-08-01",
		[]byte(`{"error":{"code":"InternalServerError","message":"failed scope /subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/sql-a/databases/appdb with bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ"}}`),
	)

	message := err.Error()
	for _, forbidden := range []string{"sub-1", "prod-rg", "sql-a", "appdb", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("expected sanitized error, got %s", message)
		}
	}
	for _, expected := range []string{"[subscription_id]", "[resource_group]", "[servers]", "[databases]", "[REDACTED_JWT]"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("expected %s in sanitized error, got %s", expected, message)
		}
	}
}

func TestARMResourceIDParseErrorsAreSanitized(t *testing.T) {
	_, _, _, sqlErr := sqlServerIDParts("/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Sql/notServers/sql-a")
	if sqlErr == nil {
		t.Fatal("expected SQL server ID parse error")
	}
	assertNoRawResourceIdentifiers(t, sqlErr.Error())

	_, vaultErr := recoveryServicesVaultRoute("/subscriptions/sub-1/resourceGroups/backup-rg/providers/Microsoft.RecoveryServices/notVaults/vault-a", "backupJobs", nil)
	if vaultErr == nil {
		t.Fatal("expected Recovery Services vault ID parse error")
	}
	assertNoRawResourceIdentifiers(t, vaultErr.Error())
}

func assertNoRawResourceIdentifiers(t *testing.T, message string) {
	t.Helper()
	for _, forbidden := range []string{"sub-1", "prod-rg", "backup-rg", "sql-a", "vault-a"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("expected sanitized resource ID error, got %s", message)
		}
	}
	for _, expected := range []string{"[subscription_id]", "[resource_group]"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("expected %s in sanitized error, got %s", expected, message)
		}
	}
}

func TestARMDataProtectionRoutes(t *testing.T) {
	vaultID := "/subscriptions/sub-1/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a"
	serverID := "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a"
	databaseID := serverID + "/databases/appdb"
	calls := map[string]int{}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Host, "vault.azure.net") {
			t.Fatalf("unexpected data-plane host: %s", r.URL.Host)
		}
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts":
			if got := r.URL.Query().Get("api-version"); got != "2024-01-01" {
				t.Fatalf("unexpected storage api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "storage-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults":
			if got := r.URL.Query().Get("api-version"); got != "2024-11-01" {
				t.Fatalf("unexpected key vault api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "kv-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Sql/servers":
			if got := r.URL.Query().Get("api-version"); got != "2023-08-01" {
				t.Fatalf("unexpected sql server api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": serverID}}}), nil
		case "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a/databases":
			if got := r.URL.Query().Get("api-version"); got != "2023-08-01" {
				t.Fatalf("unexpected sql database api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": databaseID}}}), nil
		case "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Sql/servers/sql-a/databases/appdb/transparentDataEncryption/current":
			return jsonResponse(http.StatusOK, map[string]any{"properties": map[string]any{"state": "Enabled"}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines":
			if got := r.URL.Query().Get("api-version"); got != "2024-07-01" {
				t.Fatalf("unexpected compute api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "vm-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Network/publicIPAddresses":
			if got := r.URL.Query().Get("api-version"); got != "2023-11-01" {
				t.Fatalf("unexpected public IP api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "pip-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.RecoveryServices/vaults":
			if got := r.URL.Query().Get("api-version"); got != "2026-01-01" {
				t.Fatalf("unexpected vault api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": vaultID}}}), nil
		case "/subscriptions/sub-1/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a/backupProtectedItems":
			if got := r.URL.Query().Get("api-version"); got != "2026-01-01" {
				t.Fatalf("unexpected protected item api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "item-a"}}}), nil
		case "/subscriptions/sub-1/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a/backupPolicies":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "policy-a"}}}), nil
		case "/subscriptions/sub-1/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a/backupJobs":
			if got := r.URL.Query().Get("$filter"); got != "operation eq 'Backup'" {
				t.Fatalf("unexpected backup jobs filter: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "job-a"}}}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	if _, err := client.StorageAccounts(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.KeyVaults(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SQLServers(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SQLDatabases(context.Background(), serverID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SQLTransparentDataEncryption(context.Background(), databaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VirtualMachines(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PublicIPAddresses(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RecoveryServicesVaults(context.Background(), "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.BackupProtectedItems(context.Background(), vaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.BackupPolicies(context.Background(), vaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.BackupJobs(context.Background(), vaultID, "operation eq 'Backup'"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 11 {
		t.Fatalf("expected 11 ARM data protection routes, got %d: %#v", len(calls), calls)
	}
}

func TestARMGovernanceRoutes(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Security/assessments":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected assessments method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2020-01-01" {
				t.Fatalf("unexpected assessments api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "assessment-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected policy assignments method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2023-04-01" {
				t.Fatalf("unexpected policy assignments api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "assignment-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.PolicyInsights/policyStates/latest/summarize":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected policy summary method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2019-10-01" {
				t.Fatalf("unexpected policy summary api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{
						"results": map[string]any{
							"resourceDetails": []map[string]any{
								{"complianceState": "compliant", "count": 3},
								{"complianceState": "noncompliant", "count": 1},
							},
						},
					},
				},
			}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	assessments, err := client.DefenderAssessments(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assessments) != 1 {
		t.Fatalf("expected one assessment, got %d", len(assessments))
	}
	assignments, err := client.PolicyAssignments(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 {
		t.Fatalf("expected one assignment, got %d", len(assignments))
	}
	summary, err := client.PolicyStateSummary(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Value) != 1 {
		t.Fatalf("expected one policy summary, got %#v", summary)
	}
}

func TestARMMonitoringNetworkRoutes(t *testing.T) {
	resourceID := "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea"
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Network/networkSecurityGroups":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected NSG method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2023-11-01" {
				t.Fatalf("unexpected NSG api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "nsg-a"}}}), nil
		case "/subscriptions/sub-1/providers/Microsoft.Insights/diagnosticSettings":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected subscription diagnostics method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2021-05-01-preview" {
				t.Fatalf("unexpected subscription diagnostics api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{
				"id": "subdiag-a",
				"properties": map[string]any{
					"workspaceId": "law-a",
					"logs":        []map[string]any{{"category": "Administrative", "enabled": true}},
				},
			}}}), nil
		case "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/storagea/providers/Microsoft.Insights/diagnosticSettings":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected resource diagnostics method: %s", r.Method)
			}
			if got := r.URL.Query().Get("api-version"); got != "2021-05-01-preview" {
				t.Fatalf("unexpected resource diagnostics api-version: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "diag-a"}}}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	nsgs, err := client.NetworkSecurityGroups(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nsgs) != 1 {
		t.Fatalf("expected one NSG, got %d", len(nsgs))
	}
	subscriptionSettings, err := client.SubscriptionDiagnosticSettings(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(subscriptionSettings) != 1 {
		t.Fatalf("expected one subscription diagnostic setting, got %d", len(subscriptionSettings))
	}
	if logs := subscriptionSettings[0].Properties.Logs; len(logs) != 1 || logs[0].Category != "Administrative" || !logs[0].Enabled {
		t.Fatalf("unexpected subscription diagnostic logs: %#v", logs)
	}
	settings, err := client.DiagnosticSettings(context.Background(), resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings) != 1 {
		t.Fatalf("expected one resource diagnostic setting, got %d", len(settings))
	}
}
