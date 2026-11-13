package microsoft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const DefaultARMBaseURL = "https://management.azure.com"

type ARMClient struct {
	baseURL     string
	tokenSource AccessTokenSource
	httpClient  *http.Client
}

type ARMOption func(*ARMClient)

func WithARMBaseURL(baseURL string) ARMOption {
	return func(c *ARMClient) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func WithARMHTTPClient(client *http.Client) ARMOption {
	return func(c *ARMClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func NewARMClient(tokenSource AccessTokenSource, opts ...ARMOption) *ARMClient {
	c := &ARMClient{
		baseURL:     DefaultARMBaseURL,
		tokenSource: tokenSource,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *ARMClient) Subscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "?api-version=2020-01-01"
	var subscription Subscription
	if _, err := c.getJSON(ctx, armOperation("arm.subscriptions.get"), route, &subscription); err != nil {
		return nil, err
	}
	if subscription.SubscriptionID == "" {
		return nil, invalidResponse("arm", route, "has no subscriptionId")
	}
	return &subscription, nil
}

func (c *ARMClient) Resources(ctx context.Context, subscriptionID string) ([]ARMResource, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/resources?api-version=2021-04-01"
	return getARMPaged[ARMResource](ctx, c, "arm.resources.list", route, "id", "type", "location")
}

func (c *ARMClient) DefenderSecureScore(ctx context.Context, subscriptionID string) (*ARMSecureScore, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
	var score struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Properties struct {
			Score *ARMScore `json:"score"`
		} `json:"properties"`
	}
	if _, err := c.getJSON(ctx, armOperation("arm.defender.secure_score.get"), route, &score); err != nil {
		return nil, err
	}
	if score.Properties.Score == nil {
		return nil, invalidResponse("arm", route, "has no score")
	}
	return &ARMSecureScore{ID: score.ID, Name: score.Name, Properties: ARMSecureScoreProperties{Score: *score.Properties.Score}}, nil
}

func (c *ARMClient) DefenderAssessments(ctx context.Context, subscriptionID string) ([]SecurityAssessment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Security/assessments?api-version=2020-01-01"
	return getARMPaged[SecurityAssessment](ctx, c, "arm.defender.assessments.list", route, "properties/status/code")
}

// RoleAssignments lists the role assignments that apply to a subscription:
// those at the subscription, above it, and on its resource groups and
// resources. Each one's scope says where it is. An empty list means the
// identity can see no role assignment, even the one that lets it read the
// subscription. An identity whose access comes through Azure Lighthouse sees
// that: the list leaves out Lighthouse's role assignments, and shows an
// identity in the managing tenant none of the customer's.
// https://learn.microsoft.com/en-us/azure/lighthouse/how-to/view-manage-service-providers#view-delegations
func (c *ARMClient) RoleAssignments(ctx context.Context, subscriptionID string) ([]ARMRoleAssignment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
	assignments, resp, err := getARMPages[ARMRoleAssignment](ctx, c, "arm.role_assignments.list", route,
		[]string{"properties/roleDefinitionId", "properties/principalId", "properties/principalType", "properties/scope"})
	if err != nil {
		return nil, err
	}
	if len(assignments) == 0 {
		return nil, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodePermissionDenied,
			fmt.Errorf("arm response for %s lists no role assignment, so the identity can see none, as when its access comes through Azure Lighthouse", SanitizeRoute(route))))
	}
	return assignments, nil
}

func (c *ARMClient) PolicyAssignments(ctx context.Context, subscriptionID string) ([]PolicyAssignment, error) {
	// With atScope(), the list has the assignments that apply to the
	// subscription. Assignments on resource groups or resources inside it are
	// left out.
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01&$filter=atScope%28%29"
	return getARMPaged[PolicyAssignment](ctx, c, "arm.policy.assignments.list", route)
}

func (c *ARMClient) PolicyStateSummary(ctx context.Context, subscriptionID string) (*PolicyStateSummaryResult, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
	var summary struct {
		Value *[]json.RawMessage `json:"value"`
	}
	resp, err := c.postJSON(ctx, componentsdk.Operation{Name: "arm.policy.states.summarize", Safe: true, Permission: armReaderRole}, route, nil, &summary)
	if err != nil {
		return nil, err
	}
	// The answer holds one summary, which @odata.count says is always so.
	// https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/summarize-for-subscription
	if summary.Value == nil || len(*summary.Value) != 1 {
		return nil, componentsdk.ResponseError(resp, invalidResponse("arm", route, "does not hold one summary"))
	}
	summaries, problem, err := decodeItems[PolicyStateSummary](*summary.Value, []string{
		"results/nonCompliantResources", "results/resourceDetails",
		"results/resourceDetails/*/complianceState", "results/resourceDetails/*/count",
	})
	switch {
	case err != nil:
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding arm response for %s: %w", SanitizeRoute(route), err))
	case problem != "":
		return nil, componentsdk.ResponseError(resp, invalidResponse("arm", route, problem))
	}
	return &PolicyStateSummaryResult{Value: summaries}, nil
}

func (c *ARMClient) StorageAccounts(ctx context.Context, subscriptionID string) ([]StorageAccount, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Storage/storageAccounts?api-version=2024-01-01"
	return getARMPaged[StorageAccount](ctx, c, "arm.storage.accounts.list", route, "id", "properties/supportsHttpsTrafficOnly")
}

func (c *ARMClient) KeyVaults(ctx context.Context, subscriptionID string) ([]KeyVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01"
	return getARMPaged[KeyVault](ctx, c, "arm.keyvault.vaults.list", route, "id")
}

func (c *ARMClient) SQLServers(ctx context.Context, subscriptionID string) ([]SQLServer, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Sql/servers?api-version=2023-08-01"
	return getARMPaged[SQLServer](ctx, c, "arm.sql.servers.list", route, "id", "properties/publicNetworkAccess")
}

func (c *ARMClient) SQLDatabases(ctx context.Context, serverID string) ([]SQLDatabase, error) {
	subscriptionID, resourceGroup, serverName, err := sqlServerIDParts(serverID)
	if err != nil {
		return nil, err
	}
	route := "/subscriptions/" + url.PathEscape(subscriptionID) +
		"/resourceGroups/" + url.PathEscape(resourceGroup) +
		"/providers/Microsoft.Sql/servers/" + url.PathEscape(serverName) +
		"/databases?api-version=2023-08-01"
	databases, resp, err := getARMPages[SQLDatabase](ctx, c, "arm.sql.databases.list", route, []string{"id", "name"})
	if err != nil {
		return nil, err
	}
	// Every server has a master database, and the list holds it.
	if !slices.ContainsFunc(databases, func(d SQLDatabase) bool { return strings.EqualFold(d.Name, "master") }) {
		return nil, componentsdk.ResponseError(resp, invalidResponse("arm", route, "lists no master database, and every server has one"))
	}
	return databases, nil
}

func (c *ARMClient) SQLTransparentDataEncryption(ctx context.Context, databaseID string) (*SQLTransparentDataEncryption, error) {
	route := strings.TrimRight(databaseID, "/") + "/transparentDataEncryption/current?api-version=2023-08-01"
	var tde SQLTransparentDataEncryption
	if _, err := c.getJSON(ctx, armOperation("arm.sql.transparent_data_encryption.get"), route, &tde); err != nil {
		return nil, err
	}
	if tde.Properties.State == "" {
		return nil, invalidResponse("arm", route, "has no state")
	}
	return &tde, nil
}

func (c *ARMClient) VirtualMachines(ctx context.Context, subscriptionID string) ([]VirtualMachine, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01"
	return getARMPaged[VirtualMachine](ctx, c, "arm.compute.virtual_machines.list", route,
		"id", "properties/networkProfile/networkInterfaces", "properties/networkProfile/networkInterfaces/*/id")
}

func (c *ARMClient) PublicIPAddresses(ctx context.Context, subscriptionID string) ([]PublicIPAddress, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/publicIPAddresses?api-version=2023-11-01"
	return getARMPaged[PublicIPAddress](ctx, c, "arm.network.public_ip_addresses.list", route)
}

func (c *ARMClient) NetworkSecurityGroups(ctx context.Context, subscriptionID string) ([]NetworkSecurityGroup, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-11-01"
	return getARMPaged[NetworkSecurityGroup](ctx, c, "arm.network.security_groups.list", route, "properties/securityRules",
		"properties/securityRules/*/properties/priority", "properties/securityRules/*/properties/access",
		"properties/securityRules/*/properties/direction", "properties/securityRules/*/properties/protocol")
}

func (c *ARMClient) DiagnosticSettings(ctx context.Context, resourceID string) ([]DiagnosticSetting, error) {
	route := strings.TrimRight(resourceID, "/") + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, "arm.monitor.diagnostic_settings.list", route, diagnosticSettingFields...)
}

func (c *ARMClient) SubscriptionDiagnosticSettings(ctx context.Context, subscriptionID string) ([]DiagnosticSetting, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, "arm.monitor.subscription_diagnostic_settings.list", route, diagnosticSettingFields...)
}

// diagnosticSettingFields are the fields of a diagnostic setting that Azure
// Monitor always sends. A setting on a subscription has no metrics.
var diagnosticSettingFields = []string{"properties/logs", "properties/logs/*/enabled", "properties/metrics/*/enabled"}

func (c *ARMClient) RecoveryServicesVaults(ctx context.Context, subscriptionID string) ([]RecoveryServicesVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.RecoveryServices/vaults?api-version=2026-01-01"
	return getARMPaged[RecoveryServicesVault](ctx, c, "arm.backup.vaults.list", route, "id")
}

// RecoveryServicesVault reads one vault. The vault list leaves out its
// securitySettings, which only a read of the vault itself returns.
func (c *ARMClient) RecoveryServicesVault(ctx context.Context, vaultID string) (RecoveryServicesVault, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "", nil)
	if err != nil {
		return RecoveryServicesVault{}, err
	}
	var vault RecoveryServicesVault
	if _, err := c.getJSON(ctx, armOperation("arm.backup.vaults.get"), route, &vault); err != nil {
		return RecoveryServicesVault{}, err
	}
	if vault.Properties.SecuritySettings.SoftDeleteSettings.SoftDeleteState == "" && vault.Properties.SoftDeleteFeatureState == "" {
		return RecoveryServicesVault{}, invalidResponse("arm", route, "has no soft delete state")
	}
	return vault, nil
}

func (c *ARMClient) BackupProtectedItems(ctx context.Context, vaultID string) ([]BackupProtectedItem, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupProtectedItems", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupProtectedItem](ctx, c, "arm.backup.protected_items.list", route, "properties/backupManagementType", "properties/protectionState")
}

func (c *ARMClient) BackupPolicies(ctx context.Context, vaultID string) ([]BackupPolicy, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupPolicies", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupPolicy](ctx, c, "arm.backup.policies.list", route, "id")
}

func (c *ARMClient) BackupJobs(ctx context.Context, vaultID, filter string) ([]BackupJob, error) {
	query := url.Values{}
	if filter != "" {
		query.Set("$filter", filter)
	}
	route, err := recoveryServicesVaultRoute(vaultID, "backupJobs", query)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupJob](ctx, c, "arm.backup.jobs.list", route, "properties/status", "properties/startTime")
}

// armReaderRole is the Azure role each Resource Manager call needs on the
// subscription. Reader includes every read action the calls make, and
// docs/configuration.md asks for it.
const armReaderRole = "Reader"

// armOperation names a Resource Manager call with the role it needs, so a
// permission_denied gap on it names that role.
func armOperation(name string) componentsdk.Operation {
	return componentsdk.Operation{Name: name, Permission: armReaderRole}
}

// getARMPaged fails the whole list when any page fails, so a partial list
// never reads as a complete one. A next link to a page already read fails it
// too, since following it would never end. So does an item that lacks one of
// the required fields, which Resource Manager sends for every item, or that
// breaks its type's own rule.
func getARMPaged[T any](ctx context.Context, c *ARMClient, operation, route string, required ...string) ([]T, error) {
	items, _, err := getARMPages[T](ctx, c, operation, route, required)
	return items, err
}

// getARMPages is getARMPaged that also returns the last page's response.
func getARMPages[T any](ctx context.Context, c *ARMClient, operation, route string, required []string) ([]T, *http.Response, error) {
	op := armOperation(operation)
	out := []T{}
	read := map[string]struct{}{}
	next := route
	var resp *http.Response
	for next != "" {
		var page struct {
			Value    *[]json.RawMessage `json:"value"`
			NextLink string             `json:"nextLink"`
		}
		var err error
		if resp, err = c.getJSON(ctx, op, next, &page); err != nil {
			return nil, nil, err
		}
		if page.Value == nil {
			return nil, nil, componentsdk.ResponseError(resp, invalidResponse("arm", next, "has no value array"))
		}
		items, problem, err := decodeItems[T](*page.Value, required)
		switch {
		case err != nil:
			return nil, nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding arm response for %s: %w", SanitizeRoute(next), err))
		case problem != "":
			return nil, nil, componentsdk.ResponseError(resp, invalidResponse("arm", next, problem))
		}
		out = append(out, items...)
		read[next] = struct{}{}
		if _, ok := read[page.NextLink]; ok {
			return nil, nil, componentsdk.ResponseError(resp, invalidResponse("arm", next, "links to a page already read"))
		}
		next = page.NextLink
	}
	return out, resp, nil
}

func (c *ARMClient) getJSON(ctx context.Context, op componentsdk.Operation, route string, out any) (*http.Response, error) {
	body, resp, err := c.do(ctx, op, http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}
	return resp, decodeARM(resp, route, body, out)
}

func (c *ARMClient) postJSON(ctx context.Context, op componentsdk.Operation, route string, body any, out any) (*http.Response, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	respBody, resp, err := c.do(ctx, op, http.MethodPost, route, payload)
	if err != nil {
		return nil, err
	}
	return resp, decodeARM(resp, route, respBody, out)
}

func decodeARM(resp *http.Response, route string, body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("decoding arm response for %s: %w", SanitizeRoute(route), err))
	}
	return nil
}

// do sends one named call, and returns the body and the response it came in.
// The SDK's transport retries it when that is safe.
func (c *ARMClient) do(ctx context.Context, op componentsdk.Operation, method, route string, body []byte) ([]byte, *http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, op)
	req, err := c.newRequest(ctx, method, route, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, &RequestError{Service: "arm", Route: route, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, nil, &RequestError{Service: "arm", Route: route, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// ResponseError ties the error to its call, so a gap from it names
		// the call and the role it needs.
		return nil, nil, componentsdk.ResponseError(resp, armAPIError(resp.StatusCode, route, resp.Header, respBody))
	}
	if len(respBody) > maxResponseBytes {
		return nil, nil, tooLarge("arm", route)
	}
	return respBody, resp, nil
}

func (c *ARMClient) newRequest(ctx context.Context, method, route string, body io.Reader) (*http.Request, error) {
	endpoint, err := c.resolveURL(route)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	token, err := c.tokenSource.AccessToken(ctx)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *ARMClient) resolveURL(route string) (string, error) {
	return resolveServiceURL(c.baseURL, route)
}

func armAPIError(status int, route string, header http.Header, body []byte) *APIError {
	apiErr := &APIError{Service: "arm", StatusCode: status, Route: route, Body: string(body), Header: header}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		apiErr.Code = payload.Error.Code
		apiErr.Message = payload.Error.Message
	}
	return apiErr
}

func sqlServerIDParts(id string) (subscriptionID, resourceGroup, serverName string, err error) {
	parts := resourceIDParts(id)
	subscriptionID = resourceIDValue(parts, "subscriptions")
	resourceGroup = resourceIDValue(parts, "resourcegroups")
	serverName = resourceIDValue(parts, "servers")
	if subscriptionID == "" || resourceGroup == "" || serverName == "" {
		return "", "", "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("invalid SQL server resource id: %s", SanitizeErrorText(id)))
	}
	return subscriptionID, resourceGroup, serverName, nil
}

func recoveryServicesVaultRoute(vaultID, child string, query url.Values) (string, error) {
	parts := resourceIDParts(vaultID)
	subscriptionID := resourceIDValue(parts, "subscriptions")
	resourceGroup := resourceIDValue(parts, "resourcegroups")
	vaultName := resourceIDValue(parts, "vaults")
	if subscriptionID == "" || resourceGroup == "" || vaultName == "" {
		return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("invalid Recovery Services vault resource id: %s", SanitizeErrorText(vaultID)))
	}
	values := url.Values{"api-version": []string{"2026-01-01"}}
	for key, entries := range query {
		for _, entry := range entries {
			values.Add(key, entry)
		}
	}
	route := "/subscriptions/" + url.PathEscape(subscriptionID) +
		"/resourceGroups/" + url.PathEscape(resourceGroup) +
		"/providers/Microsoft.RecoveryServices/vaults/" + url.PathEscape(vaultName)
	if child != "" {
		route += "/" + child
	}
	return route + "?" + values.Encode(), nil
}

func resourceIDParts(id string) []string {
	return strings.Split(strings.Trim(id, "/"), "/")
}

func resourceIDValue(parts []string, name string) string {
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], name) {
			return parts[i+1]
		}
	}
	return ""
}
