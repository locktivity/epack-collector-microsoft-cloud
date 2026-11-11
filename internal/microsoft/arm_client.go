package microsoft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	if err := c.getJSON(ctx, armOperation("arm.subscriptions.get"), route, &subscription); err != nil {
		return nil, err
	}
	if subscription.SubscriptionID == "" {
		return nil, invalidResponse("arm", route, "has no subscriptionId")
	}
	return &subscription, nil
}

func (c *ARMClient) Resources(ctx context.Context, subscriptionID string) ([]ARMResource, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/resources?api-version=2021-04-01"
	return getARMPaged[ARMResource](ctx, c, "arm.resources.list", route)
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
	if err := c.getJSON(ctx, armOperation("arm.defender.secure_score.get"), route, &score); err != nil {
		return nil, err
	}
	if score.Properties.Score == nil {
		return nil, invalidResponse("arm", route, "has no score")
	}
	return &ARMSecureScore{ID: score.ID, Name: score.Name, Properties: ARMSecureScoreProperties{Score: *score.Properties.Score}}, nil
}

func (c *ARMClient) DefenderAssessments(ctx context.Context, subscriptionID string) ([]SecurityAssessment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Security/assessments?api-version=2020-01-01"
	return getARMPaged[SecurityAssessment](ctx, c, "arm.defender.assessments.list", route)
}

// RoleAssignments lists the role assignments that apply to a subscription:
// those at the subscription, above it, and on its resource groups and
// resources. Each one's scope says where it is.
func (c *ARMClient) RoleAssignments(ctx context.Context, subscriptionID string) ([]ARMRoleAssignment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
	return getARMPaged[ARMRoleAssignment](ctx, c, "arm.role_assignments.list", route)
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
		Value *[]PolicyStateSummary `json:"value"`
	}
	if err := c.postJSON(ctx, componentsdk.Operation{Name: "arm.policy.states.summarize", Safe: true, Permission: armReaderRole}, route, nil, &summary); err != nil {
		return nil, err
	}
	if summary.Value == nil {
		return nil, invalidResponse("arm", route, "has no value array")
	}
	return &PolicyStateSummaryResult{Value: *summary.Value}, nil
}

func (c *ARMClient) StorageAccounts(ctx context.Context, subscriptionID string) ([]StorageAccount, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Storage/storageAccounts?api-version=2024-01-01"
	return getARMPaged[StorageAccount](ctx, c, "arm.storage.accounts.list", route)
}

func (c *ARMClient) KeyVaults(ctx context.Context, subscriptionID string) ([]KeyVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01"
	return getARMPaged[KeyVault](ctx, c, "arm.keyvault.vaults.list", route)
}

func (c *ARMClient) SQLServers(ctx context.Context, subscriptionID string) ([]SQLServer, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Sql/servers?api-version=2023-08-01"
	return getARMPaged[SQLServer](ctx, c, "arm.sql.servers.list", route)
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
	return getARMPaged[SQLDatabase](ctx, c, "arm.sql.databases.list", route)
}

func (c *ARMClient) SQLTransparentDataEncryption(ctx context.Context, databaseID string) (*SQLTransparentDataEncryption, error) {
	route := strings.TrimRight(databaseID, "/") + "/transparentDataEncryption/current?api-version=2023-08-01"
	var tde SQLTransparentDataEncryption
	if err := c.getJSON(ctx, armOperation("arm.sql.transparent_data_encryption.get"), route, &tde); err != nil {
		return nil, err
	}
	if tde.Properties.State == "" {
		return nil, invalidResponse("arm", route, "has no state")
	}
	return &tde, nil
}

func (c *ARMClient) VirtualMachines(ctx context.Context, subscriptionID string) ([]VirtualMachine, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01"
	return getARMPaged[VirtualMachine](ctx, c, "arm.compute.virtual_machines.list", route)
}

func (c *ARMClient) PublicIPAddresses(ctx context.Context, subscriptionID string) ([]PublicIPAddress, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/publicIPAddresses?api-version=2023-11-01"
	return getARMPaged[PublicIPAddress](ctx, c, "arm.network.public_ip_addresses.list", route)
}

func (c *ARMClient) NetworkSecurityGroups(ctx context.Context, subscriptionID string) ([]NetworkSecurityGroup, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-11-01"
	return getARMPaged[NetworkSecurityGroup](ctx, c, "arm.network.security_groups.list", route)
}

func (c *ARMClient) DiagnosticSettings(ctx context.Context, resourceID string) ([]DiagnosticSetting, error) {
	route := strings.TrimRight(resourceID, "/") + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, "arm.monitor.diagnostic_settings.list", route)
}

func (c *ARMClient) SubscriptionDiagnosticSettings(ctx context.Context, subscriptionID string) ([]DiagnosticSetting, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, "arm.monitor.subscription_diagnostic_settings.list", route)
}

func (c *ARMClient) RecoveryServicesVaults(ctx context.Context, subscriptionID string) ([]RecoveryServicesVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.RecoveryServices/vaults?api-version=2026-01-01"
	return getARMPaged[RecoveryServicesVault](ctx, c, "arm.backup.vaults.list", route)
}

func (c *ARMClient) BackupProtectedItems(ctx context.Context, vaultID string) ([]BackupProtectedItem, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupProtectedItems", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupProtectedItem](ctx, c, "arm.backup.protected_items.list", route)
}

func (c *ARMClient) BackupPolicies(ctx context.Context, vaultID string) ([]BackupPolicy, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupPolicies", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupPolicy](ctx, c, "arm.backup.policies.list", route)
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
	return getARMPaged[BackupJob](ctx, c, "arm.backup.jobs.list", route)
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
// too, since following it would never end.
func getARMPaged[T any](ctx context.Context, c *ARMClient, operation, route string) ([]T, error) {
	op := armOperation(operation)
	out := []T{}
	read := map[string]struct{}{}
	next := route
	for next != "" {
		var page struct {
			Value    *[]T   `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := c.getJSON(ctx, op, next, &page); err != nil {
			return nil, err
		}
		if page.Value == nil {
			return nil, invalidResponse("arm", next, "has no value array")
		}
		out = append(out, *page.Value...)
		read[next] = struct{}{}
		if _, ok := read[page.NextLink]; ok {
			return nil, invalidResponse("arm", next, "links to a page already read")
		}
		next = page.NextLink
	}
	return out, nil
}

func (c *ARMClient) getJSON(ctx context.Context, op componentsdk.Operation, route string, out any) error {
	body, err := c.do(ctx, op, http.MethodGet, route, nil)
	if err != nil {
		return err
	}
	return decodeARM(route, body, out)
}

func (c *ARMClient) postJSON(ctx context.Context, op componentsdk.Operation, route string, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	resp, err := c.do(ctx, op, http.MethodPost, route, payload)
	if err != nil {
		return err
	}
	return decodeARM(route, resp, out)
}

func decodeARM(route string, body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding arm response for %s: %w", SanitizeRoute(route), err)
	}
	return nil
}

// do sends one named call. The SDK's transport retries it when that is safe.
func (c *ARMClient) do(ctx context.Context, op componentsdk.Operation, method, route string, body []byte) ([]byte, error) {
	ctx = componentsdk.WithOperation(ctx, op)
	req, err := c.newRequest(ctx, method, route, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Service: "arm", Route: route, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &RequestError{Service: "arm", Route: route, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// ResponseError ties the error to its call, so a gap from it names
		// the call and the role it needs.
		return nil, componentsdk.ResponseError(resp, armAPIError(resp.StatusCode, route, resp.Header, respBody))
	}
	if len(respBody) > maxResponseBytes {
		return nil, tooLarge("arm", route)
	}
	return respBody, nil
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
	return "/subscriptions/" + url.PathEscape(subscriptionID) +
		"/resourceGroups/" + url.PathEscape(resourceGroup) +
		"/providers/Microsoft.RecoveryServices/vaults/" + url.PathEscape(vaultName) +
		"/" + child + "?" + values.Encode(), nil
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
