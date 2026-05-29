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
)

const defaultARMBaseURL = "https://management.azure.com"

type ARMClient struct {
	baseURL     string
	tokenSource AccessTokenSource
	httpClient  *http.Client
	sleep       sleeper
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

func WithARMSleeper(s sleeper) ARMOption {
	return func(c *ARMClient) {
		if s != nil {
			c.sleep = s
		}
	}
}

func NewARMClient(tokenSource AccessTokenSource, opts ...ARMOption) *ARMClient {
	c := &ARMClient{
		baseURL:     defaultARMBaseURL,
		tokenSource: tokenSource,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		sleep:       defaultSleeper,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *ARMClient) Subscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	var subscription Subscription
	if err := c.getJSON(ctx, "/subscriptions/"+url.PathEscape(subscriptionID)+"?api-version=2020-01-01", &subscription); err != nil {
		return nil, err
	}
	return &subscription, nil
}

func (c *ARMClient) Resources(ctx context.Context, subscriptionID string) ([]ARMResource, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/resources?api-version=2021-04-01"
	return getARMPaged[ARMResource](ctx, c, route)
}

func (c *ARMClient) DefenderSecureScore(ctx context.Context, subscriptionID string) (*ARMSecureScore, error) {
	var score ARMSecureScore
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
	if err := c.getJSON(ctx, route, &score); err != nil {
		return nil, err
	}
	return &score, nil
}

func (c *ARMClient) DefenderAssessments(ctx context.Context, subscriptionID string) ([]SecurityAssessment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Security/assessments?api-version=2020-01-01"
	return getARMPaged[SecurityAssessment](ctx, c, route)
}

func (c *ARMClient) RoleAssignments(ctx context.Context, subscriptionID string) ([]ARMRoleAssignment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope%28%29"
	return getARMPaged[ARMRoleAssignment](ctx, c, route)
}

func (c *ARMClient) PolicyAssignments(ctx context.Context, subscriptionID string) ([]PolicyAssignment, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01"
	return getARMPaged[PolicyAssignment](ctx, c, route)
}

func (c *ARMClient) PolicyStateSummary(ctx context.Context, subscriptionID string) (*PolicyStateSummaryResult, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
	var summary PolicyStateSummaryResult
	if err := c.postJSON(ctx, route, nil, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func (c *ARMClient) StorageAccounts(ctx context.Context, subscriptionID string) ([]StorageAccount, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Storage/storageAccounts?api-version=2024-01-01"
	return getARMPaged[StorageAccount](ctx, c, route)
}

func (c *ARMClient) KeyVaults(ctx context.Context, subscriptionID string) ([]KeyVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01"
	return getARMPaged[KeyVault](ctx, c, route)
}

func (c *ARMClient) SQLServers(ctx context.Context, subscriptionID string) ([]SQLServer, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Sql/servers?api-version=2023-08-01"
	return getARMPaged[SQLServer](ctx, c, route)
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
	return getARMPaged[SQLDatabase](ctx, c, route)
}

func (c *ARMClient) SQLTransparentDataEncryption(ctx context.Context, databaseID string) (*SQLTransparentDataEncryption, error) {
	route := strings.TrimRight(databaseID, "/") + "/transparentDataEncryption/current?api-version=2023-08-01"
	var tde SQLTransparentDataEncryption
	if err := c.getJSON(ctx, route, &tde); err != nil {
		return nil, err
	}
	return &tde, nil
}

func (c *ARMClient) VirtualMachines(ctx context.Context, subscriptionID string) ([]VirtualMachine, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01"
	return getARMPaged[VirtualMachine](ctx, c, route)
}

func (c *ARMClient) PublicIPAddresses(ctx context.Context, subscriptionID string) ([]PublicIPAddress, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/publicIPAddresses?api-version=2023-11-01"
	return getARMPaged[PublicIPAddress](ctx, c, route)
}

func (c *ARMClient) NetworkSecurityGroups(ctx context.Context, subscriptionID string) ([]NetworkSecurityGroup, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-11-01"
	return getARMPaged[NetworkSecurityGroup](ctx, c, route)
}

func (c *ARMClient) DiagnosticSettings(ctx context.Context, resourceID string) ([]DiagnosticSetting, error) {
	route := strings.TrimRight(resourceID, "/") + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, route)
}

func (c *ARMClient) SubscriptionDiagnosticSettings(ctx context.Context, subscriptionID string) ([]DiagnosticSetting, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
	return getARMPaged[DiagnosticSetting](ctx, c, route)
}

func (c *ARMClient) RecoveryServicesVaults(ctx context.Context, subscriptionID string) ([]RecoveryServicesVault, error) {
	route := "/subscriptions/" + url.PathEscape(subscriptionID) + "/providers/Microsoft.RecoveryServices/vaults?api-version=2026-01-01"
	return getARMPaged[RecoveryServicesVault](ctx, c, route)
}

func (c *ARMClient) BackupProtectedItems(ctx context.Context, vaultID string) ([]BackupProtectedItem, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupProtectedItems", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupProtectedItem](ctx, c, route)
}

func (c *ARMClient) BackupPolicies(ctx context.Context, vaultID string) ([]BackupPolicy, error) {
	route, err := recoveryServicesVaultRoute(vaultID, "backupPolicies", nil)
	if err != nil {
		return nil, err
	}
	return getARMPaged[BackupPolicy](ctx, c, route)
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
	return getARMPaged[BackupJob](ctx, c, route)
}

func getARMPaged[T any](ctx context.Context, c *ARMClient, route string) ([]T, error) {
	var out []T
	next := route
	for next != "" {
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := c.getJSON(ctx, next, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		next = page.NextLink
	}
	return out, nil
}

func (c *ARMClient) getJSON(ctx context.Context, route string, out any) error {
	body, err := c.do(ctx, http.MethodGet, route, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (c *ARMClient) postJSON(ctx context.Context, route string, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	resp, err := c.do(ctx, http.MethodPost, route, payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(resp, out)
}

func (c *ARMClient) do(ctx context.Context, method, route string, body []byte) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		payload := bytes.NewReader(body)
		req, err := c.newRequest(ctx, method, route, payload)
		if err != nil {
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return respBody, nil
			}
			lastErr = armAPIError(resp.StatusCode, route, respBody)
			if !retryableStatus(resp.StatusCode) || attempt == maxAttempts {
				return nil, lastErr
			}
			if err := c.sleep(ctx, retryDelay(resp, attempt)); err != nil {
				return nil, err
			}
			continue
		}

		if attempt == maxAttempts {
			break
		}
		if err := c.sleep(ctx, retryDelay(nil, attempt)); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
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

func armAPIError(status int, route string, body []byte) *APIError {
	apiErr := &APIError{Service: "arm", StatusCode: status, Route: route, Body: string(body)}
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
		return "", "", "", fmt.Errorf("invalid SQL server resource id: %s", SanitizeErrorText(id))
	}
	return subscriptionID, resourceGroup, serverName, nil
}

func recoveryServicesVaultRoute(vaultID, child string, query url.Values) (string, error) {
	parts := resourceIDParts(vaultID)
	subscriptionID := resourceIDValue(parts, "subscriptions")
	resourceGroup := resourceIDValue(parts, "resourcegroups")
	vaultName := resourceIDValue(parts, "vaults")
	if subscriptionID == "" || resourceGroup == "" || vaultName == "" {
		return "", fmt.Errorf("invalid Recovery Services vault resource id: %s", SanitizeErrorText(vaultID))
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
