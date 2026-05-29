package microsoft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultGraphBaseURL = "https://graph.microsoft.com/v1.0"

type APIError struct {
	Service    string
	StatusCode int
	Route      string
	Code       string
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	service := e.Service
	if service == "" {
		service = "graph"
	}
	route := SanitizeRoute(e.Route)
	code := SanitizeErrorText(e.Code)
	message := SanitizeErrorText(e.Message)
	if e.Code != "" || e.Message != "" {
		return fmt.Sprintf("%s request %s failed: status=%d code=%s message=%s", service, route, e.StatusCode, code, message)
	}
	return fmt.Sprintf("%s request %s failed: status=%d body=%s", service, route, e.StatusCode, SanitizeErrorText(e.Body))
}

type GraphClient struct {
	baseURL     string
	tokenSource AccessTokenSource
	httpClient  *http.Client
	sleep       sleeper
}

type GraphOption func(*GraphClient)

func WithGraphBaseURL(baseURL string) GraphOption {
	return func(c *GraphClient) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func WithGraphHTTPClient(client *http.Client) GraphOption {
	return func(c *GraphClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func WithRetrySleeper(s sleeper) GraphOption {
	return func(c *GraphClient) {
		if s != nil {
			c.sleep = s
		}
	}
}

func NewGraphClient(tokenSource AccessTokenSource, opts ...GraphOption) *GraphClient {
	c := &GraphClient{
		baseURL:     defaultGraphBaseURL,
		tokenSource: tokenSource,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		sleep:       defaultSleeper,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *GraphClient) Organization(ctx context.Context) (*Organization, error) {
	var page struct {
		Value []Organization `json:"value"`
	}
	if err := c.getJSON(ctx, "/organization?$select=id,verifiedDomains", &page); err != nil {
		return nil, err
	}
	if len(page.Value) == 0 {
		return nil, &APIError{StatusCode: http.StatusNotFound, Route: "/organization", Message: "no organization returned"}
	}
	return &page.Value[0], nil
}

func (c *GraphClient) Users(ctx context.Context) ([]User, error) {
	return getPaged[User](ctx, c, "/users?$select=id,accountEnabled,userType&$top=999")
}

func (c *GraphClient) UsersWithSignInActivity(ctx context.Context) ([]User, error) {
	return getPaged[User](ctx, c, "/users?$select=id,accountEnabled,userType,signInActivity&$top=999")
}

func (c *GraphClient) UserRegistrationDetails(ctx context.Context) ([]UserRegistrationDetail, error) {
	return getPaged[UserRegistrationDetail](ctx, c, "/reports/authenticationMethods/userRegistrationDetails")
}

func (c *GraphClient) ConditionalAccessPolicies(ctx context.Context) ([]ConditionalAccessPolicy, error) {
	return getPaged[ConditionalAccessPolicy](ctx, c, "/identity/conditionalAccess/policies")
}

func (c *GraphClient) SecurityDefaults(ctx context.Context) (*IdentitySecurityDefaultsEnforcementPolicy, error) {
	var policy IdentitySecurityDefaultsEnforcementPolicy
	if err := c.getJSON(ctx, "/policies/identitySecurityDefaultsEnforcementPolicy", &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (c *GraphClient) RoleAssignments(ctx context.Context) ([]UnifiedRoleAssignment, error) {
	return getPaged[UnifiedRoleAssignment](ctx, c, "/roleManagement/directory/roleAssignments?$expand=principal&$top=999")
}

func (c *GraphClient) RoleEligibilitySchedules(ctx context.Context) ([]UnifiedRoleEligibilitySchedule, error) {
	return getPaged[UnifiedRoleEligibilitySchedule](ctx, c, "/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition&$top=999")
}

func (c *GraphClient) ServicePrincipals(ctx context.Context) ([]ServicePrincipal, error) {
	return getPaged[ServicePrincipal](ctx, c, "/servicePrincipals?$filter=servicePrincipalType%20eq%20'Application'&$select=id,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,servicePrincipalType,passwordCredentials,keyCredentials&$top=999")
}

func (c *GraphClient) Applications(ctx context.Context) ([]Application, error) {
	return getPaged[Application](ctx, c, "/applications?$select=id,passwordCredentials,keyCredentials&$top=999")
}

func (c *GraphClient) SecureScores(ctx context.Context) ([]SecureScore, error) {
	return getPaged[SecureScore](ctx, c, "/security/secureScores?$top=1")
}

func (c *GraphClient) SignIns(ctx context.Context, since time.Time) ([]SignIn, error) {
	query := url.Values{}
	query.Set("$filter", "createdDateTime ge "+since.UTC().Format(time.RFC3339))
	query.Set("$orderby", "createdDateTime desc")
	query.Set("$select", "id,createdDateTime,userId,appId,status,conditionalAccessStatus,appliedConditionalAccessPolicies,clientAppUsed,riskLevelAggregated,riskLevelDuringSignIn")
	query.Set("$top", "999")
	return getPaged[SignIn](ctx, c, "/auditLogs/signIns?"+query.Encode())
}

func (c *GraphClient) DirectoryAudits(ctx context.Context, since time.Time) ([]DirectoryAudit, error) {
	query := url.Values{}
	query.Set("$filter", "activityDateTime ge "+since.UTC().Format(time.RFC3339))
	query.Set("$orderby", "activityDateTime desc")
	query.Set("$select", "id,activityDateTime,activityDisplayName,category,loggedByService,operationType,result,targetResources")
	query.Set("$top", "999")
	return getPaged[DirectoryAudit](ctx, c, "/auditLogs/directoryAudits?"+query.Encode())
}

func getPaged[T any](ctx context.Context, c *GraphClient, route string) ([]T, error) {
	var out []T
	next := route
	for next != "" {
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := c.getJSON(ctx, next, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		next = page.NextLink
	}
	return out, nil
}

func (c *GraphClient) getJSON(ctx context.Context, route string, out any) error {
	body, err := c.do(ctx, http.MethodGet, route, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (c *GraphClient) do(ctx context.Context, method, route string, body []byte) ([]byte, error) {
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
			lastErr = graphAPIError(resp.StatusCode, route, respBody)
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

func (c *GraphClient) newRequest(ctx context.Context, method, route string, body io.Reader) (*http.Request, error) {
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

func (c *GraphClient) resolveURL(route string) (string, error) {
	return resolveServiceURL(c.baseURL, route)
}

func graphAPIError(status int, route string, body []byte) *APIError {
	apiErr := &APIError{Service: "graph", StatusCode: status, Route: route, Body: string(body)}
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

func IsPremiumLicenseError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	combined := strings.ToLower(apiErr.Code + " " + apiErr.Message + " " + apiErr.Body)
	return strings.Contains(combined, "nonpremiumtenant") ||
		strings.Contains(combined, "aadpremiumlicenserequired") ||
		strings.Contains(combined, "premiumlicenserequired") ||
		strings.Contains(combined, "premium license") ||
		strings.Contains(combined, "entra id p2") ||
		strings.Contains(combined, "entra id governance") ||
		strings.Contains(combined, "doesn't have premium")
}
