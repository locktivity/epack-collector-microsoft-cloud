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
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const DefaultGraphBaseURL = "https://graph.microsoft.com/v1.0"

const maxResponseBytes = 4 << 20

type APIError struct {
	Service    string
	StatusCode int
	Route      string
	Code       string
	Message    string
	Body       string
	Header     http.Header
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

// These let componentsdk.Classify read the status and throttle headers, and
// give records the Graph or ARM error code.
func (e *APIError) HTTPStatus() int         { return e.StatusCode }
func (e *APIError) HTTPHeader() http.Header { return e.Header }
func (e *APIError) VendorCode() string      { return e.Code }

type GraphClient struct {
	baseURL     string
	tokenSource AccessTokenSource
	httpClient  *http.Client
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

func NewGraphClient(tokenSource AccessTokenSource, opts ...GraphOption) *GraphClient {
	c := &GraphClient{
		baseURL:     DefaultGraphBaseURL,
		tokenSource: tokenSource,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *GraphClient) Organization(ctx context.Context) (*Organization, error) {
	route := "/organization?$select=id,verifiedDomains"
	orgs, err := getPaged[Organization](ctx, c, "graph.organization.get", route)
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 || orgs[0].ID == "" {
		return nil, invalidResponse("graph", route, "has no organization")
	}
	return &orgs[0], nil
}

func (c *GraphClient) Users(ctx context.Context) ([]User, error) {
	return getPaged[User](ctx, c, "graph.users.list", "/users?$select=id,accountEnabled,userType,userPrincipalName&$top=999", "id", "accountEnabled")
}

func (c *GraphClient) UsersWithSignInActivity(ctx context.Context) ([]User, error) {
	return getPaged[User](ctx, c, "graph.users.sign_in_activity.list", "/users?$select=id,accountEnabled,userType,signInActivity&$top=999", "id", "accountEnabled")
}

func (c *GraphClient) UserRegistrationDetails(ctx context.Context) ([]UserRegistrationDetail, error) {
	return getPaged[UserRegistrationDetail](ctx, c, "graph.user_registration_details.list", "/reports/authenticationMethods/userRegistrationDetails",
		"isMfaRegistered", "isSsprRegistered", "methodsRegistered")
}

func (c *GraphClient) ConditionalAccessPolicies(ctx context.Context) ([]ConditionalAccessPolicy, error) {
	return getPaged[ConditionalAccessPolicy](ctx, c, "graph.conditional_access.policies.list", "/identity/conditionalAccess/policies",
		"state", "conditions", "conditions/applications", "conditions/applications/includeApplications")
}

func (c *GraphClient) SecurityDefaults(ctx context.Context) (*IdentitySecurityDefaultsEnforcementPolicy, error) {
	route := "/policies/identitySecurityDefaultsEnforcementPolicy"
	var policy struct {
		IsEnabled *bool `json:"isEnabled"`
	}
	if _, err := c.getJSON(ctx, graphOperation("graph.security_defaults.get"), route, nil, &policy); err != nil {
		return nil, err
	}
	if policy.IsEnabled == nil {
		return nil, invalidResponse("graph", route, "has no isEnabled")
	}
	return &IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: *policy.IsEnabled}, nil
}

func (c *GraphClient) RoleAssignments(ctx context.Context) ([]UnifiedRoleAssignment, error) {
	return getPaged[UnifiedRoleAssignment](ctx, c, "graph.role_assignments.list", "/roleManagement/directory/roleAssignments?$expand=principal&$top=999",
		"principalId", "roleDefinitionId")
}

func (c *GraphClient) NamedLocations(ctx context.Context) ([]NamedLocation, error) {
	return getPaged[NamedLocation](ctx, c, "graph.conditional_access.named_locations.list", "/identity/conditionalAccess/namedLocations")
}

// RoleDefinitions lists the directory roles Microsoft has classified. Graph
// v1.0 returns isPrivileged as null but filters on it, so the roles are read
// once with each value of the filter, and each role carries the value its
// read asked for. A role in neither read is one Microsoft hasn't classified.
func (c *GraphClient) RoleDefinitions(ctx context.Context) ([]UnifiedRoleDefinition, error) {
	var out []UnifiedRoleDefinition
	for _, privileged := range []bool{true, false} {
		route := "/roleManagement/directory/roleDefinitions?$filter=isPrivileged%20eq%20" + strconv.FormatBool(privileged) + "&$select=id,templateId,isPrivileged,rolePermissions"
		definitions, err := getPaged[UnifiedRoleDefinition](ctx, c, "graph.role_definitions.list", route, "rolePermissions", "rolePermissions/*/allowedResourceActions")
		if err != nil {
			return nil, err
		}
		for i := range definitions {
			definitions[i].IsPrivileged = &privileged
		}
		out = append(out, definitions...)
	}
	return out, nil
}

func (c *GraphClient) RoleEligibilitySchedules(ctx context.Context) ([]UnifiedRoleEligibilitySchedule, error) {
	return getPaged[UnifiedRoleEligibilitySchedule](ctx, c, "graph.role_eligibility_schedules.list", "/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition&$top=999",
		"principalId", "roleDefinitionId")
}

// credentialFields are the fields of an app's or a service principal's
// client secrets and certificates that Graph always sends. Graph sets a
// secret's startDateTime when it is added, and a certificate's dates are its
// own. A secret can have no endDateTime.
// https://learn.microsoft.com/en-us/graph/api/application-addpassword
var credentialFields = []string{
	"passwordCredentials", "passwordCredentials/*/startDateTime",
	"keyCredentials", "keyCredentials/*/startDateTime", "keyCredentials/*/endDateTime",
}

// ServicePrincipals lists the tenant's Application service principals. An
// empty list is not an answer, since the collector signs in as one of them.
func (c *GraphClient) ServicePrincipals(ctx context.Context) ([]ServicePrincipal, error) {
	route := "/servicePrincipals?$filter=servicePrincipalType%20eq%20'Application'&$select=id,appId,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,servicePrincipalType,passwordCredentials,keyCredentials&$top=999"
	required := append([]string{"id", "appId", "accountEnabled", "appRoleAssignmentRequired"}, credentialFields...)
	servicePrincipals, resp, err := getPages[ServicePrincipal](ctx, c, "graph.service_principals.list", route, nil, required)
	if err != nil {
		return nil, err
	}
	if len(servicePrincipals) == 0 {
		return nil, componentsdk.ResponseError(resp, invalidResponse("graph", route, "lists no service principal, and the one the collector signs in as is always listed"))
	}
	return servicePrincipals, nil
}

func (c *GraphClient) Applications(ctx context.Context) ([]Application, error) {
	return getPaged[Application](ctx, c, "graph.applications.list", "/applications?$select=id,appId,passwordCredentials,keyCredentials&$top=999",
		append([]string{"appId"}, credentialFields...)...)
}

// SecureScores reads the tenant's newest identity secure score. Graph keeps
// one score a day, newest first, so the first page of one holds it, and its
// next links lead only to older days.
// https://learn.microsoft.com/en-us/graph/api/security-list-securescores
func (c *GraphClient) SecureScores(ctx context.Context) ([]SecureScore, error) {
	items, _, _, err := readPage[SecureScore](ctx, c, graphOperation("graph.secure_scores.list"), "/security/secureScores?$top=1", nil, []string{"currentScore"})
	return items, err
}

func (c *GraphClient) SignIns(ctx context.Context, since time.Time) ([]SignIn, error) {
	query := url.Values{}
	query.Set("$filter", "createdDateTime ge "+since.UTC().Format(time.RFC3339))
	query.Set("$orderby", "createdDateTime desc")
	query.Set("$select", "id,createdDateTime,userId,appId,status,conditionalAccessStatus,appliedConditionalAccessPolicies,clientAppUsed,riskLevelAggregated,riskLevelDuringSignIn")
	query.Set("$top", "999")
	signIns, _, err := getPages[SignIn](ctx, c, "graph.sign_ins.list", "/auditLogs/signIns?"+query.Encode(), preferUnknownEnumMembers, []string{
		"userId", "appId", "status/errorCode", "conditionalAccessStatus", "clientAppUsed", "riskLevelAggregated", "riskLevelDuringSignIn",
		"appliedConditionalAccessPolicies/*/id", "appliedConditionalAccessPolicies/*/result",
	})
	return signIns, err
}

// preferUnknownEnumMembers is the Prefer header for the members of an
// evolvable enum that come after unknownFutureValue. Without it, an applied
// policy's reportOnlyFailure result arrives as unknownFutureValue.
// https://learn.microsoft.com/en-us/graph/api/resources/appliedconditionalaccesspolicy
var preferUnknownEnumMembers = http.Header{"Prefer": {"include-unknown-enum-members"}}

func (c *GraphClient) DirectoryAudits(ctx context.Context, since time.Time) ([]DirectoryAudit, error) {
	query := url.Values{}
	query.Set("$filter", "activityDateTime ge "+since.UTC().Format(time.RFC3339))
	query.Set("$orderby", "activityDateTime desc")
	query.Set("$select", "id,activityDateTime,activityDisplayName,category,loggedByService,operationType,result,targetResources")
	query.Set("$top", "999")
	return getPaged[DirectoryAudit](ctx, c, "graph.directory_audits.list", "/auditLogs/directoryAudits?"+query.Encode(),
		"category", "loggedByService", "operationType", "result")
}

// graphPermissions names the Microsoft Graph application permission each call
// needs, as docs/configuration.md lists them.
var graphPermissions = map[string]string{
	"graph.organization.get":                        "Organization.Read.All",
	"graph.users.list":                              "User.Read.All",
	"graph.users.sign_in_activity.list":             "AuditLog.Read.All",
	"graph.user_registration_details.list":          "AuditLog.Read.All",
	"graph.conditional_access.policies.list":        "Policy.Read.All",
	"graph.conditional_access.named_locations.list": "Policy.Read.All",
	"graph.security_defaults.get":                   "Policy.Read.All",
	"graph.role_assignments.list":                   "RoleManagement.Read.Directory",
	"graph.role_definitions.list":                   "RoleManagement.Read.Directory",
	"graph.role_eligibility_schedules.list":         "RoleEligibilitySchedule.Read.Directory",
	"graph.service_principals.list":                 "Application.Read.All",
	"graph.applications.list":                       "Application.Read.All",
	"graph.secure_scores.list":                      "SecurityEvents.Read.All",
	"graph.sign_ins.list":                           "AuditLog.Read.All",
	"graph.directory_audits.list":                   "AuditLog.Read.All",
}

// graphOperation names a Graph call with the permission it needs, so a
// permission_denied gap on it names that permission.
func graphOperation(name string) componentsdk.Operation {
	return componentsdk.Operation{Name: name, Permission: graphPermissions[name]}
}

// getPaged fails the whole list when any page fails, so a partial list never
// reads as a complete one. A next link to a page already read fails it too,
// since following it would never end. So does an item that lacks one of the
// required fields, which Graph sends for every item, or that breaks its
// type's own rule.
func getPaged[T any](ctx context.Context, c *GraphClient, operation, route string, required ...string) ([]T, error) {
	items, _, err := getPages[T](ctx, c, operation, route, nil, required)
	return items, err
}

// getPages is getPaged with header added to the request for every page. It
// also returns the last page's response.
func getPages[T any](ctx context.Context, c *GraphClient, operation, route string, header http.Header, required []string) ([]T, *http.Response, error) {
	op := graphOperation(operation)
	out := []T{}
	read := map[string]struct{}{}
	next := route
	var resp *http.Response
	for next != "" {
		items, link, pageResp, err := readPage[T](ctx, c, op, next, header, required)
		if err != nil {
			return nil, nil, err
		}
		resp = pageResp
		out = append(out, items...)
		read[next] = struct{}{}
		if _, ok := read[link]; ok {
			return nil, nil, componentsdk.ResponseError(resp, invalidResponse("graph", next, "links to a page already read"))
		}
		next = link
	}
	return out, resp, nil
}

// readPage reads one page of a list, with header added to the request, and
// returns its items, its next link, and the response it came in. A page with
// no value array, or an item that lacks a required field or breaks its
// type's own rule, fails it.
func readPage[T any](ctx context.Context, c *GraphClient, op componentsdk.Operation, route string, header http.Header, required []string) ([]T, string, *http.Response, error) {
	var page struct {
		Value    *[]json.RawMessage `json:"value"`
		NextLink string             `json:"@odata.nextLink"`
	}
	resp, err := c.getJSON(ctx, op, route, header, &page)
	if err != nil {
		return nil, "", nil, err
	}
	if page.Value == nil {
		return nil, "", nil, componentsdk.ResponseError(resp, invalidResponse("graph", route, "has no value array"))
	}
	items, problem, err := decodeItems[T](*page.Value, required)
	switch {
	case err != nil:
		return nil, "", nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding graph response for %s: %w", SanitizeRoute(route), err))
	case problem != "":
		return nil, "", nil, componentsdk.ResponseError(resp, invalidResponse("graph", route, problem))
	}
	return items, page.NextLink, resp, nil
}

func (c *GraphClient) getJSON(ctx context.Context, op componentsdk.Operation, route string, header http.Header, out any) (*http.Response, error) {
	body, resp, err := c.do(ctx, op, http.MethodGet, route, header, nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding graph response for %s: %w", SanitizeRoute(route), err))
	}
	return resp, nil
}

// do sends one named call with header added, and returns the body and the
// response it came in. The SDK's transport retries it when that is safe.
func (c *GraphClient) do(ctx context.Context, op componentsdk.Operation, method, route string, header http.Header, body []byte) ([]byte, *http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, op)
	req, err := c.newRequest(ctx, method, route, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, &RequestError{Service: "graph", Route: route, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, nil, &RequestError{Service: "graph", Route: route, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// ResponseError ties the error to its call, so a gap from it names
		// the call and the permission it needs.
		return nil, nil, componentsdk.ResponseError(resp, graphAPIError(resp.StatusCode, route, resp.Header, respBody))
	}
	if len(respBody) > maxResponseBytes {
		return nil, nil, tooLarge("graph", route)
	}
	return respBody, resp, nil
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

func graphAPIError(status int, route string, header http.Header, body []byte) *APIError {
	apiErr := &APIError{Service: "graph", StatusCode: status, Route: route, Body: string(body), Header: header}
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
