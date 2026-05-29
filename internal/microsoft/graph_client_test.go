package microsoft

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGraphClientPagesAndRetries(t *testing.T) {
	var usersCalls int
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		betaSegment := "/" + "beta" + "/"
		if strings.Contains(r.URL.Path, betaSegment) {
			t.Fatalf("beta path used: %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1.0/users":
			if r.URL.Query().Get("page") == "2" {
				return jsonResponse(http.StatusOK, map[string]any{
					"value": []map[string]any{
						{"id": "u2", "accountEnabled": false, "userType": "Member"},
					},
				}), nil
			}
			usersCalls++
			if usersCalls == 1 {
				return textResponse(http.StatusTooManyRequests, "retry", map[string]string{"Retry-After": "0"}), nil
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{"id": "u1", "accountEnabled": true, "userType": "Member"},
				},
				"@odata.nextLink": "https://graph.test/v1.0/users?page=2",
			}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient), WithRetrySleeper(func(context.Context, time.Duration) error { return nil }))
	users, err := client.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if usersCalls != 2 {
		t.Fatalf("expected retry, got %d calls", usersCalls)
	}
}

func TestGraphClientRejectsCrossOriginNextLink(t *testing.T) {
	var calls int
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatalf("unexpected request to %s", r.URL.String())
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"value":           []map[string]any{{"id": "u1"}},
			"@odata.nextLink": "https://evil.test/v1.0/users?page=2",
		}), nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	_, err := client.Users(context.Background())
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

func TestGraphClientPolicyRoutes(t *testing.T) {
	seen := map[string]bool{}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/v1.0/identity/conditionalAccess/policies":
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{
						"id":    "policy-1",
						"state": "enabled",
						"grantControls": map[string]any{
							"builtInControls": []string{"mfa"},
						},
					},
				},
			}), nil
		case "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy":
			return jsonResponse(http.StatusOK, map[string]any{"isEnabled": true}), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		return nil, nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	policies, err := client.ConditionalAccessPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].ID != "policy-1" {
		t.Fatalf("unexpected policies: %#v", policies)
	}
	defaults, err := client.SecurityDefaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if defaults == nil || !defaults.IsEnabled {
		t.Fatalf("unexpected defaults: %#v", defaults)
	}
	if !seen["/v1.0/identity/conditionalAccess/policies"] || !seen["/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"] {
		t.Fatalf("missing expected routes: %#v", seen)
	}
}

func TestGraphClientB2Routes(t *testing.T) {
	seen := map[string]bool{}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/v1.0/users":
			if !strings.Contains(r.URL.RawQuery, "signInActivity") {
				t.Fatalf("expected signInActivity select, got %s", r.URL.RawQuery)
			}
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "u1"}}}), nil
		case "/v1.0/roleManagement/directory/roleAssignments":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "ra1", "principalId": "u1", "roleDefinitionId": "role-1"}}}), nil
		case "/v1.0/roleManagement/directory/roleEligibilitySchedules":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "rs1", "principalId": "u1", "roleDefinitionId": "role-1"}}}), nil
		case "/v1.0/servicePrincipals":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "sp1", "servicePrincipalType": "Application"}}}), nil
		case "/v1.0/applications":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"id": "app1"}}}), nil
		case "/v1.0/security/secureScores":
			return jsonResponse(http.StatusOK, map[string]any{"value": []map[string]any{{"currentScore": 1, "maxScore": 2}}}), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		return nil, nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	if _, err := client.UsersWithSignInActivity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RoleAssignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RoleEligibilitySchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ServicePrincipals(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Applications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SecureScores(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1.0/users",
		"/v1.0/roleManagement/directory/roleAssignments",
		"/v1.0/roleManagement/directory/roleEligibilitySchedules",
		"/v1.0/servicePrincipals",
		"/v1.0/applications",
		"/v1.0/security/secureScores",
	} {
		if !seen[path] {
			t.Fatalf("missing expected route %s in %#v", path, seen)
		}
	}
}

func TestGraphClientDirectoryAuditRoute(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1.0/auditLogs/directoryAudits":
			if got := r.URL.Query().Get("$top"); got != "999" {
				t.Fatalf("unexpected top: %s", got)
			}
			if got := r.URL.Query().Get("$orderby"); got != "activityDateTime desc" {
				t.Fatalf("unexpected orderby: %s", got)
			}
			if got := r.URL.Query().Get("$filter"); got != "activityDateTime ge 2026-05-19T14:12:09Z" {
				t.Fatalf("unexpected filter: %s", got)
			}
			if !strings.Contains(r.URL.Query().Get("$select"), "targetResources") {
				t.Fatalf("expected targetResources select, got %s", r.URL.Query().Get("$select"))
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{
						"id":              "audit-a",
						"category":        "UserManagement",
						"operationType":   "Add",
						"result":          "success",
						"targetResources": []map[string]any{{"type": "User"}},
					},
				},
			}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	audits, err := client.DirectoryAudits(context.Background(), time.Date(2026, 5, 19, 14, 12, 9, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].Category != "UserManagement" {
		t.Fatalf("unexpected directory audits: %#v", audits)
	}
}

func TestGraphClientSignInRoute(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1.0/auditLogs/signIns":
			if got := r.URL.Query().Get("$top"); got != "999" {
				t.Fatalf("unexpected top: %s", got)
			}
			if got := r.URL.Query().Get("$orderby"); got != "createdDateTime desc" {
				t.Fatalf("unexpected orderby: %s", got)
			}
			if got := r.URL.Query().Get("$filter"); got != "createdDateTime ge 2026-05-19T14:12:09Z" {
				t.Fatalf("unexpected filter: %s", got)
			}
			if !strings.Contains(r.URL.Query().Get("$select"), "appliedConditionalAccessPolicies") {
				t.Fatalf("expected appliedConditionalAccessPolicies select, got %s", r.URL.Query().Get("$select"))
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"value": []map[string]any{
					{
						"id":                      "signin-a",
						"userId":                  "u1",
						"appId":                   "app1",
						"conditionalAccessStatus": "success",
						"status":                  map[string]any{"errorCode": 0},
						"appliedConditionalAccessPolicies": []map[string]any{
							{"id": "policy-a", "result": "success"},
						},
					},
				},
			}), nil
		default:
			t.Fatalf("unexpected path: %s raw=%s", r.URL.Path, r.URL.String())
		}
		return nil, nil
	})}

	client := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	signIns, err := client.SignIns(context.Background(), time.Date(2026, 5, 19, 14, 12, 9, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(signIns) != 1 || signIns[0].AppliedConditionalAccessPolicies[0].ID != "policy-a" {
		t.Fatalf("unexpected sign-ins: %#v", signIns)
	}
}

func textResponse(status int, body string, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	return resp
}
