package microsoft

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestAPIErrorsClassifyByStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		want   componentsdk.Code
	}{
		{"denied", http.StatusForbidden, nil, componentsdk.CodePermissionDenied},
		{"throttled 403", http.StatusForbidden, http.Header{"Retry-After": []string{"5"}}, componentsdk.CodeRateLimited},
		{"server error", http.StatusInternalServerError, nil, componentsdk.CodeVendorError},
		{"not found", http.StatusNotFound, nil, componentsdk.CodeInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := armAPIError(tc.status, "/subscriptions/sub-1", tc.header, []byte(`{"error":{"code":"AuthorizationFailed","message":"denied"}}`))
			if got := componentsdk.Classify(err); got != tc.want {
				t.Fatalf("Classify() = %s, want %s", got, tc.want)
			}
			if got := componentsdk.VendorCodeOf(err); got != "AuthorizationFailed" {
				t.Fatalf("VendorCodeOf() = %q, want the ARM error code", got)
			}
		})
	}
}

func TestListWithoutValueIsAnInvalidResponse(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{}), nil
	})}
	graph := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	arm := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))

	_, graphErr := graph.Users(context.Background())
	_, armErr := arm.StorageAccounts(context.Background(), "sub-1")
	_, summaryErr := arm.PolicyStateSummary(context.Background(), "sub-1")
	_, defaultsErr := graph.SecurityDefaults(context.Background())
	for name, err := range map[string]error{"graph list": graphErr, "arm list": armErr, "policy summary": summaryErr, "security defaults": defaultsErr} {
		if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
			t.Errorf("%s: Classify(%v) = %s, want invalid_response", name, err, got)
		}
	}
}

func TestEveryCallIsNamed(t *testing.T) {
	seen := map[string]bool{}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		op, ok := componentsdk.OperationOf(r.Context())
		if !ok {
			t.Fatalf("unnamed call to %s", r.URL.Path)
		}
		seen[op.Name] = true
		if r.Method == http.MethodPost && !op.Safe {
			t.Fatalf("POST %s is not marked Safe", op.Name)
		}
		return jsonResponse(http.StatusOK, map[string]any{"value": []any{}}), nil
	})}
	graph := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	arm := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	ctx := context.Background()

	_, _ = graph.Users(ctx)
	_, _ = arm.PolicyStateSummary(ctx, "sub-1")
	_, _ = arm.DiagnosticSettings(ctx, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa")
	for _, name := range []string{"graph.users.list", "arm.policy.states.summarize", "arm.monitor.diagnostic_settings.list"} {
		if !seen[name] {
			t.Errorf("no call named %s; saw %v", name, seen)
		}
	}
}

func TestTokenErrorsKeepTheirCode(t *testing.T) {
	cases := []struct {
		name    string
		respond func() (*http.Response, error)
		want    componentsdk.Code
		vendor  string
	}{
		{
			name:    "server error",
			respond: func() (*http.Response, error) { return textResponse(http.StatusServiceUnavailable, "", nil), nil },
			want:    componentsdk.CodeVendorError,
		},
		{
			name: "rejected subject",
			respond: func() (*http.Response, error) {
				return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "AADSTS700213: No matching federated identity record found."}), nil
			},
			want:   componentsdk.CodeAuthFailed,
			vendor: "invalid_request",
		},
		{
			name: "connection reset",
			respond: func() (*http.Response, error) {
				return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
			},
			want: componentsdk.CodeVendorError,
		},
		{
			name:    "malformed body",
			respond: func() (*http.Response, error) { return textResponse(http.StatusOK, "{not json", nil), nil },
			want:    componentsdk.CodeInvalidResponse,
		},
		{
			name: "no access token",
			respond: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, map[string]any{"token_type": "Bearer"}), nil
			},
			want: componentsdk.CodeInvalidResponse,
		},
		{
			name: "no application roles",
			respond: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, map[string]any{"token_type": "Bearer", "access_token": signedJWT(map[string]any{"tid": testTenantID})}), nil
			},
			want: componentsdk.CodePermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, err := NewTokenSource(Credentials{
				TenantID:          testTenantID,
				ClientID:          testClientID,
				AuthMode:          "client_secret",
				ClientSecret:      "super-secret",
				TokenEndpointBase: "https://login.test",
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if op, ok := componentsdk.OperationOf(r.Context()); !ok || op.Name != "login.token.create" || !op.Safe {
						t.Fatalf("token request named %#v, want login.token.create marked Safe", op)
					}
					return tc.respond()
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.AccessToken(context.Background())
			var authErr AuthError
			if !errors.As(err, &authErr) {
				t.Fatalf("AccessToken() error = %v, want an AuthError", err)
			}
			if got := componentsdk.Classify(err); got != tc.want {
				t.Fatalf("Classify(%v) = %s, want %s", err, got, tc.want)
			}
			if got := componentsdk.VendorCodeOf(err); got != tc.vendor {
				t.Fatalf("VendorCodeOf() = %q, want %q", got, tc.vendor)
			}
			if strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("secret leaked in error: %s", err)
			}
		})
	}
}

func TestRequestErrorsOmitTheURL(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	})}
	arm := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))
	_, err := arm.DiagnosticSettings(context.Background(), "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/secret-name")
	if got := componentsdk.Classify(err); got != componentsdk.CodeVendorError {
		t.Fatalf("Classify(%v) = %s, want vendor_error", err, got)
	}
	for _, forbidden := range []string{"management.test", "prod-rg", "secret-name", "api-version=2021"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error %q contains %q", err, forbidden)
		}
	}
}

func TestGitHubTokenFailureIsNamedAndClassified(t *testing.T) {
	source, err := NewTokenSource(Credentials{
		TenantID:          testTenantID,
		ClientID:          testClientID,
		AuthMode:          "oidc",
		OIDCRequestURL:    "https://actions.test/oidc?api-version=2.0",
		OIDCRequestToken:  "github-request-token",
		TokenEndpointBase: "https://login.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if op, ok := componentsdk.OperationOf(r.Context()); !ok || op.Name != "github.id_token.get" {
				t.Fatalf("GitHub token request named %#v", op)
			}
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.AccessToken(context.Background())
	if got := componentsdk.Classify(err); got != componentsdk.CodeVendorError {
		t.Fatalf("Classify(%v) = %s, want vendor_error", err, got)
	}
	if strings.Contains(err.Error(), "actions.test") {
		t.Fatalf("error %q names the request URL", err)
	}
}

func TestTemplateRouteDropsResourceNames(t *testing.T) {
	cases := map[string]string{
		"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/payments-rg/providers/Microsoft.Sql/servers/ledger/databases/appdb/transparentDataEncryption/current": "/subscriptions/{id}/resourceGroups/{name}/providers/Microsoft.Sql/servers/{name}/databases/{name}/transparentDataEncryption/{name}",
		"/subscriptions/sub-1/resourceGroups/compute/providers/Microsoft.Compute/virtualMachines/vm-a/providers/Microsoft.Insights/diagnosticSettings":                            "/subscriptions/{id}/resourceGroups/{name}/providers/Microsoft.Compute/virtualMachines/{name}/providers/Microsoft.Insights/diagnosticSettings",
		"/subscriptions/sub-1/resourceGroups/backup/providers/Microsoft.RecoveryServices/vaults/vault-a/backupJobs":                                                               "/subscriptions/{id}/resourceGroups/{name}/providers/Microsoft.RecoveryServices/vaults/{name}/backupJobs",
		"/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts":                                                                                                        "/subscriptions/{id}/providers/Microsoft.Storage/storageAccounts",
		"/v1.0/roleManagement/directory/roleAssignments":                                                                                                                          "/v1.0/roleManagement/directory/roleAssignments",
		"/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token":                                                                                                                 "/{id}/oauth2/v2.0/token",
	}
	for in, want := range cases {
		if got := TemplateRoute(in); got != want {
			t.Errorf("TemplateRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPageLongerThanTheReadLimitIsTooLarge(t *testing.T) {
	long := `{"value":[],"padding":"` + strings.Repeat("x", maxResponseBytes) + `"}`
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(long))}, nil
	})}
	graph := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient))
	arm := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient))

	_, graphErr := graph.Users(context.Background())
	_, armErr := arm.StorageAccounts(context.Background(), "sub-1")
	for name, err := range map[string]error{"graph": graphErr, "arm": armErr} {
		if got := componentsdk.Classify(err); got != componentsdk.CodeTooLarge {
			t.Errorf("%s: Classify(%v) = %s, want too_large", name, err, got)
		}
	}
}
