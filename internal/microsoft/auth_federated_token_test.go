package microsoft

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFederatedTokenFromFile(t *testing.T) {
	assertion := signedJWT(map[string]any{"sub": "project_path:northwind/compliance:ref_type:branch:ref:main"})
	accessToken := signedJWT(map[string]any{
		"tid":   testTenantID,
		"roles": []string{"User.Read.All"},
	})
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(assertion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var sawToken bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/" + testTenantID + "/oauth2/v2.0/token":
			sawToken = true
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("client_assertion"); got != assertion {
				t.Fatalf("unexpected client_assertion: %s", got)
			}
			if got := r.Form.Get("client_assertion_type"); got != clientAssertionTypeJWTBearer {
				t.Fatalf("unexpected client_assertion_type: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"token_type":   "Bearer",
				"access_token": accessToken,
				"expires_in":   3600,
			}), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		return nil, nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:           testTenantID,
		ClientID:           testClientID,
		AuthMode:           "oidc",
		FederatedTokenFile: path,
		TokenEndpointBase:  "https://login.test",
		HTTPClient:         client,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != accessToken || !sawToken {
		t.Fatalf("expected the exchanged access token, got %q (token endpoint called: %v)", token, sawToken)
	}
}

func TestFederatedTokenFileErrorsNameTheVariable(t *testing.T) {
	_, err := NewTokenSource(Credentials{TenantID: testTenantID, ClientID: testClientID, AuthMode: "oidc"})
	if err == nil || !strings.Contains(err.Error(), FederatedTokenFileEnv) {
		t.Fatalf("NewTokenSource() error = %v, want one naming %s", err, FederatedTokenFileEnv)
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), empty} {
		source, err := NewTokenSource(Credentials{
			TenantID:           testTenantID,
			ClientID:           testClientID,
			AuthMode:           "oidc",
			FederatedTokenFile: path,
			TokenEndpointBase:  "https://login.test",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected request to %s", r.URL.Path)
				return nil, nil
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = source.AccessToken(context.Background())
		if err == nil || !strings.Contains(err.Error(), FederatedTokenFileEnv) {
			t.Fatalf("path %q: AccessToken() error = %v, want one naming %s", path, err, FederatedTokenFileEnv)
		}
	}
}

func TestFederatedTokenMismatchNamesTheSubjectWithoutGitHubAdvice(t *testing.T) {
	subject := "project_path:northwind/compliance:ref_type:branch:ref:main"
	assertion := signedJWT(map[string]any{"sub": subject})
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(assertion), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "AADSTS70021: No matching federated identity record found for presented assertion.",
		}), nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:           testTenantID,
		ClientID:           testClientID,
		AuthMode:           "oidc",
		FederatedTokenFile: path,
		TokenEndpointBase:  "https://login.test",
		HTTPClient:         client,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.AccessToken(context.Background())
	if err == nil {
		t.Fatal("AccessToken() error = nil, want federated credential guidance")
	}
	msg := err.Error()
	if !strings.Contains(msg, subject) || !strings.Contains(msg, "Other issuer") {
		t.Errorf("AccessToken() error = %q, want the subject and the Other issuer scenario", msg)
	}
	if strings.Contains(msg, "GitHub") || strings.Contains(msg, assertion) {
		t.Errorf("AccessToken() error = %q, must not mention GitHub or carry the assertion", msg)
	}
}

func TestOIDCPrefersGitHubTokenOverFile(t *testing.T) {
	githubAssertion := signedJWT(map[string]any{"sub": "repo:northwind/compliance:ref:refs/heads/main"})
	fileAssertion := signedJWT(map[string]any{"sub": "project_path:northwind/compliance:ref_type:branch:ref:main"})
	accessToken := signedJWT(map[string]any{"tid": testTenantID, "roles": []string{"User.Read.All"}})
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(fileAssertion), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/github/token":
			return jsonResponse(http.StatusOK, map[string]any{"value": githubAssertion}), nil
		case "/" + testTenantID + "/oauth2/v2.0/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("client_assertion"); got != githubAssertion {
				t.Fatalf("expected GitHub's token as the client_assertion, got the file's: %v", got == fileAssertion)
			}
			return jsonResponse(http.StatusOK, map[string]any{"token_type": "Bearer", "access_token": accessToken, "expires_in": 3600}), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		return nil, nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:           testTenantID,
		ClientID:           testClientID,
		AuthMode:           "oidc",
		OIDCRequestURL:     "https://github.test/github/token",
		OIDCRequestToken:   "request-token",
		FederatedTokenFile: path,
		TokenEndpointBase:  "https://login.test",
		HTTPClient:         client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
}
