package microsoft

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const testTenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
const testClientID = "11111111-2222-3333-4444-555555555555"

func TestOIDC(t *testing.T) {
	assertion := signedJWT(map[string]any{"sub": "repo:locktivity/repo:ref:refs/heads/main"})
	accessToken := signedJWT(map[string]any{
		"tid":   testTenantID,
		"roles": []string{"User.Read.All"},
	})

	var sawOIDC bool
	var sawToken bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/oidc":
			sawOIDC = true
			if got := r.Header.Get("Authorization"); got != "Bearer github-request-token" {
				t.Fatalf("unexpected OIDC authorization header: %s", got)
			}
			if got := r.URL.Query().Get("audience"); got != defaultOIDCAudience {
				t.Fatalf("unexpected audience: %s", got)
			}
			return jsonResponse(http.StatusOK, map[string]string{"value": assertion}), nil
		case "/" + testTenantID + "/oauth2/v2.0/token":
			sawToken = true
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Fatalf("unexpected grant_type: %s", got)
			}
			if got := r.Form.Get("client_assertion"); got != assertion {
				t.Fatalf("unexpected client_assertion: %s", got)
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
		TenantID:          testTenantID,
		ClientID:          testClientID,
		AuthMode:          "oidc",
		OIDCRequestURL:    "https://actions.test/oidc",
		OIDCRequestToken:  "github-request-token",
		TokenEndpointBase: "https://login.test",
		HTTPClient:        client,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != accessToken {
		t.Fatalf("unexpected access token: %s", token)
	}
	if !sawOIDC || !sawToken {
		t.Fatalf("expected OIDC and token endpoints to be called")
	}
}

func TestOIDCRejectsDelegatedToken(t *testing.T) {
	if err := validateAppOnlyToken(signedJWT(map[string]any{
		"tid": testTenantID,
		"scp": "User.Read",
	}), testTenantID, GraphScope); err == nil {
		t.Fatal("expected delegated token to be rejected")
	}
}

func signedJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "none"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, value any) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}
