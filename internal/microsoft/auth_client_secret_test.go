package microsoft

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClientSecret(t *testing.T) {
	accessToken := signedJWT(map[string]any{
		"tid":   testTenantID,
		"roles": []string{"User.Read.All"},
	})

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/"+testTenantID+"/oauth2/v2.0/token" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("client_secret"); got != "super-secret" {
			t.Fatalf("unexpected secret: %s", got)
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"token_type":   "Bearer",
			"access_token": accessToken,
			"expires_in":   3600,
		}), nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:          testTenantID,
		ClientID:          testClientID,
		AuthMode:          "client_secret",
		ClientSecret:      "super-secret",
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
		t.Fatalf("unexpected token: %s", token)
	}
}

func TestClientSecretSupportsARMScope(t *testing.T) {
	accessToken := signedJWT(map[string]any{
		"tid":   testTenantID,
		"roles": []string{"Reader"},
	})
	var gotScope string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotScope = r.Form.Get("scope")
		return jsonResponse(http.StatusOK, map[string]any{
			"token_type":   "Bearer",
			"access_token": accessToken,
			"expires_in":   3600,
		}), nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:          testTenantID,
		ClientID:          testClientID,
		AuthMode:          "client_secret",
		ClientSecret:      "super-secret",
		Scope:             ARMScope,
		TokenEndpointBase: "https://login.test",
		HTTPClient:        client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotScope != ARMScope {
		t.Fatalf("expected ARM scope, got %s", gotScope)
	}
}

func TestClientSecretRedactsSecretFromErrors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("bad secret super-secret")),
		}, nil
	})}

	source, err := NewTokenSource(Credentials{
		TenantID:          testTenantID,
		ClientID:          testClientID,
		AuthMode:          "client_secret",
		ClientSecret:      "super-secret",
		TokenEndpointBase: "https://login.test",
		HTTPClient:        client,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = source.AccessToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("secret leaked in error: %s", err)
	}
}
