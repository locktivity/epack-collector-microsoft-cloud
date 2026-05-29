package microsoft

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	GraphScope = "https://graph.microsoft.com/.default"
	ARMScope   = "https://management.azure.com/.default"

	clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	defaultTokenEndpointBase     = "https://login.microsoftonline.com"
	defaultOIDCAudience          = "api://AzureADTokenExchange"
)

type AuthError struct{ Err error }

func (e AuthError) Error() string { return e.Err.Error() }
func (e AuthError) Unwrap() error { return e.Err }

type Credentials struct {
	TenantID          string
	ClientID          string
	AuthMode          string
	ClientSecret      string
	OIDCRequestURL    string
	OIDCRequestToken  string
	Scope             string
	TokenEndpointBase string
	HTTPClient        *http.Client
}

type AccessTokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}

type StaticTokenSource string

func (s StaticTokenSource) AccessToken(context.Context) (string, error) {
	return string(s), nil
}

type TokenSource struct {
	credentials Credentials
	client      *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewTokenSource(credentials Credentials) (*TokenSource, error) {
	if credentials.Scope == "" {
		credentials.Scope = GraphScope
	}
	if credentials.TokenEndpointBase == "" {
		credentials.TokenEndpointBase = defaultTokenEndpointBase
	}
	client := credentials.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	switch credentials.AuthMode {
	case "oidc":
		if credentials.OIDCRequestURL == "" || credentials.OIDCRequestToken == "" {
			return nil, AuthError{Err: errors.New("oidc authentication requires ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN")}
		}
	case "client_secret":
		if credentials.ClientSecret == "" {
			return nil, AuthError{Err: errors.New("client_secret authentication requires AZURE_CLIENT_SECRET")}
		}
	default:
		return nil, AuthError{Err: fmt.Errorf("unsupported auth_mode %q", credentials.AuthMode)}
	}

	return &TokenSource{credentials: credentials, client: client}, nil
}

func (s *TokenSource) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiresAt.Add(-1*time.Minute)) {
		return s.token, nil
	}

	token, expiresIn, err := s.acquire(ctx)
	if err != nil {
		secrets := []string{s.credentials.ClientSecret, s.credentials.OIDCRequestToken, s.token}
		return "", AuthError{Err: RedactError(err, secrets...)}
	}
	if err := validateAppOnlyToken(token, s.credentials.TenantID, s.credentials.Scope); err != nil {
		return "", AuthError{Err: RedactError(err, token)}
	}

	s.token = token
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.token, nil
}

func (s *TokenSource) acquire(ctx context.Context) (string, int, error) {
	switch s.credentials.AuthMode {
	case "oidc":
		assertion, err := s.githubOIDCToken(ctx)
		if err != nil {
			return "", 0, err
		}
		return s.exchangeOIDCAssertion(ctx, assertion)
	case "client_secret":
		return s.exchangeClientSecret(ctx)
	default:
		return "", 0, fmt.Errorf("unsupported auth_mode %q", s.credentials.AuthMode)
	}
}

func (s *TokenSource) githubOIDCToken(ctx context.Context) (string, error) {
	requestURL, err := url.Parse(s.credentials.OIDCRequestURL)
	if err != nil {
		return "", fmt.Errorf("invalid OIDC request URL: %w", err)
	}
	q := requestURL.Query()
	if q.Get("audience") == "" {
		q.Set("audience", defaultOIDCAudience)
		requestURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.credentials.OIDCRequestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GitHub OIDC token request failed: status=%d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.Value == "" {
		return "", errors.New("GitHub OIDC token response missing value")
	}
	return payload.Value, nil
}

func (s *TokenSource) exchangeOIDCAssertion(ctx context.Context, assertion string) (string, int, error) {
	form := url.Values{}
	form.Set("client_id", s.credentials.ClientID)
	form.Set("scope", s.credentials.Scope)
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	return s.tokenRequest(ctx, form, assertion)
}

func (s *TokenSource) exchangeClientSecret(ctx context.Context) (string, int, error) {
	form := url.Values{}
	form.Set("client_id", s.credentials.ClientID)
	form.Set("scope", s.credentials.Scope)
	form.Set("grant_type", "client_credentials")
	form.Set("client_secret", s.credentials.ClientSecret)
	return s.tokenRequest(ctx, form, s.credentials.ClientSecret)
}

func (s *TokenSource) tokenRequest(ctx context.Context, form url.Values, secrets ...string) (string, int, error) {
	endpoint := strings.TrimRight(s.credentials.TokenEndpointBase, "/") + "/" + url.PathEscape(s.credentials.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, RedactError(fmt.Errorf("token request failed: status=%d body=%s", resp.StatusCode, body), secrets...)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, err
	}
	if payload.AccessToken == "" {
		return "", 0, errors.New("token response missing access_token")
	}
	if !strings.EqualFold(payload.TokenType, "Bearer") && payload.TokenType != "" {
		return "", 0, fmt.Errorf("unexpected token_type %q", payload.TokenType)
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}

func validateAppOnlyToken(token, tenantID, scope string) error {
	claims, err := decodeJWTClaims(token)
	if err != nil {
		return err
	}
	if scp, ok := claims["scp"].(string); ok && scp != "" {
		return errors.New("delegated Microsoft Graph tokens are not supported")
	}
	if tid, ok := claims["tid"].(string); ok && tenantID != "" && !strings.EqualFold(tid, tenantID) {
		return fmt.Errorf("access token tenant %q did not match configured tenant", tid)
	}
	if scope == ARMScope {
		return nil
	}
	roles, ok := claims["roles"].([]any)
	if !ok || len(roles) == 0 {
		return errors.New("access token is missing application roles")
	}
	return nil
}

func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding access token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
