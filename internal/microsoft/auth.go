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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	GraphScope = "https://graph.microsoft.com/.default"
	ARMScope   = "https://management.azure.com/.default"

	DefaultTokenEndpointBase = "https://login.microsoftonline.com"

	clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	defaultOIDCAudience          = "api://AzureADTokenExchange"

	// FederatedTokenFileEnv names the file a CI job or a workload identity
	// writes the run's identity token to, the variable Azure's own SDKs read
	// for the same purpose.
	FederatedTokenFileEnv = "AZURE_FEDERATED_TOKEN_FILE"
)

// AuthError is a failure to get a usable access token. It unwraps to the
// cause, so componentsdk.Classify codes it by the token endpoint's status, a
// transport failure, or the code the token source chose.
type AuthError struct{ Err error }

func (e AuthError) Error() string { return e.Err.Error() }
func (e AuthError) Unwrap() error { return e.Err }

// TokenError is an error response from a token endpoint.
type TokenError struct {
	Endpoint   string
	StatusCode int
	Header     http.Header
	OAuthCode  string
	Body       string
	// rejects400 marks the Entra token endpoint, which answers credentials
	// it rejects, such as a federated subject it does not trust, with 400.
	rejects400 bool
}

func newTokenError(endpoint string, resp *http.Response, body []byte, rejects400 bool) *TokenError {
	return &TokenError{
		Endpoint:   endpoint,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		OAuthCode:  oauthErrorCode(body),
		Body:       string(body),
		rejects400: rejects400,
	}
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("%s request failed: status=%d body=%s", e.Endpoint, e.StatusCode, e.Body)
}

func (e *TokenError) HTTPStatus() int         { return e.StatusCode }
func (e *TokenError) HTTPHeader() http.Header { return e.Header }
func (e *TokenError) VendorCode() string      { return e.OAuthCode }

func (e *TokenError) CollectionCode() componentsdk.Code {
	if e.rejects400 && e.StatusCode == http.StatusBadRequest {
		return componentsdk.CodeAuthFailed
	}
	return ""
}

// oauthErrorCode reads the error code from an OAuth error, which carries it
// as a string, or from a Graph-style error object.
func oauthErrorCode(body []byte) string {
	var oauth struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &oauth) == nil && oauth.Error != "" {
		return oauth.Error
	}
	var graph struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &graph) == nil {
		return graph.Error.Code
	}
	return ""
}

type Credentials struct {
	TenantID         string
	ClientID         string
	AuthMode         string
	ClientSecret     string
	OIDCRequestURL   string
	OIDCRequestToken string
	// FederatedTokenFile names a file holding an identity token from an
	// issuer the app registration trusts, such as a GitLab job's ID token.
	// OIDC mode reads it outside GitHub Actions, on every exchange, so a job
	// that refreshes the file is picked up.
	FederatedTokenFile string
	Scope              string
	TokenEndpointBase  string
	HTTPClient         *http.Client
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
	roles     []string
	expiresAt time.Time
}

func NewTokenSource(credentials Credentials) (*TokenSource, error) {
	if credentials.Scope == "" {
		credentials.Scope = GraphScope
	}
	if credentials.TokenEndpointBase == "" {
		credentials.TokenEndpointBase = DefaultTokenEndpointBase
	}
	client := credentials.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	switch credentials.AuthMode {
	case "oidc":
		if !credentials.githubOIDC() && credentials.FederatedTokenFile == "" {
			return nil, authFailed(fmt.Errorf("oidc authentication requires ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN in GitHub Actions, or %s naming a token file elsewhere", FederatedTokenFileEnv))
		}
	case "client_secret":
		if credentials.ClientSecret == "" {
			return nil, authFailed(errors.New("client_secret authentication requires AZURE_CLIENT_SECRET"))
		}
	default:
		return nil, authFailed(fmt.Errorf("unsupported auth_mode %q", credentials.AuthMode))
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
	s.roles = tokenRoles(token)
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.token, nil
}

// Roles returns the application roles in the last token acquired.
func (s *TokenSource) Roles() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.roles...)
}

func authFailed(err error) error {
	return AuthError{Err: componentsdk.CodeError(componentsdk.CodeAuthFailed, err)}
}

func (s *TokenSource) acquire(ctx context.Context) (string, int, error) {
	switch s.credentials.AuthMode {
	case "oidc":
		assertion, err := s.oidcAssertion(ctx)
		if err != nil {
			return "", 0, err
		}
		token, expiresIn, err := s.exchangeOIDCAssertion(ctx, assertion)
		if err != nil {
			return "", 0, RedactError(err, assertion)
		}
		return token, expiresIn, nil
	case "client_secret":
		return s.exchangeClientSecret(ctx)
	default:
		return "", 0, fmt.Errorf("unsupported auth_mode %q", s.credentials.AuthMode)
	}
}

// oidcAssertion returns the identity token to exchange: GitHub's when the
// workflow exposes its token endpoint, otherwise the one in the file
// AZURE_FEDERATED_TOKEN_FILE names.
func (s *TokenSource) oidcAssertion(ctx context.Context) (string, error) {
	if s.credentials.githubOIDC() {
		return s.githubOIDCToken(ctx)
	}
	return s.federatedTokenFromFile()
}

func (c Credentials) githubOIDC() bool {
	return c.OIDCRequestURL != "" && c.OIDCRequestToken != ""
}

func (s *TokenSource) githubOIDCToken(ctx context.Context) (string, error) {
	requestURL, err := url.Parse(s.credentials.OIDCRequestURL)
	if err != nil {
		return "", componentsdk.CodeError(componentsdk.CodeConfigInvalid, errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a valid URL"))
	}
	q := requestURL.Query()
	if q.Get("audience") == "" {
		q.Set("audience", defaultOIDCAudience)
		requestURL.RawQuery = q.Encode()
	}

	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: "github.id_token.get", Permission: "id-token:write"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.credentials.OIDCRequestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", &RequestError{Service: "GitHub OIDC token", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", &RequestError{Service: "GitHub OIDC token", Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", newTokenError("GitHub OIDC token", resp, body, false)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decoding the GitHub OIDC token response: %w", err)
	}
	if payload.Value == "" {
		return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("GitHub OIDC token response missing value"))
	}
	return payload.Value, nil
}

func (s *TokenSource) federatedTokenFromFile() (string, error) {
	path := s.credentials.FederatedTokenFile
	token, err := os.ReadFile(path)
	if err != nil {
		return "", componentsdk.CodeError(componentsdk.CodeAuthFailed, fmt.Errorf("reading federated token file %s (%s): %w", path, FederatedTokenFileEnv, err))
	}
	assertion := strings.TrimSpace(string(token))
	if assertion == "" {
		return "", componentsdk.CodeError(componentsdk.CodeAuthFailed, fmt.Errorf("federated token file %s (%s) is empty", path, FederatedTokenFileEnv))
	}
	return assertion, nil
}

func (s *TokenSource) exchangeOIDCAssertion(ctx context.Context, assertion string) (string, int, error) {
	form := url.Values{}
	form.Set("client_id", s.credentials.ClientID)
	form.Set("scope", s.credentials.Scope)
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	token, expiresIn, err := s.tokenRequest(ctx, form, assertion)
	if err != nil {
		return "", 0, describeFederatedCredentialMismatch(err, assertion, s.credentials.githubOIDC())
	}
	return token, expiresIn, nil
}

func isFederatedCredentialMismatch(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "AADSTS70021") || strings.Contains(msg, "No matching federated identity record")
}

// The error includes the token's subject claim, which holds only repository
// and branch names. The assertion is a credential and must not be printed.
func describeFederatedCredentialMismatch(err error, assertion string, githubToken bool) error {
	if !isFederatedCredentialMismatch(err) {
		return err
	}
	claims, claimsErr := decodeJWTClaims(assertion)
	if claimsErr != nil {
		return err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return err
	}
	if !githubToken {
		return fmt.Errorf("the token's subject is %q and Entra has no federated credential matching it. On the app registration, create or edit a federated credential with the Other issuer scenario whose subject is exactly this value: %w", sub, err)
	}
	return fmt.Errorf("the GitHub token's subject is %q and Entra has no federated credential matching it. On the app registration, create or edit a federated credential whose subject is exactly this value. The portal form expects GitHub's immutable subject format; a repository that still sends the name-based format needs the Edit (optional) override on the Subject identifier field: %w", sub, err)
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
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: "login.token.create", Safe: true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, &RequestError{Service: "token", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, &RequestError{Service: "token", Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, RedactError(newTokenError("token", resp, body, true), secrets...)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, fmt.Errorf("decoding the token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", 0, componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("token response missing access_token"))
	}
	if !strings.EqualFold(payload.TokenType, "Bearer") && payload.TokenType != "" {
		return "", 0, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("unexpected token_type %q", payload.TokenType))
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}

func validateAppOnlyToken(token, tenantID, scope string) error {
	claims, err := decodeJWTClaims(token)
	if err != nil {
		return componentsdk.CodeError(componentsdk.CodeAuthFailed, err)
	}
	if scp, ok := claims["scp"].(string); ok && scp != "" {
		return componentsdk.CodeError(componentsdk.CodeAuthFailed, errors.New("delegated Microsoft Graph tokens are not supported"))
	}
	if tid, ok := claims["tid"].(string); ok && tenantID != "" && !strings.EqualFold(tid, tenantID) {
		return componentsdk.CodeError(componentsdk.CodeAuthFailed, fmt.Errorf("access token tenant %q did not match configured tenant", tid))
	}
	if scope == ARMScope {
		return nil
	}
	roles, ok := claims["roles"].([]any)
	if !ok || len(roles) == 0 {
		return componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("access token is missing application roles"))
	}
	return nil
}

func tokenRoles(token string) []string {
	claims, err := decodeJWTClaims(token)
	if err != nil {
		return nil
	}
	raw, _ := claims["roles"].([]any)
	roles := make([]string, 0, len(raw))
	for _, role := range raw {
		if name, ok := role.(string); ok && name != "" {
			roles = append(roles, name)
		}
	}
	return roles
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
