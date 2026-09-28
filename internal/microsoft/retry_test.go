package microsoft

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClientsReportExhaustedRetries(t *testing.T) {
	tests := []struct {
		name      string
		respond   func() (*http.Response, error)
		attempts  int
		exhausted bool
		status    int
	}{
		{
			name:      "server error with empty body",
			respond:   func() (*http.Response, error) { return textResponse(http.StatusInternalServerError, "", nil), nil },
			attempts:  maxAttempts,
			exhausted: true,
			status:    http.StatusInternalServerError,
		},
		{
			name:      "throttled",
			respond:   func() (*http.Response, error) { return textResponse(http.StatusTooManyRequests, "", nil), nil },
			attempts:  maxAttempts,
			exhausted: true,
			status:    http.StatusTooManyRequests,
		},
		{
			name:      "no response",
			respond:   func() (*http.Response, error) { return nil, errors.New("connection reset") },
			attempts:  maxAttempts,
			exhausted: true,
		},
		{
			name:     "forbidden",
			respond:  func() (*http.Response, error) { return textResponse(http.StatusForbidden, "", nil), nil },
			attempts: 1,
			status:   http.StatusForbidden,
		},
	}

	noSleep := func(context.Context, time.Duration) error { return nil }
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return tt.respond()
			})}
			arm := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient), WithARMSleeper(noSleep))
			graph := NewGraphClient(StaticTokenSource("token"), WithGraphBaseURL("https://graph.test/v1.0"), WithGraphHTTPClient(httpClient), WithRetrySleeper(noSleep))

			_, armErr := arm.DefenderAssessments(context.Background(), "sub-1")
			_, graphErr := graph.Users(context.Background())
			if calls != 2*tt.attempts {
				t.Fatalf("expected %d attempts per client, got %d calls", tt.attempts, calls)
			}
			for service, err := range map[string]error{"arm": armErr, "graph": graphErr} {
				if err == nil {
					t.Fatalf("%s: expected an error", service)
				}
				if got := RetriesExhausted(err); got != tt.exhausted {
					t.Fatalf("%s: expected exhausted=%t, got %t for %v", service, tt.exhausted, got, err)
				}
				var apiErr *APIError
				if tt.status != 0 && (!errors.As(err, &apiErr) || apiErr.StatusCode != tt.status) {
					t.Fatalf("%s: expected API error with status %d, got %v", service, tt.status, err)
				}
			}
		})
	}
}

func TestCancelledContextDoesNotReportExhaustedRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		return nil, r.Context().Err()
	})}
	client := NewARMClient(StaticTokenSource("arm-token"), WithARMBaseURL("https://management.test"), WithARMHTTPClient(httpClient), WithARMSleeper(func(context.Context, time.Duration) error { return nil }))

	_, err := client.DefenderAssessments(ctx, "sub-1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if RetriesExhausted(err) {
		t.Fatalf("expected a cancelled context not to report exhausted retries, got %v", err)
	}
}
