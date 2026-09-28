package microsoft

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const maxAttempts = 5

type RetriesExhaustedError struct{ Err error }

func (e RetriesExhaustedError) Error() string { return e.Err.Error() }
func (e RetriesExhaustedError) Unwrap() error { return e.Err }

func RetriesExhausted(err error) bool {
	var target RetriesExhaustedError
	return errors.As(err, &target)
}

func exhausted(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	return RetriesExhaustedError{Err: err}
}

type sleeper func(context.Context, time.Duration) error

func defaultSleeper(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if raw := resp.Header.Get("Retry-After"); raw != "" {
			if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
				return time.Duration(seconds) * time.Second
			}
			if when, err := http.ParseTime(raw); err == nil {
				if delay := time.Until(when); delay > 0 {
					return delay
				}
			}
		}
	}
	delay := time.Duration(100*(1<<(attempt-1))) * time.Millisecond
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
}
