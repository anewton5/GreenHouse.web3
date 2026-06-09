package gonetwork

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetryHTTP_NonIdempotentRequest_NotRetried(t *testing.T) {
	attempts := 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: false},
		func(ctx context.Context) (*http.Response, error) {
			attempts++
			return nil, errors.New("connection reset")
		},
	)

	require.Error(t, err)
	require.Equal(t, 1, attempts)
}
func TestRetryHTTP_IdempotentRequest_RetriesUntilSuccess(t *testing.T) {
	attempts := 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {
			attempts++

			if attempts < 3 {
				return nil, errors.New("network error")
			}

			return &http.Response{
				StatusCode: 200,
				Body:       http.NoBody,
			}, nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 3, attempts)
}

func TestRetryHTTP_RetriesOn5xx(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {
			attempts++

			if attempts < 3 {
				return &http.Response{
					StatusCode: 500,
					Body:       http.NoBody,
				}, nil
			}

			return &http.Response{
				StatusCode: 200,
				Body:       http.NoBody,
			}, nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 3, attempts)
}

func TestRetryHTTP_ContextCancellation_StopsImmediately(t *testing.T) {
	attempts := 0

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {
			attempts++
			return nil, errors.New("network error")
		},
	)

	require.Error(t, err)
	require.Equal(t, 0, attempts)
}

func TestRetryJitter_AlwaysWithinBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		j := paymentRetryJitter()
		require.GreaterOrEqual(t, j, -0.1)
		require.LessOrEqual(t, j, 0.1)
	}
}
