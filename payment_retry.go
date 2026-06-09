package gonetwork

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

var (
	// Backoff schedule (deterministic, bounded growth)
	paymentRetryBackoffs = []time.Duration{
		0,
		500 * time.Millisecond,
		2 * time.Second,
	}

	paymentRetryJitter = func() float64 {
		jitterMu.Lock()
		defer jitterMu.Unlock()

		// ±10% jitter
		return jitterSource.Float64()*0.2 - 0.1
	}

	jitterSource = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))
	jitterMu     sync.Mutex
)

type retryConfig struct {
	maxAttempts int

	// safeToRetry allows retrying non-idempotent methods (e.g. POST)
	// ONLY when caller guarantees idempotency via external mechanism
	// (Idempotency-Key, deduplication store, etc).
	safeToRetry bool
}

func retryHTTPWithConfig(
	ctx context.Context,
	cfg retryConfig,
	fn func(ctx context.Context) (*http.Response, error),
) (*http.Response, error) {

	if cfg.maxAttempts <= 0 {
		cfg.maxAttempts = 1
	}

	var lastErr error

	for attempt := 0; attempt < cfg.maxAttempts; attempt++ {

		// 1. fast cancel check (pre-request)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// 2. execute request
		resp, err := fn(ctx)

		// -------------------------
		// SUCCESS PATH
		// -------------------------
		if err == nil {
			if resp.StatusCode < 500 {
				return resp, nil
			}

			// last attempt → return server response
			if attempt == cfg.maxAttempts-1 {
				return resp, nil
			}

			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		} else {
			lastErr = err

			// hard abort on context cancellation
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}

			// last attempt → stop
			if attempt == cfg.maxAttempts-1 {
				break
			}

			// CRITICAL SAFETY RULE:
			// Do NOT retry unsafe POST unless explicitly allowed.
			if !cfg.safeToRetry {
				break
			}
		}

		// 3. compute backoff
		delay := retryDelayForAttempt(attempt)

		// 4. clamp to context deadline (H-1 compliance)
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)

			if remaining <= 0 {
				return nil, context.DeadlineExceeded
			}

			if delay > remaining {
				delay = remaining
			}
		}

		// 5. wait interruptibly
		if err := waitRetry(ctx, delay); err != nil {
			return nil, err
		}
	}

	return nil, lastErr
}

// ------------------------------------------------------------
// BACKWARD COMPAT WRAPPER (optional legacy support)
// ------------------------------------------------------------

func retryHTTP(
	ctx context.Context,
	cfg retryConfig,
	fn func(ctx context.Context) (*http.Response, error),
) (*http.Response, error) {
	return retryHTTPWithConfig(ctx, cfg, fn)
}

func waitRetry(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Nanosecond
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryDelayForAttempt(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	base := paymentRetryBackoffs[len(paymentRetryBackoffs)-1]

	if attempt < len(paymentRetryBackoffs) {
		base = paymentRetryBackoffs[attempt]
	}

	if base <= 0 {
		return 0
	}

	j := paymentRetryJitter()

	// clamp jitter for safety
	if j < -0.1 {
		j = -0.1
	}
	if j > 0.1 {
		j = 0.1
	}

	return time.Duration(float64(base) * (1 + j))
}
