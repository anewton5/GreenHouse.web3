package gonetwork

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ----------------------------
// EURC Provider
// ----------------------------

type EURCPaymentProvider struct {
	apiKey           string
	baseURL          string
	walletSetID      string
	webhookSecret    string
	client           *http.Client
	store            PaymentStore
	operationTimeout time.Duration

	mu             sync.Mutex
	accounts       map[string]string
	pendingAccount map[string]*eurcAccountRequest
	payments       map[string]PaymentStatus
}

type eurcAccountRequest struct {
	done chan struct{}
	addr string
	err  error
	mu   sync.Mutex
}

type circleWalletResponse struct {
	Data struct {
		Wallet struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"wallet"`
	} `json:"data"`
}

func NewEURCPaymentProviderFromEnv() (*EURCPaymentProvider, error) {
	apiKey := os.Getenv("CIRCLE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("eurc: CIRCLE_API_KEY required")
	}

	baseURL := os.Getenv("CIRCLE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.circle.com/v1"
	}

	walletSetID := os.Getenv("CIRCLE_WALLET_SET_ID")
	if walletSetID == "" {
		return nil, fmt.Errorf("eurc: CIRCLE_WALLET_SET_ID required")
	}

	webhookSecret := os.Getenv("CIRCLE_WEBHOOK_SECRET")

	store := NewMemoryPaymentStore()

	return NewEURCPaymentProvider(apiKey, baseURL, walletSetID, webhookSecret, store)
}

func NewEURCPaymentProvider(apiKey, baseURL, walletSetID, webhookSecret string, store PaymentStore) (*EURCPaymentProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("eurc: apiKey must not be empty")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("eurc: baseURL must not be empty")
	}
	if store == nil {
		return nil, fmt.Errorf("eurc: store must not be nil")
	}
	if webhookSecret == "" {
		return nil, fmt.Errorf("eurc: webhookSecret must not be empty; webhook signature verification is required for production")
	}

	return &EURCPaymentProvider{
		apiKey:           apiKey,
		baseURL:          baseURL,
		walletSetID:      walletSetID,
		webhookSecret:    webhookSecret,
		store:            store,
		client:           &http.Client{Timeout: 30 * time.Second},
		accounts:         make(map[string]string),
		pendingAccount:   make(map[string]*eurcAccountRequest),
		payments:         make(map[string]PaymentStatus),
		operationTimeout: 10 * time.Second,
	}, nil
}

// ----------------------------
// Wallet creation
// ----------------------------

func (e *EURCPaymentProvider) CreateVirtualAccount(
	ctx context.Context,
	walletID string,
) (string, error) {

	ctx, cancel := context.WithTimeout(ctx, e.operationTimeout)
	defer cancel()

	// -------------------------
	// Fast path cache
	// -------------------------
	e.mu.Lock()
	if addr, ok := e.accounts[walletID]; ok {
		e.mu.Unlock()
		return addr, nil
	}

	// -------------------------
	// In-flight dedupe
	// -------------------------
	if req, ok := e.pendingAccount[walletID]; ok {
		e.mu.Unlock()

		select {
		case <-req.done:
		case <-ctx.Done():
			return "", ctx.Err()
		}

		return req.addr, req.err
	}

	// Create request holder
	req := &eurcAccountRequest{
		done: make(chan struct{}),
	}
	e.pendingAccount[walletID] = req
	e.mu.Unlock()

	var (
		resultAddr string
		resultErr  error
	)

	// -------------------------
	// SINGLE-FLIGHT EXECUTION
	// -------------------------
	func() {
		defer func() {
			// ALWAYS finalize exactly once

			e.mu.Lock()
			delete(e.pendingAccount, walletID)
			e.mu.Unlock()

			req.addr = resultAddr
			req.err = resultErr

			// safe close
			select {
			case <-req.done:
			default:
				close(req.done)
			}
		}()

		idempotencyKey := buildIdempotencyKey(walletID)

		payload := map[string]any{
			"idempotencyKey": idempotencyKey,
			"walletSetId":    e.walletSetID,
			"blockchains":    []string{"ETH"},
		}

		body, err := json.Marshal(payload)
		if err != nil {
			resultErr = fmt.Errorf("eurc: marshal error: %w", err)
			return
		}

		endpoint := e.baseURL + "/wallets"

		resp, err := retryHTTPWithConfig(
			ctx,
			retryConfig{maxAttempts: 3, safeToRetry: true},
			func(ctx context.Context) (*http.Response, error) {
				reqHTTP, err := http.NewRequestWithContext(
					ctx,
					http.MethodPost,
					endpoint,
					bytes.NewReader(body),
				)
				if err != nil {
					return nil, err
				}

				reqHTTP.Header.Set("Content-Type", "application/json")
				reqHTTP.Header.Set("Authorization", "Bearer "+e.apiKey)
				reqHTTP.Header.Set("Idempotency-Key", idempotencyKey)

				return e.client.Do(reqHTTP)
			},
		)

		if err != nil {
			resultErr = fmt.Errorf("eurc: wallet creation request failed: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resultErr = fmt.Errorf(
				"eurc: wallet creation returned HTTP %d: %s",
				resp.StatusCode,
				string(b),
			)
			return
		}

		var result circleWalletResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resultErr = fmt.Errorf("eurc: failed to decode wallet response: %w", err)
			return
		}

		addr := result.Data.Wallet.Address
		if addr == "" {
			resultErr = fmt.Errorf("eurc: no address in wallet response")
			return
		}

		// commit
		e.mu.Lock()
		e.accounts[walletID] = addr
		e.mu.Unlock()

		resultAddr = addr
	}()

	return resultAddr, resultErr
}

// ----------------------------
// Payment status
// ----------------------------

func (e *EURCPaymentProvider) GetPaymentStatus(
	ctx context.Context,
	reference string,
) (PaymentStatus, error) {

	e.mu.Lock()
	defer e.mu.Unlock()

	if s, ok := e.payments[reference]; ok {
		return s, nil
	}

	return PaymentStatusPending, nil
}

func (e *EURCPaymentProvider) ConfirmPayment(
	ctx context.Context,
	reference string,
	amount float64,
	currency string,
) error {

	expectedAmount, expectedCurrency, found, err :=
		e.store.GetExpected(ctx, reference)

	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("eurc: unknown reference %s", reference)
	}

	if currency != expectedCurrency {
		return fmt.Errorf("eurc: currency mismatch")
	}

	diff := amount - expectedAmount
	if diff < 0 {
		diff = -diff
	}

	if expectedAmount > 0 && diff/expectedAmount > amountTolerancePct {
		return fmt.Errorf("eurc: amount mismatch")
	}

	if err := e.store.SetStatus(ctx, reference, PaymentStatusConfirmed); err != nil {
		return err
	}

	e.mu.Lock()
	e.payments[reference] = PaymentStatusConfirmed
	e.mu.Unlock()

	return nil
}

// ----------------------------
// Webhook verification
// ----------------------------

func (e *EURCPaymentProvider) VerifyWebhookSignature(payload []byte, signature string) bool {
	if e.webhookSecret == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(e.webhookSecret))
	mac.Write(payload)

	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}

// ----------------------------
// Helpers
// ----------------------------

func buildIdempotencyKey(walletID string) string {
	key := "gh-" + walletID
	if len(key) <= 36 {
		return key
	}

	sum := sha256.Sum256([]byte(walletID))
	return "gh-" + hex.EncodeToString(sum[:])[:33]
}
