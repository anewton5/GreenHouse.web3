package gonetwork

import (
	"bytes"
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

// EURCPaymentProvider implements PaymentProvider using Circle's EURC
// euro stablecoin. EURC is a MiCA-regulated, euro-denominated stablecoin
// issued by Circle Internet Financial in Europe. It provides near-instant
// settlement finality on-chain and eliminates commercial-bank credit risk —
// making it the primary EUR settlement bridge until the ECB's Pontes CeBM
// pilot launches in Q3 2026.
//
// Upgrade path: once a PontesPaymentProvider is registered via
// Blockchain.RegisterSettlementProvider(SettlementCeBM, pontesProvider),
// new EUR instructions automatically route to CeBM. Existing EURC
// instructions already in-flight continue to settle via this provider.
//
// Configuration (environment variables):
//
//	CIRCLE_API_KEY          — Circle API key
//	CIRCLE_BASE_URL         — API base URL (default: https://api.circle.com/v1)
//	CIRCLE_WALLET_SET_ID    — WalletSet to create EURC wallets under
//	CIRCLE_WEBHOOK_SECRET   — HMAC-SHA256 secret for webhook signature verification
type EURCPaymentProvider struct {
	apiKey        string
	baseURL       string
	walletSetID   string
	webhookSecret string
	client        *http.Client

	mu       sync.Mutex
	accounts map[string]string        // walletID → on-chain address
	payments map[string]PaymentStatus // reference → status
}

// NewEURCPaymentProviderFromEnv creates an EURCPaymentProvider from environment
// variables. Returns an error if required variables are missing.
func NewEURCPaymentProviderFromEnv() (*EURCPaymentProvider, error) {
	apiKey := os.Getenv("CIRCLE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("eurc: CIRCLE_API_KEY environment variable is required")
	}
	baseURL := os.Getenv("CIRCLE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.circle.com/v1"
	}
	walletSetID := os.Getenv("CIRCLE_WALLET_SET_ID")
	if walletSetID == "" {
		return nil, fmt.Errorf("eurc: CIRCLE_WALLET_SET_ID environment variable is required")
	}
	webhookSecret := os.Getenv("CIRCLE_WEBHOOK_SECRET")
	return NewEURCPaymentProvider(apiKey, baseURL, walletSetID, webhookSecret)
}

// NewEURCPaymentProvider creates an EURCPaymentProvider with explicit credentials.
func NewEURCPaymentProvider(apiKey, baseURL, walletSetID, webhookSecret string) (*EURCPaymentProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("eurc: apiKey must not be empty")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("eurc: baseURL must not be empty")
	}
	return &EURCPaymentProvider{
		apiKey:        apiKey,
		baseURL:       baseURL,
		walletSetID:   walletSetID,
		webhookSecret: webhookSecret,
		client:        &http.Client{Timeout: 30 * time.Second},
		accounts:      make(map[string]string),
		payments:      make(map[string]PaymentStatus),
	}, nil
}

// circleWalletResponse is the shape of Circle's POST /wallets response.
type circleWalletResponse struct {
	Data struct {
		Wallet struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"wallet"`
	} `json:"data"`
}

// CreateVirtualAccount provisions a Circle EURC wallet for a participant and
// returns its Ethereum on-chain address. The call is idempotent — repeated
// calls for the same walletID return the cached address without re-calling the API.
func (e *EURCPaymentProvider) CreateVirtualAccount(walletID string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if addr, ok := e.accounts[walletID]; ok {
		return addr, nil
	}

	// Build a collision-resistant idempotency key within Circle's 36-char limit.
	// Naive prefix truncation would make two walletIDs that share the first 33
	// characters map to the same key — hash the full ID instead.
	idempotencyKey := "gh-" + walletID
	if len(idempotencyKey) > 36 {
		h := sha256.Sum256([]byte(walletID))
		idempotencyKey = "gh-" + hex.EncodeToString(h[:])[:33]
	}

	payload := map[string]any{
		"idempotencyKey": idempotencyKey,
		"walletSetId":    e.walletSetID,
		"blockchains":    []string{"ETH"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("eurc: failed to marshal wallet request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, e.baseURL+"/wallets", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("eurc: failed to build wallet request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("eurc: wallet creation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("eurc: wallet creation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result circleWalletResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("eurc: failed to decode wallet response: %w", err)
	}

	addr := result.Data.Wallet.Address
	if addr == "" {
		return "", fmt.Errorf("eurc: wallet creation returned no address")
	}

	e.accounts[walletID] = addr
	return addr, nil
}

// GetPaymentStatus returns the current status of an on-chain EURC transfer.
// Returns PaymentStatusPending for references not yet confirmed via webhook.
func (e *EURCPaymentProvider) GetPaymentStatus(reference string) (PaymentStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if s, ok := e.payments[reference]; ok {
		return s, nil
	}
	return PaymentStatusPending, nil
}

// ConfirmPayment records an on-chain EURC transfer as confirmed. In production
// this is called by Blockchain.ConfirmAndSettle which is invoked from the
// POST /v1/webhooks/eurc handler when Circle delivers a transfer.complete event.
// It must not be called directly from finalizeBlock.
func (e *EURCPaymentProvider) ConfirmPayment(reference string, amount float64, currency string) error {
	if currency != "EUR" && currency != "EURC" {
		return fmt.Errorf("eurc: unexpected currency %q; this provider only handles EUR/EURC", currency)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.payments[reference] = PaymentStatusConfirmed
	return nil
}

// VerifyWebhookSignature validates a Circle webhook payload against the
// HMAC-SHA256 signature in the Circle-Signature header. Returns true only when
// the signatures match (constant-time comparison).
func (e *EURCPaymentProvider) VerifyWebhookSignature(payload []byte, signature string) bool {
	if e.webhookSecret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(e.webhookSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}
