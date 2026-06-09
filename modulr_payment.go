package gonetwork

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ModulrPaymentProvider implements PaymentProvider against the Modulr API.
// Credentials are never hardcoded — they are read from environment variables
// or passed explicitly to NewModulrPaymentProvider.
//
// Environment variables:
//
//	MODULR_API_KEY      — API key from the Modulr developer portal
//	MODULR_API_SECRET   — API secret from the Modulr developer portal
//	MODULR_CUSTOMER_ID  — Modulr customer ID (e.g. "C213Y4XY"); required for account creation
//	MODULR_PRODUCT_CODE — Modulr product code (e.g. "O1200001"); required for account creation
//	MODULR_BASE_URL     — defaults to the sandbox URL if not set
//
// API documentation: https://modulr.readme.io/docs
type ModulrPaymentProvider struct {
	apiKey           string
	apiSecret        string
	baseURL          string
	customerID       string
	productCode      string
	client           *http.Client
	operationTimeout time.Duration
}

// modulrSandboxBaseURL is the default when MODULR_BASE_URL is not set.
const modulrSandboxBaseURL = "https://api-sandbox.modulrfinance.com/api-sandbox"

// NewModulrPaymentProviderFromEnv creates a ModulrPaymentProvider by reading
// credentials from environment variables. Returns an error if MODULR_API_KEY
// or MODULR_API_SECRET are not set. MODULR_CUSTOMER_ID and MODULR_PRODUCT_CODE
// are optional but both required for CreateVirtualAccount.
func NewModulrPaymentProviderFromEnv() (*ModulrPaymentProvider, error) {
	apiKey := os.Getenv("MODULR_API_KEY")
	apiSecret := os.Getenv("MODULR_API_SECRET")
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("modulr: MODULR_API_KEY and MODULR_API_SECRET must be set")
	}
	baseURL := os.Getenv("MODULR_BASE_URL")
	if baseURL == "" {
		baseURL = modulrSandboxBaseURL
	}
	customerID := os.Getenv("MODULR_CUSTOMER_ID")
	productCode := os.Getenv("MODULR_PRODUCT_CODE")
	return NewModulrPaymentProvider(apiKey, apiSecret, baseURL, customerID, productCode)
}

// NewModulrPaymentProvider creates a ModulrPaymentProvider with explicitly
// provided credentials. baseURL defaults to the sandbox URL if empty.
// customerID and productCode are optional but both required for CreateVirtualAccount.
func NewModulrPaymentProvider(apiKey, apiSecret, baseURL, customerID, productCode string) (*ModulrPaymentProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("modulr: apiKey must not be empty")
	}
	if apiSecret == "" {
		return nil, fmt.Errorf("modulr: apiSecret must not be empty")
	}
	if baseURL == "" {
		baseURL = modulrSandboxBaseURL
	}
	return &ModulrPaymentProvider{
		apiKey:      apiKey,
		apiSecret:   apiSecret,
		baseURL:     baseURL,
		customerID:  customerID,
		productCode: productCode,
		client:      &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// addAuthHeaders attaches the Modulr HMAC-SHA1 authentication headers to req.
//
// The algorithm follows the Modulr HTTP Signature spec exactly:
//  1. Set Date header (RFC 7231 GMT format).
//  2. Set x-mod-nonce header to a unique hex string.
//  3. Build signature string: "date: {date}\nx-mod-nonce: {nonce}" (lowercase labels).
//  4. Compute HMAC-SHA1 of the signature string using apiSecret as key.
//  5. URL-encode the standard base64 of the raw HMAC bytes.
//  6. Set Authorization: Signature keyId="{key}",algorithm="hmac-sha1",
//     headers="date x-mod-nonce",signature="{urlEncodedBase64}"
//
// Reference: https://modulr.readme.io/docs/authentication
func (m *ModulrPaymentProvider) addAuthHeaders(req *http.Request) error {
	date := time.Now().UTC().Format(http.TimeFormat) // produces "GMT" suffix as required

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("modulr: failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	sigString := "date: " + date + "\n" + "x-mod-nonce: " + nonce

	h := hmac.New(sha1.New, []byte(m.apiSecret))
	h.Write([]byte(sigString))
	// URL-encode the base64 of the raw bytes (not the hex representation).
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))

	req.Header.Set("Date", date)
	req.Header.Set("x-mod-nonce", nonce)
	req.Header.Set("Authorization", fmt.Sprintf(
		`Signature keyId="%s",algorithm="hmac-sha1",headers="date x-mod-nonce",signature="%s"`,
		m.apiKey, sig,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return nil
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type modulrAccountRequest struct {
	Name              string `json:"name"`
	Currency          string `json:"currency"`
	ExternalReference string `json:"externalReference,omitempty"`
	ProductCode       string `json:"productCode,omitempty"`
}

type modulrAccountIdentifier struct {
	Type          string `json:"type"`
	IBAN          string `json:"iban"`
	SortCode      string `json:"sortCode"`
	AccountNumber string `json:"accountNumber"`
}

type modulrAccountResponse struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Identifiers []modulrAccountIdentifier `json:"identifiers"`
}

type modulrPaymentRecord struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"`
	Amount    float64 `json:"amount"`
	Reference string  `json:"externalReference"`
}

type modulrPaymentsResponse struct {
	Content []modulrPaymentRecord `json:"content"`
}

// ---------------------------------------------------------------------------
// PaymentProvider interface implementation
// ---------------------------------------------------------------------------

// CreateVirtualAccount creates a named GBP virtual account in Modulr for a
// participant wallet. Returns the account identifier — IBAN for accounts that
// have one, or "{sortCode}/{accountNumber}" for UK BACS accounts.
// customerID and productCode must be set on the provider.
func (m *ModulrPaymentProvider) CreateVirtualAccount(ctx context.Context, walletID string) (string, error) {

	// ----------------------------------------------------
	// 1. VALIDATION (no timeout burn)
	// ----------------------------------------------------
	if m.customerID == "" {
		return "", fmt.Errorf("modulr: customerID must be set")
	}
	if m.productCode == "" {
		return "", fmt.Errorf("modulr: productCode must be set")
	}

	// ----------------------------------------------------
	// 2. BUILD REQUEST
	// ----------------------------------------------------
	payload := modulrAccountRequest{
		Name:              walletID,
		Currency:          "GBP",
		ExternalReference: walletID,
		ProductCode:       m.productCode,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("modulr: failed to marshal account request: %w", err)
	}

	endpoint := m.baseURL + "/customers/" + m.customerID + "/accounts"
	idempotencyKey := "gh-gbp-" + walletID

	// ----------------------------------------------------
	// 3. APPLY OPERATION TIMEOUT (H-1)
	// ----------------------------------------------------
	if m.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.operationTimeout)
		defer cancel()
	}

	// ----------------------------------------------------
	// 4. HTTP CALL (retry-safe)
	// ----------------------------------------------------
	resp, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				endpoint,
				bytes.NewReader(body),
			)
			if err != nil {
				return nil, fmt.Errorf("modulr: failed to build request: %w", err)
			}

			req.Header.Set("Idempotency-Key", idempotencyKey)

			if err := m.addAuthHeaders(req); err != nil {
				return nil, err
			}

			return m.client.Do(req)
		},
	)

	if err != nil {
		return "", fmt.Errorf("modulr: CreateVirtualAccount failed: %w", err)
	}
	defer resp.Body.Close()

	// ----------------------------------------------------
	// 5. RESPONSE HANDLING
	// ----------------------------------------------------
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("modulr: CreateVirtualAccount HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result modulrAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("modulr: decode account response failed: %w", err)
	}

	for _, id := range result.Identifiers {
		if id.IBAN != "" {
			return id.IBAN, nil
		}
	}
	for _, id := range result.Identifiers {
		if id.SortCode != "" && id.AccountNumber != "" {
			return id.SortCode + "/" + id.AccountNumber, nil
		}
	}

	return "", fmt.Errorf("modulr: account created but no IBAN or sort code returned")
}

// CreateEURVirtualAccount creates a named EUR virtual account in Modulr for a
// participant wallet. It uses the same product code as the GBP account but
// requests EUR currency, which creates a SEPA-enabled IBAN. This method exists
// alongside CreateVirtualAccount (GBP) to preserve backward compatibility.
// customerID and productCode must be set on the provider.
func (m *ModulrPaymentProvider) CreateEURVirtualAccount(ctx context.Context, walletID string) (string, error) {

	if m.customerID == "" {
		return "", fmt.Errorf("modulr: customerID must be set")
	}
	if m.productCode == "" {
		return "", fmt.Errorf("modulr: productCode must be set")
	}

	payload := modulrAccountRequest{
		Name:              walletID + "-EUR",
		Currency:          "EUR",
		ExternalReference: walletID + "-EUR",
		ProductCode:       m.productCode,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("modulr: failed to marshal EUR request: %w", err)
	}

	endpoint := m.baseURL + "/customers/" + m.customerID + "/accounts"
	idempotencyKey := "gh-eur-" + walletID

	if m.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.operationTimeout)
		defer cancel()
	}

	resp, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				endpoint,
				bytes.NewReader(body),
			)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Idempotency-Key", idempotencyKey)

			if err := m.addAuthHeaders(req); err != nil {
				return nil, err
			}

			return m.client.Do(req)
		},
	)

	if err != nil {
		return "", fmt.Errorf("modulr: CreateEURVirtualAccount failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("modulr: EUR account HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result modulrAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("modulr: decode EUR response failed: %w", err)
	}

	for _, id := range result.Identifiers {
		if id.IBAN != "" {
			return id.IBAN, nil
		}
	}
	for _, id := range result.Identifiers {
		if id.SortCode != "" && id.AccountNumber != "" {
			return id.SortCode + "/" + id.AccountNumber, nil
		}
	}

	return "", fmt.Errorf("modulr: EUR account created but no IBAN returned")
}

// GetPaymentStatus looks up an inbound payment by its external reference and
// maps the Modulr status string to our internal PaymentStatus type. Returns
// PaymentStatusPending (not an error) when no matching payment is found.
func (m *ModulrPaymentProvider) GetPaymentStatus(ctx context.Context, reference string) (PaymentStatus, error) {

	// ----------------------------------------------------
	// 1. VALIDATION / QUERY BUILD (no timeout burn)
	// ----------------------------------------------------
	params := url.Values{}
	params.Set("externalReference", reference)
	params.Set("type", "PAYIN")
	params.Set("fromCreatedDate",
		time.Now().AddDate(0, 0, -90).UTC().Format("2006-01-02T15:04:05-0700"),
	)

	endpoint := m.baseURL + "/payments?" + params.Encode()
	idempotencyKey := "gh-payin-" + reference

	// ----------------------------------------------------
	// 2. APPLY OPERATION TIMEOUT ONLY FOR NETWORK
	// ----------------------------------------------------
	if m.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.operationTimeout)
		defer cancel()
	}

	resp, err := retryHTTPWithConfig(
		ctx,
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {

			req, err := http.NewRequestWithContext(
				ctx,
				http.MethodGet,
				endpoint,
				nil,
			)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Idempotency-Key", idempotencyKey)

			if err := m.addAuthHeaders(req); err != nil {
				return nil, err
			}

			return m.client.Do(req)
		},
	)

	if err != nil {
		return PaymentStatusPending, fmt.Errorf("modulr: GetPaymentStatus failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return PaymentStatusPending, fmt.Errorf("modulr: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result modulrPaymentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return PaymentStatusPending, fmt.Errorf("modulr: decode failed: %w", err)
	}

	if len(result.Content) == 0 {
		return PaymentStatusPending, nil
	}

	return modulrStatusToPaymentStatus(result.Content[0].Status), nil
}

func (m *ModulrPaymentProvider) GetPaymentStatusCtx(
	ctx context.Context,
	reference string,
) (PaymentStatus, error) {
	return m.GetPaymentStatus(ctx, reference)
}

// ConfirmPayment is not called directly on ModulrPaymentProvider.
// In production, payment confirmations arrive via the Modulr webhook
// (POST /v1/webhooks/payment) and are handled by the API layer.
// This method exists only to satisfy the PaymentProvider interface.
func (m *ModulrPaymentProvider) ConfirmPayment(_ context.Context, _ string, _ float64, _ string) error {
	return fmt.Errorf("modulr: ConfirmPayment must not be called directly; confirmations arrive via the Modulr webhook handler")
}

// ---------------------------------------------------------------------------
// Webhook verification
// ---------------------------------------------------------------------------

// VerifyWebhookSignature verifies the HMAC-SHA256 signature on a Modulr webhook
// payload. Modulr sends the hex-encoded signature in the X-Mod-Nonce header.
// This must be called before processing any webhook payload.
func (m *ModulrPaymentProvider) VerifyWebhookSignature(payload []byte, signature string) bool {
	if m.apiSecret == "" {
		panic("modulr: apiSecret is empty — webhook verification is disabled; this indicates a broken initialization")
	}
	mac := hmac.New(sha256.New, []byte(m.apiSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// modulrStatusToPaymentStatus maps Modulr payment status strings to our type.
func modulrStatusToPaymentStatus(s string) PaymentStatus {
	switch s {
	case "PROCESSED", "SETTLED":
		return PaymentStatusConfirmed
	case "FAILED", "REJECTED":
		return PaymentStatusFailed
	case "EXPIRED":
		return PaymentStatusExpired
	default:
		return PaymentStatusPending
	}
}
