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

// PontesPaymentProvider implements PaymentProvider using the Eurosystem's Pontes
// bridge — the ECB's DLT interoperability solution that links Market DLT platforms
// to TARGET2 (T2) for settlement in tokenised Central Bank Money (CeBM).
//
// # Pontes Settlement Flow (DVP)
//
//  1. A trade is matched and finalizeBlock calls DefaultSettlementMethod → SettlementCeBM.
//  2. The API layer calls RegisterSettlement to register the DLT delivery leg with
//     the Pontes bridge. Pontes returns a transactionId.
//  3. Pontes instructs the T2 RTGS to execute the cash leg.
//  4. On T2 confirmation, Pontes calls POST /v1/webhooks/pontes with a
//     settlement.confirmed event.
//  5. The webhook handler calls Blockchain.ConfirmAndSettle which applies the
//     DVP asset transfer on-chain.
//
// # Status
//
// The Pontes pilot is scheduled to launch in Q3 2026. This provider targets the
// pilot API. Register it via Blockchain.RegisterSettlementProvider(SettlementCeBM, p)
// once your operator credentials are issued by the Eurosystem.
//
// Configuration (environment variables):
//
//	PONTES_API_KEY        — API key issued by the Eurosystem for the Pontes pilot
//	PONTES_BASE_URL       — API base URL (default: https://pilot.pontes.ecb.europa.eu/v1)
//	PONTES_DLT_OPERATOR   — GreenHouse's Market DLT Operator identifier (assigned at registration)
//	PONTES_HMAC_SECRET    — HMAC-SHA256 secret for callback signature verification
type PontesPaymentProvider struct {
	apiKey      string
	baseURL     string
	dltOperator string
	hmacSecret  string
	client      *http.Client

	mu       sync.Mutex
	pending  map[string]string        // reference → Pontes transactionId
	payments map[string]PaymentStatus // reference → status
}

const pontesPilotBaseURL = "https://pilot.pontes.ecb.europa.eu/v1"

// NewPontesPaymentProviderFromEnv creates a PontesPaymentProvider from environment
// variables. Returns an error if required variables are missing.
func NewPontesPaymentProviderFromEnv() (*PontesPaymentProvider, error) {
	apiKey := os.Getenv("PONTES_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("pontes: PONTES_API_KEY environment variable is required")
	}
	baseURL := os.Getenv("PONTES_BASE_URL")
	if baseURL == "" {
		baseURL = pontesPilotBaseURL
	}
	dltOperator := os.Getenv("PONTES_DLT_OPERATOR")
	if dltOperator == "" {
		return nil, fmt.Errorf("pontes: PONTES_DLT_OPERATOR environment variable is required")
	}
	hmacSecret := os.Getenv("PONTES_HMAC_SECRET")
	return NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret)
}

// NewPontesPaymentProvider creates a PontesPaymentProvider with explicit credentials.
func NewPontesPaymentProvider(apiKey, baseURL, dltOperator, hmacSecret string) (*PontesPaymentProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("pontes: apiKey must not be empty")
	}
	if dltOperator == "" {
		return nil, fmt.Errorf("pontes: dltOperator must not be empty")
	}
	return &PontesPaymentProvider{
		apiKey:      apiKey,
		baseURL:     baseURL,
		dltOperator: dltOperator,
		hmacSecret:  hmacSecret,
		client:      &http.Client{Timeout: 30 * time.Second},
		pending:     make(map[string]string),
		payments:    make(map[string]PaymentStatus),
	}, nil
}

// pontesRegisterRequest is the body sent to POST /settlements to register the
// DLT delivery leg of a DVP trade with the Pontes bridge.
type pontesRegisterRequest struct {
	DLTOperator string  `json:"dltOperator"`
	Reference   string  `json:"externalReference"`
	PayerBIC    string  `json:"payerBIC"`
	PayeeBIC    string  `json:"payeeBIC"`
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
}

// pontesRegisterResponse is the response from POST /settlements.
type pontesRegisterResponse struct {
	TransactionID string `json:"transactionId"`
	Status        string `json:"status"`
}

// CreateVirtualAccount satisfies the PaymentProvider interface. Pontes
// participants are identified by their BIC and are registered offline during
// the Market DLT Operator onboarding process — no API call is required here.
// Returns a "pontes-<walletID>" reference so the calling code can store it.
func (p *PontesPaymentProvider) CreateVirtualAccount(walletID string) (string, error) {
	return "pontes-" + walletID, nil
}

// GetPaymentStatus returns the current T2 settlement status for a reference.
// Checks the local cache first; if the reference is registered but not yet
// confirmed, queries the Pontes API for the latest status.
func (p *PontesPaymentProvider) GetPaymentStatus(reference string) (PaymentStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s, ok := p.payments[reference]; ok {
		return s, nil
	}

	transactionID, ok := p.pending[reference]
	if !ok {
		return PaymentStatusPending, nil
	}

	req, err := http.NewRequest(http.MethodGet, p.baseURL+"/settlements/"+transactionID, nil)
	if err != nil {
		return PaymentStatusPending, fmt.Errorf("pontes: failed to build status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return PaymentStatusPending, fmt.Errorf("pontes: status request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return PaymentStatusPending, nil
	}

	status := pontesStatusToPaymentStatus(result.Status)
	if status == PaymentStatusConfirmed {
		p.payments[reference] = status
	}
	return status, nil
}

// ConfirmPayment records a Pontes T2 settlement confirmation. In production
// this is called exclusively by Blockchain.ConfirmAndSettle from the
// POST /v1/webhooks/pontes handler when the bridge delivers a
// settlement.confirmed event. Must not be called directly from finalizeBlock.
func (p *PontesPaymentProvider) ConfirmPayment(reference string, amount float64, currency string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.payments[reference] = PaymentStatusConfirmed
	return nil
}

// RegisterSettlement submits the DLT delivery leg to the Pontes bridge and
// stores the returned Pontes transactionId against the instruction reference.
// It also sets instruction.PontesTransactionID and instruction.SettlementNetwork
// in-place so the oracle can include them in its signature.
//
// This is called from the API layer (or a background routine) immediately after
// the PaymentInstruction is oracle-signed and stored in PendingInstructions.
func (p *PontesPaymentProvider) RegisterSettlement(instruction *PaymentInstruction) (string, error) {
	body, err := json.Marshal(pontesRegisterRequest{
		DLTOperator: p.dltOperator,
		Reference:   instruction.Reference,
		PayerBIC:    instruction.PayerWalletID,
		PayeeBIC:    instruction.PayeeWalletID,
		Amount:      instruction.TotalAmount,
		Currency:    instruction.Currency,
	})
	if err != nil {
		return "", fmt.Errorf("pontes: failed to marshal settlement request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, p.baseURL+"/settlements", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("pontes: failed to build settlement request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pontes: settlement registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pontes: settlement registration returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result pontesRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("pontes: failed to decode settlement response: %w", err)
	}
	if result.TransactionID == "" {
		return "", fmt.Errorf("pontes: settlement registration returned no transactionId")
	}

	instruction.PontesTransactionID = result.TransactionID
	instruction.SettlementNetwork = "eurosystem-pontes"

	p.mu.Lock()
	p.pending[instruction.Reference] = result.TransactionID
	p.mu.Unlock()

	return result.TransactionID, nil
}

// VerifyWebhookSignature validates a Pontes callback payload against the
// HMAC-SHA256 signature in the X-Pontes-Signature header. Returns true only
// when the signatures match (constant-time comparison).
func (p *PontesPaymentProvider) VerifyWebhookSignature(payload []byte, signature string) bool {
	if p.hmacSecret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(p.hmacSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// pontesStatusToPaymentStatus maps Pontes T2 settlement status strings to
// the platform's PaymentStatus enum.
func pontesStatusToPaymentStatus(s string) PaymentStatus {
	switch s {
	case "SETTLED", "CONFIRMED":
		return PaymentStatusConfirmed
	case "FAILED", "REJECTED":
		return PaymentStatusFailed
	case "EXPIRED":
		return PaymentStatusExpired
	default:
		return PaymentStatusPending
	}
}
