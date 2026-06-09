package api

// ---------------------------------------------------------------------------
// payment_webhook_test.go — API-layer webhook handler tests
//
// Covers F-2 (unsigned Modulr webhooks rejected in production),
// and will be extended by F-13 with the full webhook test matrix.
// ---------------------------------------------------------------------------

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gonetwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookHandler_ModulrNilProvider_ProductionMode_Returns401 verifies
// that when ModulrProvider is nil and GH_ENV=production, any request to
// POST /v1/webhooks/payment is rejected with 401 — no signature key is
// available to authenticate the caller (F-2).
func TestWebhookHandler_ModulrNilProvider_ProductionMode_Returns401(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	// Create the blockchain before entering production mode — NewBlockchain
	// calls log.Fatal when GH_ENV=production and mocks are still wired.
	bc := gonetwork.NewBlockchain(context.Background(), "f2-test")
	server := NewServer(bc, ":0")
	// ModulrProvider is nil by default in NewServer — this is the test condition.
	require.Nil(t, server.ModulrProvider)

	// Switch to production mode for the handler call only.
	t.Setenv("GH_ENV", "production")

	body := `{"type":"PAYMENT_RECEIVED","externalReference":"ref-001","amount":1000,"currency":"GBP"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/payment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handlePaymentWebhook(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestWebhookHandler_ModulrNilProvider_DevMode_Processes verifies that when
// ModulrProvider is nil and GH_ENV is not "production" (dev/test), a webhook
// without a signature is still accepted — the production guard is the safety
// net; dev mode remains permissive for local testing (F-2).
func TestWebhookHandler_ModulrNilProvider_DevMode_Processes(t *testing.T) {
	t.Setenv("GH_ENV", "development")
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f2-dev-test")
	server := NewServer(bc, ":0")
	require.Nil(t, server.ModulrProvider)

	body := `{"type":"PAYMENT_RECEIVED","externalReference":"ref-002","amount":500,"currency":"GBP"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/payment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handlePaymentWebhook(rec, req)

	// Dev mode: no provider → no signature check → 200 (event type matched but
	// ConfirmAndSettle returns nil for unknown reference — acceptable no-op).
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// F-3 — amount / currency validation
// ---------------------------------------------------------------------------

// TestWebhookHandler_AmountMismatch_Returns422 verifies that when a Modulr
// webhook arrives with an amount that does not match the on-chain instruction,
// the handler returns HTTP 422 Unprocessable Entity so that Modulr stops
// retrying the callback (F-3).
func TestWebhookHandler_AmountMismatch_Returns422(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f3-test")
	// Register a pending instruction for 1000 GBP.
	bc.Mu.Lock()
	bc.PendingInstructions["trade-f3-api"] = &gonetwork.PaymentInstruction{
		Reference:   "ref-f3-api",
		TotalAmount: 1000,
		Currency:    "GBP",
	}
	bc.Mu.Unlock()

	server := NewServer(bc, ":0")
	// ModulrProvider is nil → dev mode, no signature check.
	require.Nil(t, server.ModulrProvider)

	// Webhook claims 500 GBP — does not match the 1000 GBP instruction.
	body := `{"type":"PAYMENT_RECEIVED","externalReference":"ref-f3-api","amount":500,"currency":"GBP"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/payment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handlePaymentWebhook(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// TestWebhookHandler_CurrencyMismatch_Returns422 verifies that when a Modulr
// webhook arrives with a currency that does not match the on-chain instruction,
// the handler returns HTTP 422 so that Modulr stops retrying (F-3).
func TestWebhookHandler_CurrencyMismatch_Returns422(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f3-cur-test")
	bc.Mu.Lock()
	bc.PendingInstructions["trade-f3-cur"] = &gonetwork.PaymentInstruction{
		Reference:   "ref-f3-cur",
		TotalAmount: 1000,
		Currency:    "GBP",
	}
	bc.Mu.Unlock()

	server := NewServer(bc, ":0")
	require.Nil(t, server.ModulrProvider)

	// Webhook claims EUR — does not match the GBP instruction.
	body := `{"type":"PAYMENT_RECEIVED","externalReference":"ref-f3-cur","amount":1000,"currency":"EUR"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/payment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handlePaymentWebhook(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// ---------------------------------------------------------------------------
// F-4 — POST /v1/payments/{tradeID}/register admin endpoint
// ---------------------------------------------------------------------------

// mockRegistrarOnlyProvider is a minimal PaymentProvider + SettlementRegistrar
// that returns a fixed transactionID, used in the API-layer register test.
type mockRegistrarOnlyProvider struct {
	txID string
}

func (m *mockRegistrarOnlyProvider) CreateVirtualAccount(ctx context.Context, reference string) (string, error) {
	return "iban-mock", nil
}
func (m *mockRegistrarOnlyProvider) GetPaymentStatus(ctx context.Context, reference string) (gonetwork.PaymentStatus, error) {
	return gonetwork.PaymentStatusPending, nil
}
func (m *mockRegistrarOnlyProvider) ConfirmPayment(ctx context.Context, reference string, amount float64, currency string) error {
	return nil
}
func (m *mockRegistrarOnlyProvider) RegisterSettlement(instruction *gonetwork.PaymentInstruction) (string, error) {
	return m.txID, nil
}

// TestRegistrationRetry_AdminEndpoint verifies that POST /v1/payments/{tradeID}/register
// calls RegisterSettlement and returns the pontes_transaction_id in the response (F-4).
func TestRegistrationRetry_AdminEndpoint(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f4-api-test")

	// Register the mock registrar for CeBM.
	mock := &mockRegistrarOnlyProvider{txID: "pontes-retry-tx-001"}
	bc.RegisterSettlementProvider(gonetwork.SettlementCeBM, mock)

	// Seed a pending EUR instruction using the CeBM method.
	bc.Mu.Lock()
	bc.PendingInstructions["trade-f4-api"] = &gonetwork.PaymentInstruction{
		Reference:   "ref-f4-api",
		TotalAmount: 2000,
		Currency:    "EUR",
		Method:      gonetwork.SettlementCeBM,
	}
	bc.Mu.Unlock()

	server := NewServer(bc, ":0")

	req := httptest.NewRequest(http.MethodPost, "/v1/payments/trade-f4-api/register", nil)
	req.SetPathValue("tradeID", "trade-f4-api")
	rec := httptest.NewRecorder()

	server.handleRegisterCeBMSettlement(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "pontes-retry-tx-001")

	// Verify the transaction ID was written back to the instruction.
	bc.Mu.Lock()
	instr := bc.PendingInstructions["trade-f4-api"]
	bc.Mu.Unlock()
	require.NotNil(t, instr)
	assert.Equal(t, "pontes-retry-tx-001", instr.PontesTransactionID)
	assert.Equal(t, "eurosystem-pontes", instr.SettlementNetwork)
}

// TestRegistrationRetry_AdminEndpoint_NotFound verifies 404 when the tradeID
// has no matching pending instruction.
func TestRegistrationRetry_AdminEndpoint_NotFound(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f4-notfound-test")
	server := NewServer(bc, ":0")

	req := httptest.NewRequest(http.MethodPost, "/v1/payments/no-such-trade/register", nil)
	req.SetPathValue("tradeID", "no-such-trade")
	rec := httptest.NewRecorder()

	server.handleRegisterCeBMSettlement(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestRegistrationRetry_AdminEndpoint_NoRegistrar verifies 409 when the
// provider does not implement SettlementRegistrar (e.g. Modulr/EURC).
func TestRegistrationRetry_AdminEndpoint_NoRegistrar(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "f4-noregistrar-test")

	// Seed a GBP instruction — default provider (MockPaymentProvider) does not
	// implement SettlementRegistrar.
	bc.Mu.Lock()
	bc.PendingInstructions["trade-f4-gbp"] = &gonetwork.PaymentInstruction{
		Reference:   "ref-f4-gbp",
		TotalAmount: 500,
		Currency:    "GBP",
		Method:      gonetwork.SettlementFasterPay,
	}
	bc.Mu.Unlock()

	server := NewServer(bc, ":0")

	req := httptest.NewRequest(http.MethodPost, "/v1/payments/trade-f4-gbp/register", nil)
	req.SetPathValue("tradeID", "trade-f4-gbp")
	rec := httptest.NewRecorder()

	server.handleRegisterCeBMSettlement(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}
