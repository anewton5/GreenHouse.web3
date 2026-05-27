package gonetwork

// ---------------------------------------------------------------------------
// eurc_payment_test.go — EURCPaymentProvider (Circle EURC stablecoin)
//
// Covers:
//   NewEURCPaymentProvider     — valid, missing apiKey, missing baseURL
//   NewEURCPaymentProviderFromEnv — missing CIRCLE_API_KEY, CIRCLE_WALLET_SET_ID,
//                                   success with all vars
//   GetPaymentStatus           — unknown ref (Pending), after ConfirmPayment
//   ConfirmPayment             — EUR OK, EURC OK, wrong currency error
//   VerifyWebhookSignature     — valid HMAC, tampered payload, empty secret
//   CreateVirtualAccount       — idempotency (no HTTP) via pre-seeded accounts
// ---------------------------------------------------------------------------

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewEURCPaymentProvider
// ---------------------------------------------------------------------------

func TestNewEURCPaymentProvider_Valid(t *testing.T) {
	p, err := NewEURCPaymentProvider("key123", "https://api.circle.com/v1", "ws-001", "secret")
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestNewEURCPaymentProvider_MissingAPIKey_Error(t *testing.T) {
	_, err := NewEURCPaymentProvider("", "https://api.circle.com/v1", "ws-001", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiKey")
}

func TestNewEURCPaymentProvider_MissingBaseURL_Error(t *testing.T) {
	_, err := NewEURCPaymentProvider("key123", "", "ws-001", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "baseURL")
}

func TestNewEURCPaymentProvider_NoWebhookSecret_OK(t *testing.T) {
	// webhookSecret is optional — provider still constructs successfully
	p, err := NewEURCPaymentProvider("key123", "https://api.circle.com/v1", "ws-001", "")
	require.NoError(t, err)
	require.NotNil(t, p)
}

// ---------------------------------------------------------------------------
// NewEURCPaymentProviderFromEnv
// ---------------------------------------------------------------------------

func TestNewEURCPaymentProviderFromEnv_MissingAPIKey_Error(t *testing.T) {
	t.Setenv("CIRCLE_API_KEY", "")
	t.Setenv("CIRCLE_WALLET_SET_ID", "ws-001")
	_, err := NewEURCPaymentProviderFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CIRCLE_API_KEY")
}

func TestNewEURCPaymentProviderFromEnv_MissingWalletSetID_Error(t *testing.T) {
	t.Setenv("CIRCLE_API_KEY", "key123")
	t.Setenv("CIRCLE_WALLET_SET_ID", "")
	_, err := NewEURCPaymentProviderFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CIRCLE_WALLET_SET_ID")
}

func TestNewEURCPaymentProviderFromEnv_DefaultBaseURL(t *testing.T) {
	t.Setenv("CIRCLE_API_KEY", "key123")
	t.Setenv("CIRCLE_WALLET_SET_ID", "ws-001")
	t.Setenv("CIRCLE_BASE_URL", "")
	p, err := NewEURCPaymentProviderFromEnv()
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "https://api.circle.com/v1", p.baseURL)
}

func TestNewEURCPaymentProviderFromEnv_CustomBaseURL(t *testing.T) {
	t.Setenv("CIRCLE_API_KEY", "key123")
	t.Setenv("CIRCLE_WALLET_SET_ID", "ws-001")
	t.Setenv("CIRCLE_BASE_URL", "https://custom.example.com/v2")
	p, err := NewEURCPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://custom.example.com/v2", p.baseURL)
}

// ---------------------------------------------------------------------------
// GetPaymentStatus
// ---------------------------------------------------------------------------

func TestGetPaymentStatus_UnknownRef_ReturnsPending(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	status, err := p.GetPaymentStatus("UNKNOWN-REF")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestGetPaymentStatus_AfterConfirm_ReturnsConfirmed(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	require.NoError(t, p.ConfirmPayment("REF-001", 1000, "EUR"))

	status, err := p.GetPaymentStatus("REF-001")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

// ---------------------------------------------------------------------------
// ConfirmPayment
// ---------------------------------------------------------------------------

func TestConfirmPayment_EUR_OK(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	err := p.ConfirmPayment("REF-EUR-001", 5000, "EUR")
	assert.NoError(t, err)
}

func TestConfirmPayment_EURC_OK(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	err := p.ConfirmPayment("REF-EURC-001", 5000, "EURC")
	assert.NoError(t, err)
}

func TestConfirmPayment_WrongCurrency_Error(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	err := p.ConfirmPayment("REF-USD-001", 5000, "USD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "currency")
}

func TestConfirmPayment_WrongCurrency_GBP_Error(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	err := p.ConfirmPayment("REF-GBP-001", 5000, "GBP")
	require.Error(t, err)
}

func TestConfirmPayment_Idempotent(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	require.NoError(t, p.ConfirmPayment("REF-IDEM", 100, "EUR"))
	require.NoError(t, p.ConfirmPayment("REF-IDEM", 100, "EUR")) // second call must not error
	s, _ := p.GetPaymentStatus("REF-IDEM")
	assert.Equal(t, PaymentStatusConfirmed, s)
}

// ---------------------------------------------------------------------------
// VerifyWebhookSignature
// ---------------------------------------------------------------------------

func validEURCSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "my-webhook-secret")
	payload := []byte(`{"type":"transfer.complete","amount":"1000"}`)
	sig := validEURCSignature("my-webhook-secret", payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

func TestVerifyWebhookSignature_TamperedPayload_False(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "my-webhook-secret")
	original := []byte(`{"type":"transfer.complete","amount":"1000"}`)
	sig := validEURCSignature("my-webhook-secret", original)

	tampered := []byte(`{"type":"transfer.complete","amount":"9999"}`)
	assert.False(t, p.VerifyWebhookSignature(tampered, sig))
}

func TestVerifyWebhookSignature_WrongSecret_False(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "correct-secret")
	payload := []byte(`{"type":"transfer.complete"}`)
	sig := validEURCSignature("wrong-secret", payload)
	assert.False(t, p.VerifyWebhookSignature(payload, sig))
}

func TestVerifyWebhookSignature_EmptySecret_False(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	payload := []byte(`{"type":"transfer.complete"}`)
	assert.False(t, p.VerifyWebhookSignature(payload, "any-sig"))
}

func TestVerifyWebhookSignature_EmptyPayload_ValidHMAC(t *testing.T) {
	secret := "test-secret"
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", secret)
	payload := []byte{}
	sig := validEURCSignature(secret, payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

// ---------------------------------------------------------------------------
// CreateVirtualAccount — idempotency (in-memory cache, no HTTP)
// ---------------------------------------------------------------------------

func TestCreateVirtualAccount_Idempotent_NoHTTP(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	// Pre-seed the in-memory cache so we can test idempotency without HTTP
	p.mu.Lock()
	p.accounts["wallet-001"] = "0xABCDEF1234567890"
	p.mu.Unlock()

	addr1, err := p.CreateVirtualAccount("wallet-001")
	require.NoError(t, err)
	assert.Equal(t, "0xABCDEF1234567890", addr1)

	// Second call returns the same address from cache
	addr2, err := p.CreateVirtualAccount("wallet-001")
	require.NoError(t, err)
	assert.Equal(t, addr1, addr2, "repeated calls must return cached address")
}

func TestCreateVirtualAccount_DifferentWallets_DifferentAddresses(t *testing.T) {
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "")
	p.mu.Lock()
	p.accounts["wallet-A"] = "0xAAAA"
	p.accounts["wallet-B"] = "0xBBBB"
	p.mu.Unlock()

	addrA, _ := p.CreateVirtualAccount("wallet-A")
	addrB, _ := p.CreateVirtualAccount("wallet-B")
	assert.NotEqual(t, addrA, addrB)
}
