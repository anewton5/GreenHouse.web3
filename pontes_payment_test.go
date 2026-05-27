package gonetwork

// ---------------------------------------------------------------------------
// pontes_payment_test.go
//
// Covers PontesPaymentProvider without any real HTTP calls:
//   NewPontesPaymentProvider        — valid, missing apiKey, missing operator
//   NewPontesPaymentProviderFromEnv — missing vars
//   CreateVirtualAccount            — returns expected prefix
//   GetPaymentStatus                — unknown ref → Pending, after confirm → Confirmed
//   ConfirmPayment                  — idempotent, any currency accepted
//   VerifyWebhookSignature          — valid HMAC, tampered, wrong secret, empty secret
//   pontesStatusToPaymentStatus     — all status strings
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
// Constructor
// ---------------------------------------------------------------------------

func TestNewPontesPaymentProvider_Valid(t *testing.T) {
	p, err := NewPontesPaymentProvider("key-123", "https://example.com", "GH-OP-01", "secret")
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestNewPontesPaymentProvider_DefaultBaseURL(t *testing.T) {
	p, err := NewPontesPaymentProvider("key-123", "", "GH-OP-01", "")
	require.NoError(t, err)
	// empty baseURL is accepted (defaults would be applied at construction if desired)
	assert.NotNil(t, p)
}

func TestNewPontesPaymentProvider_MissingAPIKey_Error(t *testing.T) {
	_, err := NewPontesPaymentProvider("", "https://example.com", "GH-OP-01", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiKey")
}

func TestNewPontesPaymentProvider_MissingDLTOperator_Error(t *testing.T) {
	_, err := NewPontesPaymentProvider("key-123", "https://example.com", "", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dltOperator")
}

func TestNewPontesPaymentProviderFromEnv_MissingAPIKey(t *testing.T) {
	t.Setenv("PONTES_API_KEY", "")
	t.Setenv("PONTES_DLT_OPERATOR", "GH-OP-01")
	_, err := NewPontesPaymentProviderFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PONTES_API_KEY")
}

func TestNewPontesPaymentProviderFromEnv_MissingDLTOperator(t *testing.T) {
	t.Setenv("PONTES_API_KEY", "test-key")
	t.Setenv("PONTES_DLT_OPERATOR", "")
	_, err := NewPontesPaymentProviderFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PONTES_DLT_OPERATOR")
}

func TestNewPontesPaymentProviderFromEnv_DefaultBaseURL(t *testing.T) {
	t.Setenv("PONTES_API_KEY", "test-key")
	t.Setenv("PONTES_DLT_OPERATOR", "GH-OP-01")
	t.Setenv("PONTES_BASE_URL", "")
	p, err := NewPontesPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, pontesPilotBaseURL, p.baseURL)
}

func TestNewPontesPaymentProviderFromEnv_CustomBaseURL(t *testing.T) {
	t.Setenv("PONTES_API_KEY", "test-key")
	t.Setenv("PONTES_DLT_OPERATOR", "GH-OP-01")
	t.Setenv("PONTES_BASE_URL", "https://custom.pontes.example.com/v1")
	p, err := NewPontesPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://custom.pontes.example.com/v1", p.baseURL)
}

// ---------------------------------------------------------------------------
// CreateVirtualAccount
// ---------------------------------------------------------------------------

func TestPontesCreateVirtualAccount_ReturnsPrefix(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	ref, err := p.CreateVirtualAccount("wallet-abc")
	require.NoError(t, err)
	assert.Equal(t, "pontes-wallet-abc", ref)
}

func TestPontesCreateVirtualAccount_EmptyWallet(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	ref, err := p.CreateVirtualAccount("")
	require.NoError(t, err)
	assert.Equal(t, "pontes-", ref)
}

// ---------------------------------------------------------------------------
// GetPaymentStatus — local cache paths (no HTTP)
// ---------------------------------------------------------------------------

func TestPontesGetPaymentStatus_Unknown_ReturnsPending(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	status, err := p.GetPaymentStatus("unknown-ref")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestPontesGetPaymentStatus_AfterConfirm_ReturnsConfirmed(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	require.NoError(t, p.ConfirmPayment("ref-001", 1000, "EUR"))

	status, err := p.GetPaymentStatus("ref-001")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

// ---------------------------------------------------------------------------
// ConfirmPayment
// ---------------------------------------------------------------------------

func TestPontesConfirmPayment_AcceptsEUR(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	require.NoError(t, p.ConfirmPayment("trade-1", 5000, "EUR"))

	status, _ := p.GetPaymentStatus("trade-1")
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesConfirmPayment_Idempotent(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	require.NoError(t, p.ConfirmPayment("trade-2", 1000, "EUR"))
	require.NoError(t, p.ConfirmPayment("trade-2", 1000, "EUR"))

	status, _ := p.GetPaymentStatus("trade-2")
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesConfirmPayment_AcceptsAnyAmountAndCurrency(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	require.NoError(t, p.ConfirmPayment("trade-chf", 9999.99, "CHF"))
	status, _ := p.GetPaymentStatus("trade-chf")
	assert.Equal(t, PaymentStatusConfirmed, status)
}

// ---------------------------------------------------------------------------
// VerifyWebhookSignature
// ---------------------------------------------------------------------------

func pontesHMAC(t *testing.T, secret string, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestPontesVerifyWebhookSignature_Valid(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz")
	payload := []byte(`{"event":"settlement.confirmed","ref":"trade-1"}`)
	sig := pontesHMAC(t, "webhook-secret-xyz", payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

func TestPontesVerifyWebhookSignature_TamperedPayload_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz")
	payload := []byte(`{"event":"settlement.confirmed","ref":"trade-1"}`)
	sig := pontesHMAC(t, "webhook-secret-xyz", payload)
	// tamper the payload
	tampered := []byte(`{"event":"settlement.confirmed","ref":"trade-EVIL"}`)
	assert.False(t, p.VerifyWebhookSignature(tampered, sig))
}

func TestPontesVerifyWebhookSignature_WrongSecret_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz")
	payload := []byte(`{"event":"settlement.confirmed"}`)
	sig := pontesHMAC(t, "wrong-secret", payload)
	assert.False(t, p.VerifyWebhookSignature(payload, sig))
}

func TestPontesVerifyWebhookSignature_EmptyHMACSecret_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "")
	payload := []byte(`{"event":"settlement.confirmed"}`)
	assert.False(t, p.VerifyWebhookSignature(payload, "any-sig"))
}

func TestPontesVerifyWebhookSignature_EmptyPayload_Valid(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "my-secret")
	sig := pontesHMAC(t, "my-secret", []byte{})
	assert.True(t, p.VerifyWebhookSignature([]byte{}, sig))
}

// ---------------------------------------------------------------------------
// pontesStatusToPaymentStatus
// ---------------------------------------------------------------------------

func TestPontesStatusToPaymentStatus_Settled(t *testing.T) {
	assert.Equal(t, PaymentStatusConfirmed, pontesStatusToPaymentStatus("SETTLED"))
}

func TestPontesStatusToPaymentStatus_Confirmed(t *testing.T) {
	assert.Equal(t, PaymentStatusConfirmed, pontesStatusToPaymentStatus("CONFIRMED"))
}

func TestPontesStatusToPaymentStatus_Failed(t *testing.T) {
	assert.Equal(t, PaymentStatusFailed, pontesStatusToPaymentStatus("FAILED"))
}

func TestPontesStatusToPaymentStatus_Rejected(t *testing.T) {
	assert.Equal(t, PaymentStatusFailed, pontesStatusToPaymentStatus("REJECTED"))
}

func TestPontesStatusToPaymentStatus_Expired(t *testing.T) {
	assert.Equal(t, PaymentStatusExpired, pontesStatusToPaymentStatus("EXPIRED"))
}

func TestPontesStatusToPaymentStatus_Unknown_Pending(t *testing.T) {
	assert.Equal(t, PaymentStatusPending, pontesStatusToPaymentStatus("SUBMITTED"))
	assert.Equal(t, PaymentStatusPending, pontesStatusToPaymentStatus(""))
	assert.Equal(t, PaymentStatusPending, pontesStatusToPaymentStatus("PROCESSING"))
}
