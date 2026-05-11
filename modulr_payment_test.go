//go:build integration
// +build integration

package gonetwork

// Integration tests run against the Modulr sandbox API.
// Set the following environment variables before running:
//
//	MODULR_API_KEY      — your sandbox API key
//	MODULR_API_SECRET   — your sandbox API secret
//	MODULR_CUSTOMER_ID  — your Modulr customer ID (e.g. "C213Y4XY"); required for account creation
//	MODULR_PRODUCT_CODE — your Modulr product code (e.g. "O1200001"); required for account creation
//	MODULR_BASE_URL     — optional; defaults to sandbox URL
//
// Run with:
//
//	go test -tags=integration -run TestModulr ./...
//
// Tests that require live credentials are skipped automatically when
// MODULR_API_KEY or MODULR_API_SECRET are not set.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfNoModulrCreds skips the test if sandbox credentials are absent,
// otherwise returns a ready-to-use ModulrPaymentProvider.
func skipIfNoModulrCreds(t *testing.T) *ModulrPaymentProvider {
	t.Helper()
	p, err := NewModulrPaymentProviderFromEnv()
	if err != nil {
		t.Skipf("skipping Modulr integration test: %v", err)
	}
	return p
}

// TestModulrCreateVirtualAccount creates a virtual account in the Modulr
// sandbox and checks that a valid IBAN is returned.
func TestModulrCreateVirtualAccount(t *testing.T) {
	p := skipIfNoModulrCreds(t)

	iban, err := p.CreateVirtualAccount("gh-test-wallet-001")
	require.NoError(t, err, "CreateVirtualAccount should succeed against sandbox")
	assert.NotEmpty(t, iban, "a non-empty IBAN should be returned")
	t.Logf("Created virtual account: IBAN=%s", iban)
}

// TestModulrGetPaymentStatus_Unknown checks that a reference with no matching
// payment returns PaymentStatusPending (not an error).
func TestModulrGetPaymentStatus_Unknown(t *testing.T) {
	p := skipIfNoModulrCreds(t)

	status, err := p.GetPaymentStatus("gh-unknown-ref-99999")
	require.NoError(t, err, "unknown reference should not return an error")
	assert.Equal(t, PaymentStatusPending, status, "unknown reference should be reported as pending")
}

// TestModulrWebhookSignatureValid checks that a correctly computed HMAC-SHA256
// signature passes VerifyWebhookSignature.
func TestModulrWebhookSignatureValid(t *testing.T) {
	secret := os.Getenv("MODULR_API_SECRET")
	if secret == "" {
		t.Skip("MODULR_API_SECRET not set")
	}
	p, err := NewModulrPaymentProvider("placeholder-key", secret, "", "", "")
	require.NoError(t, err)

	payload := []byte(`{"type":"PAYMENT_RECEIVED","amount":1000,"currency":"GBP"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))

	assert.True(t, p.VerifyWebhookSignature(payload, sig), "correctly signed payload should pass")
}

// TestModulrWebhookSignatureInvalid checks that a tampered payload is rejected
// by VerifyWebhookSignature without requiring live credentials.
func TestModulrWebhookSignatureInvalid(t *testing.T) {
	p, err := NewModulrPaymentProvider("placeholder-key", "test-secret", "", "", "")
	require.NoError(t, err)

	// Compute a valid signature for one payload, then verify against a different one.
	original := []byte(`{"type":"PAYMENT_RECEIVED","amount":1000}`)
	tampered := []byte(`{"type":"PAYMENT_RECEIVED","amount":9999}`)

	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(tampered)
	sig := hex.EncodeToString(mac.Sum(nil))

	assert.False(t, p.VerifyWebhookSignature(original, sig), "signature over tampered payload should fail")
}
