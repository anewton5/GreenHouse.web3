package gonetwork

// ---------------------------------------------------------------------------
// production_guard_test.go — I-2 startup guard (productionReadinessError)
//
// Covers:
//   productionReadinessError — returns appropriate error for each missing
//                              or mocked dependency in sequence
//   OnfidoIdentityRegistry.HandleWebhook — mandatory HMAC when
//                              GH_ENV=production and ONFIDO_WEBHOOK_SECRET
//                              is not set
// ---------------------------------------------------------------------------

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// productionReadinessError
// ---------------------------------------------------------------------------

// TestProductionGuard_MockAMLScreener verifies that the default (mock) AML
// screener is caught immediately.
func TestProductionGuard_MockAMLScreener(t *testing.T) {
	bc := newTestBlockchain(t)
	err := productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AMLScreener")
}

// TestProductionGuard_MockPaymentProvider verifies that a nil AML screener
// (non-mock) advances past the AML check and catches the mock payment provider.
func TestProductionGuard_MockPaymentProvider(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.AMLScreener = nil // nil interface is not *MockAMLScreener
	err := productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PaymentProvider")
}

// TestProductionGuard_MockIdentityRegistry verifies that clearing the first
// two mock checks advances to the identity registry check.
func TestProductionGuard_MockIdentityRegistry(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.AMLScreener = nil
	bc.PaymentProvider = nil
	err := productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityRegistry")
}

// TestProductionGuard_NilOperatorKeyProvider verifies that clearing all three
// mock-interface checks advances to the nil OperatorKeyProvider check.
func TestProductionGuard_NilOperatorKeyProvider(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.AMLScreener = nil
	bc.PaymentProvider = nil
	bc.IdentityRegistry = nil
	// OperatorKeyProvider is nil by default.
	err := productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OperatorKeyProvider")
}

// TestProductionGuard_MissingOnfidoSecret verifies that a non-nil
// OperatorKeyProvider advances to the ONFIDO_WEBHOOK_SECRET check.
func TestProductionGuard_MissingOnfidoSecret(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "")

	bc := newTestBlockchain(t)
	bc.AMLScreener = nil
	bc.PaymentProvider = nil
	bc.IdentityRegistry = nil

	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(privKey)

	err = productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ONFIDO_WEBHOOK_SECRET")
}

// TestProductionGuard_MissingRegistryKey verifies that a missing
// GREENHOUSE_REGISTRY_PUBKEY is caught after all other checks pass.
func TestProductionGuard_MissingRegistryKey(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "test-secret-value")
	t.Setenv("GREENHOUSE_REGISTRY_PUBKEY", "")

	bc := newTestBlockchain(t)
	bc.AMLScreener = nil
	bc.PaymentProvider = nil
	bc.IdentityRegistry = nil

	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(privKey)

	err = productionReadinessError(bc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GREENHOUSE_REGISTRY_PUBKEY")
}

// TestProductionGuard_AllConfigured_ReturnsNil verifies that a fully configured
// blockchain returns no error.
func TestProductionGuard_AllConfigured_ReturnsNil(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "test-secret-value")

	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	t.Setenv("GREENHOUSE_REGISTRY_PUBKEY", hex.EncodeToString(registryKey.Public().Bytes()))

	bc := newTestBlockchain(t)
	bc.AMLScreener = nil
	bc.PaymentProvider = nil
	bc.IdentityRegistry = nil

	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = NewLocalKeyProvider(privKey)

	assert.NoError(t, productionReadinessError(bc))
}

// TestProductionGuard_NewBlockchain_DoesNotFatalWithoutProductionEnv verifies
// that NewBlockchain with default mocks is safe when GH_ENV != "production".
func TestProductionGuard_NewBlockchain_DoesNotFatalWithoutProductionEnv(t *testing.T) {
	// GH_ENV is unset in the test environment; NewBlockchain must not fatal.
	bc := newTestBlockchain(t)
	assert.NotNil(t, bc)
}

// ---------------------------------------------------------------------------
// OnfidoIdentityRegistry.HandleWebhook — production HMAC enforcement
// ---------------------------------------------------------------------------

// TestOnfidoRegistry_HandleWebhook_ProductionMode_MissingSecret_ReturnsError
// verifies that GH_ENV=production with no ONFIDO_WEBHOOK_SECRET rejects the
// webhook regardless of the provided signature.
func TestOnfidoRegistry_HandleWebhook_ProductionMode_MissingSecret_ReturnsError(t *testing.T) {
	t.Setenv("GH_ENV", "production")
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "")
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"wallet:w1"})
	_, err := reg.HandleWebhook(body, "", InvestorClassRetail, "GB", 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ONFIDO_WEBHOOK_SECRET")
}

// TestOnfidoRegistry_HandleWebhook_ProductionMode_WrongSig_ReturnsError
// verifies that GH_ENV=production with a set secret but wrong signature returns
// an error and does not issue a credential.
func TestOnfidoRegistry_HandleWebhook_ProductionMode_WrongSig_ReturnsError(t *testing.T) {
	secret := "production-webhook-secret"
	t.Setenv("GH_ENV", "production")
	t.Setenv("ONFIDO_WEBHOOK_SECRET", secret)
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"wallet:w1"})
	_, err := reg.HandleWebhook(body, "definitely-wrong-signature", InvestorClassRetail, "GB", 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC")
}

// TestOnfidoRegistry_HandleWebhook_ProductionMode_ValidSig_IssuesCredential
// verifies that a correctly HMAC-signed webhook in production mode issues a credential.
func TestOnfidoRegistry_HandleWebhook_ProductionMode_ValidSig_IssuesCredential(t *testing.T) {
	secret := "production-webhook-secret"
	t.Setenv("GH_ENV", "production")
	t.Setenv("ONFIDO_WEBHOOK_SECRET", secret)
	reg := newTestOnfidoRegistry(t, "")

	walletKey := "wallet-prod-test"
	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"wallet:" + walletKey})
	sig := hmacSig(secret, body)

	att, err := reg.HandleWebhook(body, sig, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	require.NotNil(t, att)
	assert.Equal(t, walletKey, att.WalletPublicKey)
}
