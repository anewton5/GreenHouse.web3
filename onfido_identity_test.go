package gonetwork

// ---------------------------------------------------------------------------
// onfido_identity_test.go — OnfidoIdentityRegistry unit tests
//
// All HTTP calls are intercepted by httptest.Server — no real network access.
// ONFIDO_API_TOKEN is injected via t.Setenv so no real credentials are needed.
//
// Covers:
//   NewOnfidoIdentityRegistry — success, missing env var
//   IssueCredential           — stores attestation; baseURL override for test
//   VerifyCredential          — found / not found
//   RegistryPublicKey         — returns non-nil key
//   InitiateKYC               — success (POST /applicants + POST /checks)
//   InitiateKYC               — applicant creation failure
//   HandleWebhook             — clear result → credential issued
//   HandleWebhook             — consider result → nil (no credential)
//   HandleWebhook             — wrong HMAC → error
//   HandleWebhook             — no wallet tag → error
// ---------------------------------------------------------------------------

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestOnfidoRegistry sets ONFIDO_API_TOKEN and returns a registry whose
// HTTP client points at the provided base URL (typically a test server).
func newTestOnfidoRegistry(t *testing.T, baseURL string) *OnfidoIdentityRegistry {
	t.Helper()
	t.Setenv("ONFIDO_API_TOKEN", "test-token-abc")

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	reg, err := NewOnfidoIdentityRegistry(key)
	require.NoError(t, err)

	// Override the default production URL with the test server URL.
	if baseURL != "" {
		reg.baseURL = baseURL
	}
	return reg
}

// onfidoWebhookBody builds a minimal Onfido webhook payload.
func onfidoWebhookBody(action, status, result string, tags []string) []byte {
	payload := map[string]any{
		"payload": map[string]any{
			"resource_type": "check",
			"action":        action,
			"object": map[string]any{
				"status": status,
				"result": result,
				"tags":   tags,
			},
		},
	}
	b, _ := json.Marshal(payload)
	return b
}

// hmacSig computes the HMAC-SHA256 hex of body using secret.
func hmacSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestOnfidoRegistry_Constructor_MissingToken_Error(t *testing.T) {
	t.Setenv("ONFIDO_API_TOKEN", "") // ensure unset
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	_, err = NewOnfidoIdentityRegistry(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ONFIDO_API_TOKEN")
}

func TestOnfidoRegistry_Constructor_NilKey_Error(t *testing.T) {
	t.Setenv("ONFIDO_API_TOKEN", "some-token")
	_, err := NewOnfidoIdentityRegistry(nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// IssueCredential / VerifyCredential / RegistryPublicKey
// ---------------------------------------------------------------------------

func TestOnfidoRegistry_IssueCredential_StoresAndReturnsAttestation(t *testing.T) {
	reg := newTestOnfidoRegistry(t, "")

	att, err := reg.IssueCredential("wallet-alice", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	require.NotNil(t, att)
	assert.Equal(t, "wallet-alice", att.WalletPublicKey)
	assert.Equal(t, InvestorClassProfessional, att.InvestorClass)
}

func TestOnfidoRegistry_VerifyCredential_Found(t *testing.T) {
	reg := newTestOnfidoRegistry(t, "")
	_, err := reg.IssueCredential("wallet-bob", InvestorClassRetail, "DE", 180)
	require.NoError(t, err)

	att, err := reg.VerifyCredential("wallet-bob")
	require.NoError(t, err)
	assert.Equal(t, "wallet-bob", att.WalletPublicKey)
}

func TestOnfidoRegistry_VerifyCredential_NotFound_ReturnsError(t *testing.T) {
	reg := newTestOnfidoRegistry(t, "")
	_, err := reg.VerifyCredential("wallet-unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no credential found")
}

func TestOnfidoRegistry_RegistryPublicKey_ReturnsNonNil(t *testing.T) {
	reg := newTestOnfidoRegistry(t, "")
	pk := reg.RegistryPublicKey()
	require.NotNil(t, pk)
}

// ---------------------------------------------------------------------------
// InitiateKYC
// ---------------------------------------------------------------------------

func TestOnfidoRegistry_InitiateKYC_Success(t *testing.T) {
	// Mock server: /applicants returns applicantID, /checks returns checkID.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/applicants":
			json.NewEncoder(w).Encode(onfidoApplicantResponse{ID: "applicant-123"})
		case "/checks":
			json.NewEncoder(w).Encode(onfidoCheckResponse{ID: "check-456"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	reg := newTestOnfidoRegistry(t, srv.URL)
	appID, err := reg.InitiateKYC(context.Background(), "wallet-charlie", "Charlie", "Brown")
	require.NoError(t, err)
	assert.Equal(t, "applicant-123", appID)
}

func TestOnfidoRegistry_InitiateKYC_EmptyWalletKey_ReturnsError(t *testing.T) {
	reg := newTestOnfidoRegistry(t, "")
	_, err := reg.InitiateKYC(context.Background(), "", "John", "Doe")
	assert.Error(t, err)
}

func TestOnfidoRegistry_InitiateKYC_ApplicantCreationFails_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	reg := newTestOnfidoRegistry(t, srv.URL)
	_, err := reg.InitiateKYC(context.Background(), "wallet-x", "X", "Y")
	assert.Error(t, err)
}

func TestOnfidoRegistry_InitiateKYC_CheckCreationFails_ReturnsError(t *testing.T) {
	callNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNum++
		w.Header().Set("Content-Type", "application/json")
		if callNum == 1 {
			// applicant succeeds
			json.NewEncoder(w).Encode(onfidoApplicantResponse{ID: "app-ok"})
		} else {
			// check fails
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	reg := newTestOnfidoRegistry(t, srv.URL)
	_, err := reg.InitiateKYC(context.Background(), "wallet-y", "Y", "Z")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// HandleWebhook
// ---------------------------------------------------------------------------

func TestOnfidoRegistry_HandleWebhook_ClearResult_IssuesCredential(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "") // no HMAC check
	reg := newTestOnfidoRegistry(t, "")

	walletKey := "wallet-diana"
	body := onfidoWebhookBody(
		"check.completed", "complete", "clear",
		[]string{"env:prod", "wallet:" + walletKey},
	)

	att, err := reg.HandleWebhook(body, "", InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	require.NotNil(t, att)
	assert.Equal(t, walletKey, att.WalletPublicKey)
}

func TestOnfidoRegistry_HandleWebhook_ConsiderResult_ReturnsNilNoCredential(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "")
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.completed", "complete", "consider", []string{"wallet:wallet-erin"})
	att, err := reg.HandleWebhook(body, "", InvestorClassRetail, "DE", 180)
	require.NoError(t, err)
	assert.Nil(t, att)

	// No credential should have been stored.
	_, verifyErr := reg.VerifyCredential("wallet-erin")
	assert.Error(t, verifyErr)
}

func TestOnfidoRegistry_HandleWebhook_WrongAction_ReturnsNil(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "")
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.started", "in_progress", "", []string{"wallet:w1"})
	att, err := reg.HandleWebhook(body, "", InvestorClassRetail, "FR", 365)
	require.NoError(t, err)
	assert.Nil(t, att)
}

func TestOnfidoRegistry_HandleWebhook_InvalidHMAC_ReturnsError(t *testing.T) {
	secret := "webhook-secret-xyz"
	t.Setenv("ONFIDO_WEBHOOK_SECRET", secret)
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"wallet:w1"})

	// Provide a wrong signature.
	_, err := reg.HandleWebhook(body, "wrong-sig", InvestorClassRetail, "GB", 365)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC")
}

func TestOnfidoRegistry_HandleWebhook_ValidHMAC_IssuesCredential(t *testing.T) {
	secret := "webhook-secret-abc"
	t.Setenv("ONFIDO_WEBHOOK_SECRET", secret)
	reg := newTestOnfidoRegistry(t, "")

	walletKey := "wallet-frank"
	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"wallet:" + walletKey})
	sig := hmacSig(secret, body)

	att, err := reg.HandleWebhook(body, sig, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)
	require.NotNil(t, att)
	assert.Equal(t, walletKey, att.WalletPublicKey)
}

func TestOnfidoRegistry_HandleWebhook_NoWalletTag_ReturnsError(t *testing.T) {
	t.Setenv("ONFIDO_WEBHOOK_SECRET", "")
	reg := newTestOnfidoRegistry(t, "")

	body := onfidoWebhookBody("check.completed", "complete", "clear", []string{"env:prod"})
	_, err := reg.HandleWebhook(body, "", InvestorClassRetail, "GB", 365)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no wallet tag")
}
