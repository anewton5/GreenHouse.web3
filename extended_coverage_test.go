package gonetwork

// extended_coverage_test.go — targeted tests for functions with < 40 % coverage
// or sitting at 0 % in the gonetwork package.
//
// Areas covered:
//   - decryptPrivateKeyLegacy  (via DecryptPrivateKey without "v2:" prefix)
//   - OperatorIdentityRegistry.RegistryPublicKey
//   - EURCPaymentProvider.CreateVirtualAccount  (HTTP paths)
//   - PontesPaymentProvider.GetPaymentStatus   (pending-map → API paths)
//   - Wallet.CreateTransaction / LockCurrency / UnlockCurrency (missing error paths)
//   - Deal / DealAnchor / DealCommitment  (nil-input and wrong-status error paths)

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// decryptPrivateKeyLegacy — exercised via the public DecryptPrivateKey shim
// ---------------------------------------------------------------------------

// buildLegacyEncryptedKey returns a hex-encoded AES-128-CFB ciphertext
// (IV || ciphertext) without the "v2:" prefix so DecryptPrivateKey routes
// to the legacy path.
func buildLegacyEncryptedKey(t *testing.T, passphrase string, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher([]byte(passphrase))
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize) // all-zero IV is fine for test data
	ct := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, plaintext)
	return hex.EncodeToString(append(iv, ct...))
}

func TestDecryptPrivateKeyLegacy_Valid(t *testing.T) {
	passphrase := "test1234test1234" // 16 bytes → AES-128
	plaintext := []byte("seed-bytes-for-key-testing-01234")
	enc := buildLegacyEncryptedKey(t, passphrase, plaintext)

	got, err := DecryptPrivateKey(enc, passphrase)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDecryptPrivateKeyLegacy_InvalidHex(t *testing.T) {
	_, err := DecryptPrivateKey("not-hex!", "test1234test1234")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legacy")
}

func TestDecryptPrivateKeyLegacy_TooShort(t *testing.T) {
	// A valid hex string but shorter than aes.BlockSize (16 bytes)
	short := hex.EncodeToString([]byte{0x01, 0x02, 0x03})
	_, err := DecryptPrivateKey(short, "test1234test1234")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptPrivateKeyLegacy_BadPassphraseLen(t *testing.T) {
	// aes.NewCipher requires 16, 24 or 32 byte key; 5 bytes → error from cipher
	enc := buildLegacyEncryptedKey(t, "test1234test1234", []byte("data"))
	_, err := DecryptPrivateKey(enc, "bad")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// OperatorIdentityRegistry.RegistryPublicKey
// ---------------------------------------------------------------------------

func TestOperatorRegistry_RegistryPublicKey_ReturnsNonNil(t *testing.T) {
	k, err := GeneratePrivateKey()
	require.NoError(t, err)
	reg, err := NewOperatorIdentityRegistry(k)
	require.NoError(t, err)

	pub := reg.RegistryPublicKey()
	require.NotNil(t, pub)
	assert.Equal(t, k.Public().Bytes(), pub.Bytes())
}

// ---------------------------------------------------------------------------
// EURCPaymentProvider.CreateVirtualAccount — HTTP paths
// ---------------------------------------------------------------------------

func newEURCProvider(t *testing.T, serverURL string) *EURCPaymentProvider {
	t.Helper()
	p, err := NewEURCPaymentProvider("api-key-test", serverURL, "ws-set-001", "hmac-secret", NewMemoryPaymentStore())
	require.NoError(t, err)
	return p
}

func TestEURCCreateVirtualAccount_HTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/wallets", r.URL.Path)
		assert.Equal(t, "Bearer api-key-test", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"wallet": map[string]interface{}{
					"id":      "circle-wallet-1",
					"address": "0xDeAdBeEf1234567890AbCdEf1234567890AbCdEf",
				},
			},
		})
	}))
	defer srv.Close()

	p := newEURCProvider(t, srv.URL)
	addr, err := p.CreateVirtualAccount(context.Background(), "investor-wallet-001")
	require.NoError(t, err)
	assert.Equal(t, "0xDeAdBeEf1234567890AbCdEf1234567890AbCdEf", addr)
}

func TestEURCCreateVirtualAccount_Idempotent_SecondCallCached(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"wallet": map[string]interface{}{
					"id":      "c-wallet",
					"address": "0xCACHED",
				},
			},
		})
	}))
	defer srv.Close()

	p := newEURCProvider(t, srv.URL)
	addr1, err := p.CreateVirtualAccount(context.Background(), "cached-wallet")
	require.NoError(t, err)
	addr2, err := p.CreateVirtualAccount(context.Background(), "cached-wallet")
	require.NoError(t, err)
	assert.Equal(t, addr1, addr2)
	assert.Equal(t, 1, callCount, "second call should use cache and not hit the server")
}

func TestEURCCreateVirtualAccount_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newEURCProvider(t, srv.URL)
	_, err := p.CreateVirtualAccount(context.Background(), "wallet-err")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestEURCCreateVirtualAccount_EmptyAddressInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// address field is absent
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"wallet": map[string]interface{}{
					"id": "wallet-no-addr",
				},
			},
		})
	}))
	defer srv.Close()

	p := newEURCProvider(t, srv.URL)
	_, err := p.CreateVirtualAccount(context.Background(), "wallet-noaddr")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no address")
}

func TestEURCCreateVirtualAccount_LongWalletID_TruncatesIdempotencyKey(t *testing.T) {
	var capturedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedKey, _ = body["idempotencyKey"].(string)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"wallet": map[string]interface{}{
					"id":      "w1",
					"address": "0x1234",
				},
			},
		})
	}))
	defer srv.Close()

	p := newEURCProvider(t, srv.URL)
	longID := "this-is-a-very-long-wallet-id-that-exceeds-36-characters"
	_, err := p.CreateVirtualAccount(context.Background(), longID)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(capturedKey), 36, "idempotency key must not exceed 36 chars")
}

// ---------------------------------------------------------------------------
// PontesPaymentProvider.GetPaymentStatus — pending-map → API paths
// ---------------------------------------------------------------------------

// newPontesWithServer returns a PontesPaymentProvider pointed at the given
// test server URL, and also returns a *PaymentInstruction ready to register.
func newPontesWithServer(t *testing.T, serverURL string) *PontesPaymentProvider {
	t.Helper()
	p, err := NewPontesPaymentProvider("pontes-key", serverURL, "DLT-OP-1", "hmac-s", NewMemoryPaymentStore())
	require.NoError(t, err)
	return p
}

func TestPontesGetPaymentStatus_PendingRef_APIReturnsSettled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// RegisterSettlement response
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"transactionId": "tx-pontes-001",
				"status":        "PENDING",
			})
			return
		}
		// GET /settlements/tx-pontes-001 — status poll
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "SETTLED"})
	}))
	defer srv.Close()

	p := newPontesWithServer(t, srv.URL)
	instr := &PaymentInstruction{
		Reference:     "ref-settled",
		PayerWalletID: "BICPAYER",
		PayeeWalletID: "BICPAYEE",
		TotalAmount:   5000.0,
		Currency:      "EUR",
		TravelRule: &TravelRulePayload{
			OriginatorName:    "Test User",
			OriginatorAccount: "DE89370400440532013000",
			BeneficiaryName:   "Test Merchant",
		},
	}
	_, err := p.RegisterSettlement(instr)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "ref-settled")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesGetPaymentStatus_PendingRef_APIReturnsPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"transactionId": "tx-pending-02",
				"status":        "PENDING",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "PENDING"})
	}))
	defer srv.Close()

	p := newPontesWithServer(t, srv.URL)
	instr := &PaymentInstruction{
		Reference:     "ref-still-pending",
		PayerWalletID: "BICPAYER",
		PayeeWalletID: "BICPAYEE",
		TotalAmount:   2500.0,
		Currency:      "EUR",
		TravelRule: &TravelRulePayload{
			// minimal valid fields (adjust to your struct)
			OriginatorName:    "Test User",
			OriginatorAccount: "NL91ABNA0417164300",
			BeneficiaryName:   "Test Merchant",
		},
	}
	_, err := p.RegisterSettlement(instr)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "ref-still-pending")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestPontesGetPaymentStatus_PendingRef_APIFails_ReturnsUnknown(t *testing.T) {
	// POST /settlements succeeds; GET fails with 500 → provider returns Unknown
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"transactionId": "tx-fail-03",
				"status":        "PENDING",
			})
			return
		}
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	p := newPontesWithServer(t, srv.URL)
	instr := &PaymentInstruction{
		Reference:     "ref-api-fail",
		PayerWalletID: "BICPAYER",
		PayeeWalletID: "BICPAYEE",
		TotalAmount:   100.0,
		Currency:      "EUR",
		TravelRule: &TravelRulePayload{
			OriginatorName:  "Test User",
			BeneficiaryName: "Test Merchant",
		},
	}
	_, err := p.RegisterSettlement(instr)
	require.NoError(t, err)

	// GetPaymentStatus hits the API which returns 504; should return Unknown with error
	status, err := p.GetPaymentStatus(context.Background(), "ref-api-fail")
	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
}

func TestPontesGetPaymentStatus_PendingRef_BadJSONResponse_ReturnsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"transactionId": "tx-badjson",
				"status":        "PENDING",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{invalid json"))
	}))
	defer srv.Close()

	p := newPontesWithServer(t, srv.URL)
	instr := &PaymentInstruction{
		Reference:     "ref-badjson",
		PayerWalletID: "BICPAYER",
		PayeeWalletID: "BICPAYEE",
		TotalAmount:   100.0,
		Currency:      "EUR",
		TravelRule: &TravelRulePayload{
			OriginatorName:  "Test User",
			BeneficiaryName: "Test Merchant",
		},
	}
	_, err := p.RegisterSettlement(instr)
	require.NoError(t, err)

	// Bad JSON response must return Unknown with an explicit decode error.
	status, err := p.GetPaymentStatus(context.Background(), "ref-badjson")
	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
}

// ---------------------------------------------------------------------------
// Wallet — missing error paths
// ---------------------------------------------------------------------------

func TestWallet_CreateTransaction_ZeroAmount(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	_, err = w.CreateTransaction("receiver-key", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "greater than zero")
}

func TestWallet_CreateTransaction_NegativeAmount(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	_, err = w.CreateTransaction("receiver-key", -10)
	require.Error(t, err)
}

func TestWallet_CreateTransaction_NilPrivateKey(t *testing.T) {
	w := &Wallet{PrivateKey: nil, PublicKey: nil, Balance: 100}
	_, err := w.CreateTransaction("receiver-key", 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestWallet_LockCurrency_ZeroAmount_Error(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 50
	err = w.LockCurrency(0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "greater than zero")
}

func TestWallet_LockCurrency_InsufficientBalance_Error(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 10
	err = w.LockCurrency(100)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")
}

func TestWallet_LockCurrency_CreatesNewLockedEntry(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 200

	err = w.LockCurrency(50)
	require.NoError(t, err)
	assert.InDelta(t, 150.0, w.Balance, 1e-9)

	wallets := GetLockedWallets()
	var key [32]byte
	copy(key[:], w.PublicKey.Bytes()[:32])
	lw, ok := wallets[key]
	require.True(t, ok, "locked wallet entry should have been created")
	assert.InDelta(t, 50.0, lw.Balance, 1e-9)
}

func TestWallet_UnlockCurrency_ZeroAmount_Error(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 50
	err = w.UnlockCurrency(0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "greater than zero")
}

func TestWallet_UnlockCurrency_NoLockedEntry_Error(t *testing.T) {
	// Fresh wallet with no locked entry
	w, err := NewWallet()
	require.NoError(t, err)
	err = w.UnlockCurrency(10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient locked")
}

func TestWallet_LockThenUnlock_FullCycle(t *testing.T) {
	w, err := NewWallet()
	require.NoError(t, err)
	w.Balance = 100

	require.NoError(t, w.LockCurrency(60))
	assert.InDelta(t, 40.0, w.Balance, 1e-9)

	require.NoError(t, w.UnlockCurrency(60))
	assert.InDelta(t, 100.0, w.Balance, 1e-9)

	// Locked entry should be removed after full unlock
	var key [32]byte
	copy(key[:], w.PublicKey.Bytes()[:32])
	wallets := GetLockedWallets()
	_, exists := wallets[key]
	assert.False(t, exists, "locked wallet entry should be removed after full unlock")
}

// ---------------------------------------------------------------------------
// Deal — nil-input and wrong-status error paths
// ---------------------------------------------------------------------------

func TestNewDeal_NilKey_Error(t *testing.T) {
	_, err := NewDeal(nil, "ASSET-1", "", 1_000_000, 0.20, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewDeal_ZeroTargetAmount_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	_, err := NewDeal(k, "ASSET-1", "", 0, 0.20, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "targetRaiseAmount")
}

func TestNewDeal_ZeroDeadlineDays_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	_, err := NewDeal(k, "ASSET-1", "", 1_000_000, 0.20, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anchorDeadlineDays")
}

func TestNewDealAnchor_NilKey_Error(t *testing.T) {
	_, err := NewDealAnchor(nil, "deal-id", 100_000, "EUR", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewDealAnchor_ZeroAmount_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	_, err := NewDealAnchor(k, "deal-id", 0, "EUR", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "greater than zero")
}

func TestNewDealCommitment_NilKey_Error(t *testing.T) {
	_, err := NewDealCommitment(nil, "deal-id", 50_000, "EUR")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewDealCommitment_ZeroAmount_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	_, err := NewDealCommitment(k, "deal-id", 0, "EUR")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "greater than zero")
}

func TestAttachAnchor_NilAnchor_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	d, _ := NewDeal(k, "ASSET-X", "", 500_000, 0.25, 30)
	err := d.AttachAnchor(nil, k.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestAttachAnchor_WrongStatus_Closed_Error(t *testing.T) {
	k, _ := GeneratePrivateKey()
	d, _ := NewDeal(k, "ASSET-X", "", 500_000, 0.25, 30)
	d.Status = DealStatusClosed
	anchor, _ := NewDealAnchor(k, d.ID, 200_000, "EUR", nil)
	err := d.AttachAnchor(anchor, k.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestAttachAnchor_InvalidSignature_Error(t *testing.T) {
	issuer, _ := GeneratePrivateKey()
	anchorKey, _ := GeneratePrivateKey()
	wrongKey, _ := GeneratePrivateKey()

	d, _ := NewDeal(issuer, "ASSET-X", "", 500_000, 0.25, 30)
	anchor, _ := NewDealAnchor(anchorKey, d.ID, 200_000, "EUR", nil)

	// Verify with wrong public key → invalid signature
	err := d.AttachAnchor(anchor, wrongKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestAddCoInvestor_NilCommitment_Error(t *testing.T) {
	issuer, _ := GeneratePrivateKey()
	anchorKey, _ := GeneratePrivateKey()
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred, err := reg.IssueCredential(anchorWalletKey, InvestorClassProfessional, "DE", 365)
	require.NoError(t, err)

	d, _ := NewDeal(issuer, "ASSET-X", "", 500_000, 0.25, 30)
	anchor, _ := NewDealAnchor(anchorKey, d.ID, 200_000, "EUR", cred)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	err = d.AddCoInvestor(nil, anchorKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestAddCoInvestor_DealIDMismatch_Error(t *testing.T) {
	issuer, _ := GeneratePrivateKey()
	anchorKey, _ := GeneratePrivateKey()
	coKey, _ := GeneratePrivateKey()

	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred, err := reg.IssueCredential(anchorWalletKey, InvestorClassProfessional, "DE", 365)
	require.NoError(t, err)

	d, _ := NewDeal(issuer, "ASSET-X", "", 500_000, 0.25, 30)
	anchor, _ := NewDealAnchor(anchorKey, d.ID, 200_000, "EUR", cred)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	// commitment signed for a different deal ID
	commitment, _ := NewDealCommitment(coKey, "wrong-deal-id", 50_000, "EUR")
	err = d.AddCoInvestor(commitment, coKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestAddCoInvestor_InvalidSignature_Error(t *testing.T) {
	issuer, _ := GeneratePrivateKey()
	anchorKey, _ := GeneratePrivateKey()
	coKey, _ := GeneratePrivateKey()
	wrongKey, _ := GeneratePrivateKey()

	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred, err := reg.IssueCredential(anchorWalletKey, InvestorClassProfessional, "DE", 365)
	require.NoError(t, err)

	d, _ := NewDeal(issuer, "ASSET-X", "", 500_000, 0.25, 30)
	anchor, _ := NewDealAnchor(anchorKey, d.ID, 200_000, "EUR", cred)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	commitment, _ := NewDealCommitment(coKey, d.ID, 50_000, "EUR")
	// Verify with wrong public key → invalid signature
	err = d.AddCoInvestor(commitment, wrongKey.Public(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestCheckAnchorDeadline_HasAnchor_ReturnsFalse(t *testing.T) {
	issuer, _ := GeneratePrivateKey()
	anchorKey, _ := GeneratePrivateKey()

	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	anchorWalletKey := pubKeyB64(anchorKey)
	cred, err := reg.IssueCredential(anchorWalletKey, InvestorClassProfessional, "GB", 365)
	require.NoError(t, err)

	d, _ := NewDeal(issuer, "ASSET-Y", "", 1_000_000, 0.30, 30)
	anchor, _ := NewDealAnchor(anchorKey, d.ID, 400_000, "EUR", cred)
	require.NoError(t, d.AttachAnchor(anchor, anchorKey.Public(), nil))

	// Anchor is set → CheckAnchorDeadline must return false
	assert.False(t, d.CheckAnchorDeadline())
	assert.NotEqual(t, DealStatusFailed, d.Status)
}
