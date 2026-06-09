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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
type failingStore struct {
	setErr error
	getErr error
}

func (f *failingStore) SetPending(
	ctx context.Context,
	reference, transactionID string,
	expectedAmount float64,
	expectedCurrency string,
) error {
	return f.setErr
}

func (f *failingStore) GetPending(
	ctx context.Context,
	reference string,
) (string, bool, error) {
	if f.getErr != nil {
		return "", false, f.getErr
	}
	return "", false, nil
}

func (f *failingStore) SetStatus(
	ctx context.Context,
	reference string,
	status PaymentStatus,
) error {
	return nil
}

func (f *failingStore) GetStatus(
	ctx context.Context,
	reference string,
) (PaymentStatus, bool, error) {
	return PaymentStatusUnknown, false, nil
}

func (f *failingStore) GetExpected(
	ctx context.Context,
	reference string,
) (float64, string, bool, error) {
	return 0, "", false, nil
}

func (f *failingStore) SetWalletAddress(
	ctx context.Context,
	walletID, address string,
) error {
	return nil
}

func (f *failingStore) GetWalletAddress(
	ctx context.Context,
	walletID string,
) (string, bool, error) {
	return "", false, nil
}

func (f *failingStore) PendingOlderThan(
	ctx context.Context,
	cutoff time.Time,
) ([]PendingSettlement, error) {
	return nil, nil
}

func TestNewPontesPaymentProvider_Valid(t *testing.T) {
	p, err := NewPontesPaymentProvider("key-123", "https://example.com", "GH-OP-01", "secret", NewMemoryPaymentStore())
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestNewPontesPaymentProvider_DefaultBaseURL(t *testing.T) {
	p, err := NewPontesPaymentProvider("key-123", "", "GH-OP-01", "secret", NewMemoryPaymentStore())
	require.NoError(t, err)
	// empty baseURL is accepted (defaults would be applied at construction if desired)
	assert.NotNil(t, p)
}

func TestNewPontesPaymentProvider_MissingAPIKey_Error(t *testing.T) {
	_, err := NewPontesPaymentProvider("", "https://example.com", "GH-OP-01", "secret", NewMemoryPaymentStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiKey")
}

func TestNewPontesPaymentProvider_MissingDLTOperator_Error(t *testing.T) {
	_, err := NewPontesPaymentProvider("key-123", "https://example.com", "", "secret", NewMemoryPaymentStore())
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
	t.Setenv("PONTES_HMAC_SECRET", "test-secret")
	p, err := NewPontesPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, pontesPilotBaseURL, p.baseURL)
}

func TestNewPontesPaymentProviderFromEnv_CustomBaseURL(t *testing.T) {
	t.Setenv("PONTES_API_KEY", "test-key")
	t.Setenv("PONTES_DLT_OPERATOR", "GH-OP-01")
	t.Setenv("PONTES_BASE_URL", "https://custom.pontes.example.com/v1")
	t.Setenv("PONTES_HMAC_SECRET", "test-secret")
	p, err := NewPontesPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://custom.pontes.example.com/v1", p.baseURL)
}

// ---------------------------------------------------------------------------
// CreateVirtualAccount
// ---------------------------------------------------------------------------

func TestPontesCreateVirtualAccount_ReturnsPrefix(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "test-hmac-secret", NewMemoryPaymentStore())
	ref, err := p.CreateVirtualAccount(context.Background(), "wallet-abc")
	require.NoError(t, err)
	assert.Equal(t, "pontes-wallet-abc", ref)
}

func TestPontesCreateVirtualAccount_EmptyWallet(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "test-hmac-secret", NewMemoryPaymentStore())
	ref, err := p.CreateVirtualAccount(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, "pontes-", ref)
}

// ---------------------------------------------------------------------------
// GetPaymentStatus — local cache paths (no HTTP)
// ---------------------------------------------------------------------------

func TestPontesGetPaymentStatus_Unknown_ReturnsError(t *testing.T) {
	store := NewMemoryPaymentStore()

	p, err := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)
	require.NoError(t, err)
	require.NotNil(t, p)

	status, err := p.GetPaymentStatus(context.Background(), "unknown-ref")

	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
	assert.Contains(t, err.Error(), "unknown-ref")
}

func TestPontesGetPaymentStatus_AfterConfirm_ReturnsConfirmed(t *testing.T) {
	store := NewMemoryPaymentStore()

	p, err := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret", // ✅ required after B-5
		store,
	)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Seed expected settlement (B-4 dependency)
	require.NoError(t, store.SetPending(
		context.Background(),
		"ref-001",
		"txn-001",
		1000,
		"EUR",
	))

	require.NoError(t, p.ConfirmPayment(
		context.Background(),
		"ref-001",
		1000,
		"EUR",
	))

	status, err := p.GetPaymentStatus(context.Background(), "ref-001")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesGetPaymentStatus_ConcurrentPolling_NoDeadlock(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)

		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/settlements/tx-123", r.URL.Path)

		time.Sleep(50 * time.Millisecond)

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"CONFIRMED"}`)
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"k",
		srv.URL,
		"OP",
		"test-hmac-secret",
		NewMemoryPaymentStore(),
	)
	require.NoError(t, err)

	require.NoError(t, p.store.SetPending(
		context.Background(),
		"ref-1",
		"tx-123",
		1000.0,
		"EUR",
	))

	var wg sync.WaitGroup
	results := make([]PaymentStatus, 2)
	errs := make([]error, 2)
	start := make(chan struct{})

	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = p.GetPaymentStatus(context.Background(), "ref-1")
		}()
	}

	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("GetPaymentStatus calls did not complete")
	}

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	assert.Equal(t, PaymentStatusConfirmed, results[0])
	assert.Equal(t, PaymentStatusConfirmed, results[1])

	assert.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(1))
}

func TestPontesGetPaymentStatus_404_ReturnsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `not found`)
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider("k", srv.URL, "OP", "test-hmac-secret", NewMemoryPaymentStore())
	require.NoError(t, err)
	require.NoError(t, p.store.SetPending(
		context.Background(),
		"ref-404",
		"tx-404",
		1000.0,
		"EUR",
	))

	status, err := p.GetPaymentStatus(context.Background(), "ref-404")
	require.Error(t, err)
	assert.Equal(t, PaymentStatusFailed, status)
	assert.Contains(t, err.Error(), "not found (404)")
}

func TestPontesGetPaymentStatus_503_ReturnsUnknownWithError(t *testing.T) {
	oldBackoffs := paymentRetryBackoffs
	oldJitter := paymentRetryJitter
	paymentRetryBackoffs = []time.Duration{0, time.Millisecond, time.Millisecond}
	paymentRetryJitter = func() float64 { return 0 }
	defer func() {
		paymentRetryBackoffs = oldBackoffs
		paymentRetryJitter = oldJitter
	}()

	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(
		context.Background(),
		"ref-503",
		"tx-503",
		1000,
		"EUR",
	))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `service unavailable`)
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"k",
		srv.URL,
		"OP",
		"test-hmac-secret",
		store,
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "ref-503")

	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
	assert.Contains(t, err.Error(), "503")
}

func TestPontesGetPaymentStatus_DecodeError_ReturnsError(t *testing.T) {
	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(
		context.Background(),
		"ref-decode",
		"tx-decode",
		1000,
		"EUR",
	))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":`) // invalid JSON
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"k",
		srv.URL,
		"OP",
		"test-hmac-secret",
		store,
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "ref-decode")

	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
	assert.Contains(t, err.Error(), "decode")
}

// ---------------------------------------------------------------------------
// ConfirmPayment
// ---------------------------------------------------------------------------

func TestPontesConfirmPayment_AcceptsEUR(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"trade-1",
			"txn-1",
			5000,
			"EUR",
		),
	)

	p, _ := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)

	require.NoError(
		t,
		p.ConfirmPayment(
			context.Background(),
			"trade-1",
			5000,
			"EUR",
		),
	)

	status, err := p.GetPaymentStatus(
		context.Background(),
		"trade-1",
	)

	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesConfirmPayment_Idempotent(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"trade-2",
			"txn-2",
			1000,
			"EUR",
		),
	)

	p, _ := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)

	require.NoError(
		t,
		p.ConfirmPayment(
			context.Background(),
			"trade-2",
			1000,
			"EUR",
		),
	)

	require.NoError(
		t,
		p.ConfirmPayment(
			context.Background(),
			"trade-2",
			1000,
			"EUR",
		),
	)

	status, err := p.GetPaymentStatus(
		context.Background(),
		"trade-2",
	)

	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontesConfirmPayment_CurrencyMismatch_ReturnsError(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"trade-chf",
			"txn-3",
			9999.99,
			"EUR",
		),
	)

	p, _ := NewPontesPaymentProvider(
		"k",
		"https://example.com",
		"OP",
		"test-hmac-secret",
		store,
	)

	err := p.ConfirmPayment(
		context.Background(),
		"trade-chf",
		9999.99,
		"CHF",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "currency mismatch")
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
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz", NewMemoryPaymentStore())
	payload := []byte(`{"event":"settlement.confirmed","ref":"trade-1"}`)
	sig := pontesHMAC(t, "webhook-secret-xyz", payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

func TestPontesVerifyWebhookSignature_TamperedPayload_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz", NewMemoryPaymentStore())
	payload := []byte(`{"event":"settlement.confirmed","ref":"trade-1"}`)
	sig := pontesHMAC(t, "webhook-secret-xyz", payload)
	// tamper the payload
	tampered := []byte(`{"event":"settlement.confirmed","ref":"trade-EVIL"}`)
	assert.False(t, p.VerifyWebhookSignature(tampered, sig))
}

func TestPontesVerifyWebhookSignature_WrongSecret_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz", NewMemoryPaymentStore())
	payload := []byte(`{"event":"settlement.confirmed"}`)
	sig := pontesHMAC(t, "wrong-secret", payload)
	assert.False(t, p.VerifyWebhookSignature(payload, sig))
}

func TestPontesVerifyWebhookSignature_EmptyHMACSecret_False(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "webhook-secret-xyz", NewMemoryPaymentStore())
	payload := []byte(`{"event":"settlement.confirmed"}`)
	assert.False(t, p.VerifyWebhookSignature(payload, "any-sig"))
}

func TestPontesVerifyWebhookSignature_EmptyPayload_Valid(t *testing.T) {
	p, _ := NewPontesPaymentProvider("k", "https://example.com", "OP", "my-secret", NewMemoryPaymentStore())
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

func TestPontes_RegisterSettlement_CancelledContext_NoRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false

	p := &PontesPaymentProvider{
		client: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					called = true
					return nil, errors.New("should not run")
				},
			},
		},
		baseURL: "http://example",
		store:   NewMemoryPaymentStore(),
	}

	instr := &PaymentInstruction{
		Reference: "ref",
	}

	_, err := p.RegisterSettlementCtx(ctx, instr)

	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
}

func TestPontes_RegisterSettlement_Idempotent_SameReference(t *testing.T) {
	store := NewMemoryPaymentStore()

	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/settlements", r.URL.Path)

		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(pontesRegisterResponse{
			TransactionID: "txn-001",
			Status:        "PENDING",
		})
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"api-key",
		srv.URL,
		"dlt-operator",
		"secret",
		store,
	)
	require.NoError(t, err)

	instr := &PaymentInstruction{
		Reference:   "ref-001",
		TotalAmount: 500.0,
		Currency:    "EUR",
	}

	txn1, err := p.RegisterSettlementCtx(context.Background(), instr)
	require.NoError(t, err)
	require.Equal(t, "txn-001", txn1)
	require.Equal(t, 1, callCount)

	// Second call should hit local store/cache only.
	txn2, err := p.RegisterSettlementCtx(context.Background(), instr)
	require.NoError(t, err)
	require.Equal(t, "txn-001", txn2)

	assert.Equal(
		t,
		1,
		callCount,
		"API must not be called on repeated registration of same reference",
	)
}

func TestPontes_RegisterSettlement_IdempotencyKeyHeader_IsSet(t *testing.T) {
	var capturedKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		capturedKey = r.Header.Get("Idempotency-Key")

		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(pontesRegisterResponse{
			TransactionID: "txn-002",
		})
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"api-key",
		srv.URL,
		"dlt-operator",
		"secret",
		NewMemoryPaymentStore(),
	)
	require.NoError(t, err)

	instr := &PaymentInstruction{
		Reference:   "ref-002",
		TotalAmount: 100.0,
		Currency:    "EUR",
	}

	_, err = p.RegisterSettlementCtx(context.Background(), instr)

	require.NoError(t, err)
	assert.Equal(t, "gh-settle-ref-002", capturedKey)
}

func TestPontes_RegisterSettlement_StoreFailure_ReturnsError(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(pontesRegisterResponse{
			TransactionID: "txn-003",
		})
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"api-key",
		srv.URL,
		"dlt-operator",
		"secret",
		&failingStore{
			setErr: errors.New("db down"),
		},
	)
	require.NoError(t, err)

	instr := &PaymentInstruction{
		Reference:   "ref-003",
		TotalAmount: 100.0,
		Currency:    "EUR",
	}

	_, err = p.RegisterSettlementCtx(context.Background(), instr)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to persist")
}

func TestPontes_GetPaymentStatus_WebhookConfirms_DuringPoll_ReturnsConfirmed(t *testing.T) {
	ctx := context.Background()

	store := NewMemoryPaymentStore()

	require.NoError(t, store.SetPending(
		ctx,
		"ref-001",
		"txn-001",
		1000.0,
		"EUR",
	))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, http.MethodGet, r.Method)

		// Simulate webhook confirmation occurring while the
		// status poll is in flight.
		require.NoError(t,
			store.SetStatus(
				ctx,
				"ref-001",
				PaymentStatusConfirmed,
			),
		)

		// API returns stale data.
		w.Header().Set("Content-Type", "application/json")

		require.NoError(t,
			json.NewEncoder(w).Encode(map[string]string{
				"status": "PENDING",
			}),
		)
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"api-key",
		srv.URL,
		"dlt-operator",
		"secret",
		store,
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(
		ctx,
		"ref-001",
	)

	require.NoError(t, err)

	assert.Equal(
		t,
		PaymentStatusConfirmed,
		status,
		"store-confirmed status must win over stale API response",
	)
}

func TestPontes_GetPaymentStatus_UnknownReference_ReturnsError(t *testing.T) {
	ctx := context.Background()
	p := newTestPontesProvider(t, NewMemoryPaymentStore())

	status, err := p.GetPaymentStatus(ctx, "never-registered")

	require.Error(t, err)
	assert.Equal(t, PaymentStatusUnknown, status)
	assert.Contains(t, err.Error(), "never-registered")
}

func TestPontes_GetPaymentStatus_Pending_RemainsPending(t *testing.T) {
	ctx := context.Background()

	store := NewMemoryPaymentStore()

	require.NoError(t, store.SetPending(
		ctx,
		"ref-pending",
		"txn-pending",
		1000.0,
		"EUR",
	))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "/settlements/txn-pending")

		w.Header().Set("Content-Type", "application/json")

		require.NoError(t,
			json.NewEncoder(w).Encode(map[string]string{
				"status": "PENDING",
			}),
		)
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider(
		"api-key",
		srv.URL,
		"dlt-operator",
		"secret",
		store,
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(
		ctx,
		"ref-pending",
	)

	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)

	// Verify the B-6 fix did not incorrectly persist a terminal status.
	storedStatus, found, err := store.GetStatus(
		ctx,
		"ref-pending",
	)

	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, PaymentStatusUnknown, storedStatus)
}

func TestNewPontesPaymentProvider_EmptyHmacSecret_ReturnsError(t *testing.T) {
	_, err := NewPontesPaymentProvider("key", "http://example", "op", "", NewMemoryPaymentStore())
	require.Error(t, err)
	require.Contains(t, err.Error(), "hmacSecret must not be empty")
}

func TestPontes_ConfirmPayment_AmountMismatch_ReturnsError(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(ctx, "ref-001", "txn-001", 1500.00, "EUR"))

	p := newTestPontesProvider(t, store)

	err := p.ConfirmPayment(ctx, "ref-001", 400.00, "EUR")
	require.Error(t, err)
	require.Contains(t, err.Error(), "amount mismatch")

	// Status must NOT be confirmed after a mismatch
	status, _, _ := store.GetStatus(ctx, "ref-001")
	require.NotEqual(t, PaymentStatusConfirmed, status)
}

func TestPontes_ConfirmPayment_CurrencyMismatch_ReturnsError(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(ctx, "ref-002", "txn-002", 1000.00, "EUR"))

	p := newTestPontesProvider(t, store)

	err := p.ConfirmPayment(ctx, "ref-002", 1000.00, "GBP")
	require.Error(t, err)
	require.Contains(t, err.Error(), "currency mismatch")
}

func TestPontes_ConfirmPayment_UnknownReference_ReturnsError(t *testing.T) {
	ctx := context.Background()
	p := newTestPontesProvider(t, NewMemoryPaymentStore())

	err := p.ConfirmPayment(ctx, "never-registered", 1000.00, "EUR")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown reference")
}

func TestPontes_ConfirmPayment_ValidAmount_Succeeds(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(ctx, "ref-003", "txn-003", 1000.00, "EUR"))

	p := newTestPontesProvider(t, store)

	// Exact amount
	require.NoError(t, p.ConfirmPayment(ctx, "ref-003", 1000.00, "EUR"))

	status, found, _ := store.GetStatus(ctx, "ref-003")
	require.True(t, found)
	require.Equal(t, PaymentStatusConfirmed, status)
}

func TestPontes_ConfirmPayment_SmallFloatDifference_Succeeds(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()
	require.NoError(t, store.SetPending(ctx, "ref-004", "txn-004", 1000.00, "EUR"))

	p := newTestPontesProvider(t, store)

	// 0.05% difference — within tolerance
	require.NoError(t, p.ConfirmPayment(ctx, "ref-004", 1000.50, "EUR"))
}

func TestPontes_RegisterSettlement_OverallTimeout_IsRespected(t *testing.T) {
	p := newTestPontesProvider(t, NewMemoryPaymentStore())

	// handlerDone lets the test explicitly unblock the server handler before
	// calling srv.Close(), preventing the deferred close from hanging because
	// httptest does not force-close active HTTP/1.1 connections on its own.
	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-handlerDone // blocks until the test unblocks it
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	p.baseURL = srv.URL

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.RegisterSettlementCtx(ctx, &PaymentInstruction{Reference: "ref", Currency: "EUR", TotalAmount: 100})
	elapsed := time.Since(start)

	// Unblock the blocked server handler before draining the server.
	close(handlerDone)
	srv.Close()

	require.Error(t, err)
	require.Less(t, elapsed, 500*time.Millisecond, "operation must abort within 500ms when ctx deadline is 100ms")
}

func TestPontes_GetPaymentStatus_UnknownReference_NotSilent(t *testing.T) {
	p := newTestPontesProvider(t, NewMemoryPaymentStore())

	status, err := p.GetPaymentStatus(context.Background(), "unknown-ref")
	require.Error(t, err, "unknown reference must return an error, not a silent pending")
	require.Equal(t, PaymentStatusUnknown, status)
	require.Contains(t, err.Error(), "unknown-ref")
}

func TestValidateTravelRule_AboveThreshold_MissingPayload_ReturnsError(t *testing.T) {
	instr := &PaymentInstruction{
		TotalAmount: 1500.00,
		Currency:    "EUR",
		TravelRule:  nil,
	}
	err := validateTravelRule(instr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TravelRulePayload is required")
}

func TestValidateTravelRule_AboveThreshold_ValidPayload_NoError(t *testing.T) {
	instr := &PaymentInstruction{
		TotalAmount: 1500.00,
		Currency:    "EUR",
		TravelRule: &TravelRulePayload{
			OriginatorName:    "Alice Smith",
			OriginatorAccount: "GB29NWBK60161331926819",
			BeneficiaryName:   "Bob Jones",
		},
	}
	require.NoError(t, validateTravelRule(instr))
}

func TestValidateTravelRule_BelowThreshold_NoPayload_NoError(t *testing.T) {
	instr := &PaymentInstruction{
		TotalAmount: 999.99,
		Currency:    "EUR",
		TravelRule:  nil,
	}
	require.NoError(t, validateTravelRule(instr))
}

func TestPontes_RegisterSettlement_AboveThreshold_NoTravelRule_ReturnsError(t *testing.T) {
	p := newTestPontesProvider(t, NewMemoryPaymentStore())
	instr := &PaymentInstruction{
		Reference:   "ref-001",
		TotalAmount: 5000.00,
		Currency:    "EUR",
		TravelRule:  nil,
	}
	_, err := p.RegisterSettlementCtx(context.Background(), instr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TravelRulePayload is required")
}

func TestNewPontesPaymentProvider_InvalidBaseURL_ReturnsError(t *testing.T) {
	_, err := NewPontesPaymentProvider("key", "not a url", "op", "secret", NewMemoryPaymentStore())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid URL")
}

func TestNewPontesPaymentProvider_EmptyBaseURL_DefaultsToPilot(t *testing.T) {
	p, err := NewPontesPaymentProvider("key", "", "op", "secret", NewMemoryPaymentStore())
	require.NoError(t, err)
	require.Equal(t, pontesPilotBaseURL, p.baseURL)
}

func TestPontes_ReconcileOnce_ConfirmsStaleSettlement(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPaymentStore()

	// Register a settlement that is older than the staleness window
	require.NoError(t, store.SetPending(ctx, "ref-001", "txn-001", 1000.0, "EUR"))

	p := newTestPontesProvider(t, store)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "/settlements/txn-001")

		w.Header().Set("Content-Type", "application/json")

		require.NoError(t,
			json.NewEncoder(w).Encode(map[string]string{
				"status": "SETTLED",
			}),
		)
	}))
	defer srv.Close()

	p.baseURL = srv.URL

	p.reconcileOnce(ctx, -1*time.Second) // staleness = -1s means everything is stale

	status, found, _ := store.GetStatus(ctx, "ref-001")
	require.True(t, found)
	require.Equal(t, PaymentStatusConfirmed, status)
}
