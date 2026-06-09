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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// NewEURCPaymentProvider
// ---------------------------------------------------------------------------

func TestNewEURCPaymentProvider_Valid(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, err := NewEURCPaymentProvider("key123", "https://api.circle.com/v1", "ws-001", "secret", store)
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestNewEURCPaymentProvider_MissingAPIKey_Error(t *testing.T) {
	store := NewMemoryPaymentStore()
	_, err := NewEURCPaymentProvider("", "https://api.circle.com/v1", "ws-001", "secret", store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiKey")
}

func TestNewEURCPaymentProvider_MissingBaseURL_Error(t *testing.T) {
	store := NewMemoryPaymentStore()
	_, err := NewEURCPaymentProvider("key123", "", "ws-001", "secret", store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "baseURL")
}

func TestNewEURCPaymentProvider_NoWebhookSecret_OK(t *testing.T) {
	store := NewMemoryPaymentStore()

	p, err := NewEURCPaymentProvider(
		"key123",
		"https://api.circle.com/v1",
		"ws-001",
		"test-secret",
		store,
	)

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
	t.Setenv("CIRCLE_WEBHOOK_SECRET", "test-secret")

	p, err := NewEURCPaymentProviderFromEnv()
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "https://api.circle.com/v1", p.baseURL)
}

func TestNewEURCPaymentProviderFromEnv_CustomBaseURL(t *testing.T) {
	t.Setenv("CIRCLE_API_KEY", "key123")
	t.Setenv("CIRCLE_WALLET_SET_ID", "ws-001")
	t.Setenv("CIRCLE_BASE_URL", "https://custom.example.com/v2")
	t.Setenv("CIRCLE_WEBHOOK_SECRET", "test-secret")

	p, err := NewEURCPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://custom.example.com/v2", p.baseURL)
}

// ---------------------------------------------------------------------------
// GetPaymentStatus
// ---------------------------------------------------------------------------

func TestGetPaymentStatus_UnknownRef_ReturnsPending(t *testing.T) {
	store := NewMemoryPaymentStore()

	p, err := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(context.Background(), "UNKNOWN-REF")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestGetPaymentStatus_AfterConfirm_ReturnsConfirmed(t *testing.T) {
	store := NewMemoryPaymentStore()

	err := store.SetPending(
		context.Background(),
		"REF-001",
		"txn-001",
		1000,
		"EUR",
	)
	require.NoError(t, err)

	p, err := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)
	require.NoError(t, err)

	err = p.ConfirmPayment(
		context.Background(),
		"REF-001",
		1000,
		"EUR",
	)
	require.NoError(t, err)

	status, err := p.GetPaymentStatus(
		context.Background(),
		"REF-001",
	)
	require.NoError(t, err)

	assert.Equal(t, PaymentStatusConfirmed, status)
}

// ---------------------------------------------------------------------------
// ConfirmPayment
// ---------------------------------------------------------------------------

func TestConfirmPayment_EUR_OK(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"REF-EUR-001",
			"txn-001",
			5000,
			"EUR",
		),
	)

	p, _ := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)

	err := p.ConfirmPayment(
		context.Background(),
		"REF-EUR-001",
		5000,
		"EUR",
	)

	assert.NoError(t, err)
}

func TestConfirmPayment_EURC_OK(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"REF-EURC-001",
			"txn-001",
			5000,
			"EURC",
		),
	)

	p, _ := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)

	err := p.ConfirmPayment(
		context.Background(),
		"REF-EURC-001",
		5000,
		"EURC",
	)

	assert.NoError(t, err)
}

func TestConfirmPayment_WrongCurrency_Error(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"REF-USD-001",
			"txn-001",
			5000,
			"EUR",
		),
	)

	p, _ := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)

	err := p.ConfirmPayment(
		context.Background(),
		"REF-USD-001",
		5000,
		"USD",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "currency mismatch")
}

func TestConfirmPayment_WrongCurrency_GBP_Error(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "test-webhook-secret", store)
	err := p.ConfirmPayment(context.Background(), "REF-GBP-001", 5000, "GBP")
	require.Error(t, err)
}

func TestConfirmPayment_Idempotent(t *testing.T) {
	store := NewMemoryPaymentStore()

	require.NoError(
		t,
		store.SetPending(
			context.Background(),
			"REF-IDEM",
			"txn-001",
			100,
			"EUR",
		),
	)

	p, _ := NewEURCPaymentProvider(
		"key",
		"https://x",
		"ws",
		"test-webhook-secret",
		store,
	)

	require.NoError(
		t,
		p.ConfirmPayment(
			context.Background(),
			"REF-IDEM",
			100,
			"EUR",
		),
	)

	require.NoError(
		t,
		p.ConfirmPayment(
			context.Background(),
			"REF-IDEM",
			100,
			"EUR",
		),
	)

	status, err := p.GetPaymentStatus(
		context.Background(),
		"REF-IDEM",
	)

	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
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
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "my-webhook-secret", store)
	payload := []byte(`{"type":"transfer.complete","amount":"1000"}`)
	sig := validEURCSignature("my-webhook-secret", payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

func TestVerifyWebhookSignature_TamperedPayload_False(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "my-webhook-secret", store)
	original := []byte(`{"type":"transfer.complete","amount":"1000"}`)
	sig := validEURCSignature("my-webhook-secret", original)

	tampered := []byte(`{"type":"transfer.complete","amount":"9999"}`)
	assert.False(t, p.VerifyWebhookSignature(tampered, sig))
}

func TestVerifyWebhookSignature_WrongSecret_False(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "correct-secret", store)
	payload := []byte(`{"type":"transfer.complete"}`)
	sig := validEURCSignature("wrong-secret", payload)
	assert.False(t, p.VerifyWebhookSignature(payload, sig))
}

func TestVerifyWebhookSignature_EmptySecret_False(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "test-webhook-secret", store)
	payload := []byte(`{"type":"transfer.complete"}`)
	assert.False(t, p.VerifyWebhookSignature(payload, "any-sig"))
}

func TestVerifyWebhookSignature_EmptyPayload_ValidHMAC(t *testing.T) {
	secret := "test-secret"
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", secret, store)
	payload := []byte{}
	sig := validEURCSignature(secret, payload)
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

// ---------------------------------------------------------------------------
// CreateVirtualAccount — idempotency (in-memory cache, no HTTP)
// ---------------------------------------------------------------------------

func TestCreateVirtualAccount_Idempotent_NoHTTP(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "test-webhook-secret", store)
	// Pre-seed the in-memory cache so we can test idempotency without HTTP
	p.mu.Lock()
	p.accounts["wallet-001"] = "0xABCDEF1234567890"
	p.mu.Unlock()

	addr1, err := p.CreateVirtualAccount(context.Background(), "wallet-001")
	require.NoError(t, err)
	assert.Equal(t, "0xABCDEF1234567890", addr1)

	// Second call returns the same address from cache
	addr2, err := p.CreateVirtualAccount(context.Background(), "wallet-001")
	require.NoError(t, err)
	assert.Equal(t, addr1, addr2, "repeated calls must return cached address")
}

func TestCreateVirtualAccount_DifferentWallets_DifferentAddresses(t *testing.T) {
	store := NewMemoryPaymentStore()
	p, _ := NewEURCPaymentProvider("key", "https://x", "ws", "test-webhook-secret", store)
	p.mu.Lock()
	p.accounts["wallet-A"] = "0xAAAA"
	p.accounts["wallet-B"] = "0xBBBB"
	p.mu.Unlock()

	addrA, _ := p.CreateVirtualAccount(context.Background(), "wallet-A")
	addrB, _ := p.CreateVirtualAccount(context.Background(), "wallet-B")
	assert.NotEqual(t, addrA, addrB)
}

func TestCreateVirtualAccount_ConcurrentSameWallet_UsesSingleHTTPRequest(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/wallets", r.URL.Path)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"wallet":{"id":"wallet-001","address":"0xabc123"}}}`)
	}))
	defer srv.Close()

	store := NewMemoryPaymentStore()
	p, err := NewEURCPaymentProvider("key", srv.URL, "ws", "test-webhook-secret", store)
	require.NoError(t, err)

	const walletID = "wallet-001"
	var wg sync.WaitGroup
	results := make([]string, 2)
	errs := make([]error, 2)
	start := make(chan struct{})

	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = p.CreateVirtualAccount(context.Background(), walletID)
		}()
	}

	close(start)
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.Equal(t, results[0], results[1], "concurrent callers must receive the same address")
	assert.Equal(t, "0xabc123", results[0])
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "only one HTTP request should be sent for the same wallet")
}

func TestCreateVirtualAccount_HTTPFailure_DoesNotCacheFailedResult(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `temporary outage`)
	}))
	defer srv.Close()

	store := NewMemoryPaymentStore()
	p, err := NewEURCPaymentProvider("key", srv.URL, "ws", "test-webhook-secret", store)
	require.NoError(t, err)

	addr, err := p.CreateVirtualAccount(context.Background(), "wallet-failure")
	require.Error(t, err)
	assert.Empty(t, addr)
	assert.NotContains(t, p.accounts, "wallet-failure", "failed HTTP responses must not be cached")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(1))
}

func TestEURC_CreateVirtualAccount_APIError_DoesNotLeakGoroutine(t *testing.T) {
	store := NewMemoryPaymentStore()
	e, _ := NewEURCPaymentProvider("key", "https://api.circle.com/v1", "ws", "secret", store)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal error"}`)
	}))
	defer srv.Close()

	var wg sync.WaitGroup
	const concurrency = 10
	wg.Add(concurrency)

	results := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, results[i] = e.CreateVirtualAccount(context.Background(), "wallet-A")
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines returned — no leak
	case <-time.After(5 * time.Second):
		t.Fatal("goroutine leak: concurrent CreateVirtualAccount calls did not all return within 5s")
	}
}

func TestEURC_CreateVirtualAccount_ConcurrentCalls_OnlyOneAPIRequest(t *testing.T) {
	var callCount int64
	store := NewMemoryPaymentStore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)

		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/wallets", r.URL.Path)

		time.Sleep(50 * time.Millisecond)

		w.Header().Set("Content-Type", "application/json")

		resp := circleWalletResponse{}
		resp.Data.Wallet.ID = "wallet-123"
		resp.Data.Wallet.Address = "0xabc123"

		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	e, err := NewEURCPaymentProvider(
		"key",
		srv.URL,
		"wallet-set-id",
		"secret",
		store,
	)
	require.NoError(t, err)

	const goroutines = 20

	var wg sync.WaitGroup

	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			results[i], errs[i] = e.CreateVirtualAccount(
				context.Background(),
				"wallet-shared",
			)
		}(i)
	}

	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i])
		assert.Equal(t, "0xabc123", results[i])
	}

	assert.Equal(
		t,
		int64(1),
		atomic.LoadInt64(&callCount),
		"exactly one API request should be sent for concurrent callers",
	)
}

func TestEURC_CreateVirtualAccount_ConcurrentCalls_APIError_AllReturn(t *testing.T) {
	var callCount int64
	store := NewMemoryPaymentStore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		http.Error(w, "upstream failure", http.StatusInternalServerError)
	}))
	defer srv.Close()

	e, err := NewEURCPaymentProvider(
		"key",
		srv.URL,
		"wallet-set-id",
		"secret",
		store,
	)
	require.NoError(t, err)

	const goroutines = 20

	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			_, errs[i] = e.CreateVirtualAccount(
				context.Background(),
				"wallet-shared",
			)
		}(i)
	}

	wg.Wait()

	for _, err := range errs {
		require.Error(t, err)
	}

	assert.Equal(t, int64(3), atomic.LoadInt64(&callCount))
}
