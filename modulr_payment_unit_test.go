package gonetwork

// ---------------------------------------------------------------------------
// modulr_payment_unit_test.go
//
// Unit tests for ModulrPaymentProvider — no real network calls.
// All HTTP calls are intercepted by httptest.NewServer.
// ---------------------------------------------------------------------------

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewModulrPaymentProvider_Valid(t *testing.T) {
	p, err := NewModulrPaymentProvider("key", "secret", "https://example.com", "CUST1", "PROD1")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "key", p.apiKey)
	assert.Equal(t, "CUST1", p.customerID)
}

func TestNewModulrPaymentProvider_DefaultBaseURL(t *testing.T) {
	p, err := NewModulrPaymentProvider("key", "secret", "", "", "")
	require.NoError(t, err)
	assert.Equal(t, modulrSandboxBaseURL, p.baseURL)
}

func TestNewModulrPaymentProvider_MissingAPIKey_Error(t *testing.T) {
	_, err := NewModulrPaymentProvider("", "secret", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiKey")
}

func TestNewModulrPaymentProvider_MissingAPISecret_Error(t *testing.T) {
	_, err := NewModulrPaymentProvider("key", "", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiSecret")
}

func TestNewModulrPaymentProviderFromEnv_MissingCreds_Error(t *testing.T) {
	t.Setenv("MODULR_API_KEY", "")
	t.Setenv("MODULR_API_SECRET", "")
	_, err := NewModulrPaymentProviderFromEnv()
	require.Error(t, err)
}

func TestNewModulrPaymentProviderFromEnv_Valid(t *testing.T) {
	t.Setenv("MODULR_API_KEY", "mykey")
	t.Setenv("MODULR_API_SECRET", "mysecret")
	t.Setenv("MODULR_BASE_URL", "https://api.test")
	t.Setenv("MODULR_CUSTOMER_ID", "C1")
	t.Setenv("MODULR_PRODUCT_CODE", "P1")
	p, err := NewModulrPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "C1", p.customerID)
	assert.Equal(t, "P1", p.productCode)
	assert.Equal(t, "https://api.test", p.baseURL)
}

func TestNewModulrPaymentProviderFromEnv_DefaultBaseURL(t *testing.T) {
	t.Setenv("MODULR_API_KEY", "k")
	t.Setenv("MODULR_API_SECRET", "s")
	t.Setenv("MODULR_BASE_URL", "")
	p, err := NewModulrPaymentProviderFromEnv()
	require.NoError(t, err)
	assert.Equal(t, modulrSandboxBaseURL, p.baseURL)
}

// ---------------------------------------------------------------------------
// addAuthHeaders
// ---------------------------------------------------------------------------

func TestModulrAddAuthHeaders_SetsRequiredHeaders(t *testing.T) {
	p, _ := NewModulrPaymentProvider("mykey", "mysecret", "https://x", "", "")
	req, _ := http.NewRequest(http.MethodGet, "https://x/test", nil)
	require.NoError(t, p.addAuthHeaders(req))

	assert.NotEmpty(t, req.Header.Get("Date"))
	assert.NotEmpty(t, req.Header.Get("x-mod-nonce"))
	authz := req.Header.Get("Authorization")
	assert.Contains(t, authz, "Signature")
	assert.Contains(t, authz, `keyId="mykey"`)
	assert.Contains(t, authz, "hmac-sha1")
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
}

// ---------------------------------------------------------------------------
// CreateVirtualAccount
// ---------------------------------------------------------------------------

func TestModulrCreateVirtualAccount_NoCustomerID_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "", "PROD1")
	ctx := context.Background()
	_, err := p.CreateVirtualAccount(ctx, "wallet-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "customerID")
}

func TestModulrCreateVirtualAccount_NoProductCode_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "CUST1", "")
	ctx := context.Background()
	_, err := p.CreateVirtualAccount(ctx, "wallet-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "productCode")
}

func TestModulrCreateVirtualAccount_IBAN_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/accounts"))
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(modulrAccountResponse{
			ID: "ACC1",
			Identifiers: []modulrAccountIdentifier{
				{Type: "IBAN", IBAN: "GB29NWBK60161331926819"},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	ctx := context.Background()
	iban, err := p.CreateVirtualAccount(ctx, "wallet-1")
	require.NoError(t, err)
	assert.Equal(t, "GB29NWBK60161331926819", iban)
}

func TestModulrCreateVirtualAccount_SortCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrAccountResponse{
			ID: "ACC2",
			Identifiers: []modulrAccountIdentifier{
				{Type: "SCAN", SortCode: "040075", AccountNumber: "12345678"},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	ctx := context.Background()
	ref, err := p.CreateVirtualAccount(ctx, "wallet-2")
	require.NoError(t, err)
	assert.Equal(t, "040075/12345678", ref)
}

func TestModulrCreateVirtualAccount_Non201_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	ctx := context.Background()
	_, err := p.CreateVirtualAccount(ctx, "wallet-3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestModulrCreateVirtualAccount_NoIdentifiers_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(modulrAccountResponse{ID: "ACC3"})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	ctx := context.Background()
	_, err := p.CreateVirtualAccount(ctx, "wallet-4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IBAN or sort code")
}

func TestModulrCreateVirtualAccount_RetriesOn503(t *testing.T) {
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++

		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporary"}`))
	}))
	defer srv.Close()

	p, err := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	require.NoError(t, err)

	ctx := context.Background()

	_, err = p.CreateVirtualAccount(ctx, "wallet-retry-503")

	require.Error(t, err)
	require.Equal(t, 3, attempts, "should retry 3 times on 503")
}

func TestModulrCreateVirtualAccount_DoesNotRetryOn400(t *testing.T) {
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++

		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	}))
	defer srv.Close()

	p, err := NewModulrPaymentProvider("k", "s", srv.URL, "CUST1", "PROD1")
	require.NoError(t, err)

	ctx := context.Background()

	_, err = p.CreateVirtualAccount(ctx, "wallet-no-retry-400")

	require.Error(t, err)
	require.Equal(t, 1, attempts, "400 must not be retried")
}

// ---------------------------------------------------------------------------
// CreateEURVirtualAccount
// ---------------------------------------------------------------------------

func TestModulrCreateEURVirtualAccount_NoCustomerID_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "", "P1")
	ctx := context.Background()
	_, err := p.CreateEURVirtualAccount(ctx, "w")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "customerID")
}

func TestModulrCreateEURVirtualAccount_NoProductCode_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "C1", "")
	ctx := context.Background()
	_, err := p.CreateEURVirtualAccount(ctx, "w")
	require.Error(t, err)
}

func TestModulrCreateEURVirtualAccount_IBAN_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req modulrAccountRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "EUR", req.Currency)
		assert.True(t, strings.HasSuffix(req.Name, "-EUR"))

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(modulrAccountResponse{
			ID: "EACC1",
			Identifiers: []modulrAccountIdentifier{
				{Type: "IBAN", IBAN: "DE89370400440532013000"},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "C1", "P1")
	ctx := context.Background()
	iban, err := p.CreateEURVirtualAccount(ctx, "eur-wallet")
	require.NoError(t, err)
	assert.Equal(t, "DE89370400440532013000", iban)
}

func TestModulrCreateEURVirtualAccount_NoIBAN_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(modulrAccountResponse{ID: "EACC2"})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "C1", "P1")
	ctx := context.Background()
	_, err := p.CreateEURVirtualAccount(ctx, "w2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IBAN")
}

func TestModulrCreateEURVirtualAccount_Non201_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "C1", "P1")
	ctx := context.Background()
	_, err := p.CreateEURVirtualAccount(ctx, "w3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// ---------------------------------------------------------------------------
// GetPaymentStatus
// ---------------------------------------------------------------------------

func TestModulrGetPaymentStatus_Processed_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.RawQuery, "externalReference")
		assert.Contains(t, r.URL.RawQuery, "PAYIN")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{
			Content: []modulrPaymentRecord{{ID: "P1", Status: "PROCESSED"}},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-001")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestModulrGetPaymentStatus_Settled_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{
			Content: []modulrPaymentRecord{{Status: "SETTLED"}},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-002")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusConfirmed, status)
}

func TestModulrGetPaymentStatus_NotFound_Pending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-003")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusPending, status)
}

func TestModulrGetPaymentStatus_Failed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{
			Content: []modulrPaymentRecord{{Status: "FAILED"}},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-004")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusFailed, status)
}

func TestModulrGetPaymentStatus_Rejected_Failed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{
			Content: []modulrPaymentRecord{{Status: "REJECTED"}},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-005")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusFailed, status)
}

func TestModulrGetPaymentStatus_Expired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(modulrPaymentsResponse{
			Content: []modulrPaymentRecord{{Status: "EXPIRED"}},
		})
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	status, err := p.GetPaymentStatus(ctx, "ref-006")
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusExpired, status)
}

func TestModulrGetPaymentStatus_Non200_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "", "")
	ctx := context.Background()
	_, err := p.GetPaymentStatus(ctx, "ref-007")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ---------------------------------------------------------------------------
// ConfirmPayment — always returns error (webhook-only path)
// ---------------------------------------------------------------------------

func TestModulrConfirmPayment_AlwaysError(t *testing.T) {
	ctx := context.Background()
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "", "")
	err := p.ConfirmPayment(ctx, "ref", 100.0, "GBP")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook")
}

// ---------------------------------------------------------------------------
// VerifyWebhookSignature
// ---------------------------------------------------------------------------

func modulrTestHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestModulrVerifyWebhookSignature_Valid(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "mysecret", "https://x", "", "")
	payload := []byte(`{"event":"payment.received","id":"P1"}`)
	sig := modulrTestHMAC(payload, "mysecret")
	assert.True(t, p.VerifyWebhookSignature(payload, sig))
}

func TestModulrVerifyWebhookSignature_TamperedPayload_False(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "mysecret", "https://x", "", "")
	payload := []byte(`{"event":"payment.received","id":"P1"}`)
	sig := modulrTestHMAC(payload, "mysecret")
	tampered := []byte(`{"event":"payment.received","id":"P99"}`)
	assert.False(t, p.VerifyWebhookSignature(tampered, sig))
}

func TestModulrVerifyWebhookSignature_WrongSecret_False(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "mysecret", "https://x", "", "")
	payload := []byte(`{"event":"test"}`)
	sig := modulrTestHMAC(payload, "wrong-secret")
	assert.False(t, p.VerifyWebhookSignature(payload, sig))
}

func TestModulrVerifyWebhookSignature_EmptySignature_False(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "mysecret", "https://x", "", "")
	assert.False(t, p.VerifyWebhookSignature([]byte("data"), ""))
}

// ---------------------------------------------------------------------------
// modulrStatusToPaymentStatus — exhaustive mapping
// ---------------------------------------------------------------------------

func TestModulrStatusToPaymentStatus_AllCases(t *testing.T) {
	cases := []struct {
		input    string
		expected PaymentStatus
	}{
		{"PROCESSED", PaymentStatusConfirmed},
		{"SETTLED", PaymentStatusConfirmed},
		{"FAILED", PaymentStatusFailed},
		{"REJECTED", PaymentStatusFailed},
		{"EXPIRED", PaymentStatusExpired},
		{"PENDING", PaymentStatusPending},
		{"SUBMITTED", PaymentStatusPending},
		{"UNKNOWN", PaymentStatusPending},
		{"", PaymentStatusPending},
	}
	for _, tc := range cases {
		t.Run("status_"+tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, modulrStatusToPaymentStatus(tc.input))
		})
	}
}

// Tests that context cancellation during backoff aborts retries and returns context.Canceled
func TestRetryHTTP_ContextCancellation_DuringBackoff_ReturnsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := retryHTTP(ctx, retryConfig{maxAttempts: 5, safeToRetry: true}, func(ctx context.Context) (*http.Response, error) {
		attempts++
		return nil, errors.New("temporary failure")
	})

	require.ErrorIs(t, err, context.Canceled)
	require.LessOrEqual(t, attempts, 3)
}

// Tests that a plain error on the final attempt is returned directly, not wrapped or swallowed
func TestRetryHTTP_NonRetryableError_ReturnedDirectly(t *testing.T) {
	ctx := context.Background()

	attempts := 0

	_, err := retryHTTP(ctx, retryConfig{maxAttempts: 1, safeToRetry: true}, func(ctx context.Context) (*http.Response, error) {
		attempts++
		return nil, errors.New("temporary failure")
	})

	require.EqualError(t, err, "temporary failure")
	require.Equal(t, attempts, 1)
}

func TestRetryHTTP_PreCancelled_NoExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attempts := 0

	_, err := retryHTTP(ctx, retryConfig{maxAttempts: 3, safeToRetry: true}, func(ctx context.Context) (*http.Response, error) {
		attempts++
		return nil, errors.New("should not run")
	})

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, attempts)
}

func TestRetryHTTP_POST_NetworkError_NotRetried(t *testing.T) {
	attempts := 0

	_, err := retryHTTPWithConfig(
		context.Background(),
		retryConfig{maxAttempts: 3, safeToRetry: false},
		func(ctx context.Context) (*http.Response, error) {
			attempts++
			return nil, errors.New("connection reset")
		},
	)

	require.Error(t, err)
	require.Equal(t, 1, attempts, "non-idempotent request must not retry on network error")
}

func TestRetryHTTP_POST_WithIdempotencyKey_IsRetried(t *testing.T) {
	attempts := 0

	resp, err := retryHTTPWithConfig(
		context.Background(),
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {
			attempts++

			if attempts < 3 {
				return nil, errors.New("network error")
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 3, attempts)
}

func TestRetryHTTP_GET_IsRetried(t *testing.T) {
	attempts := 0

	resp, err := retryHTTPWithConfig(
		context.Background(),
		retryConfig{maxAttempts: 3, safeToRetry: true},
		func(ctx context.Context) (*http.Response, error) {
			attempts++

			if attempts < 2 {
				return nil, errors.New("transient error")
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 2, attempts)
}

func TestModulr_GetPaymentStatus_CancelledContext_NoHTTPCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false

	transport := &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("should not be called")
		},
	}

	client := &http.Client{Transport: transport}

	p := &ModulrPaymentProvider{
		client:  client,
		baseURL: "http://example",
	}

	_, err := p.GetPaymentStatusCtx(ctx, "ref")

	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
}

func TestRetryHTTP_CancelsDuringBackoff_NoFurtherAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0

	start := make(chan struct{})

	go func() {
		<-start
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := retryHTTP(ctx, retryConfig{maxAttempts: 3, safeToRetry: true}, func(ctx context.Context) (*http.Response, error) {
		if attempts == 0 {
			close(start) // start cancellation timer only once loop begins
		}

		attempts++

		// simulate real work so cancellation can actually intersect execution
		time.Sleep(20 * time.Millisecond)

		return nil, errors.New("fail")
	})

	require.ErrorIs(t, err, context.Canceled)
	require.LessOrEqual(t, attempts, 3)
}

func TestPaymentShutdown_CancelsInFlightRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	blocked := make(chan struct{})

	transport := &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			close(started)
			<-blocked // simulate long API call
			return nil, errors.New("should not reach")
		},
	}

	client := &http.Client{Transport: transport}

	p := &ModulrPaymentProvider{
		client:  client,
		baseURL: "http://example",
	}

	go func() {
		_, _ = p.GetPaymentStatusCtx(ctx, "ref")
	}()

	<-started
	cancel()

	done := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("shutdown did not complete in time")
	}

	close(blocked)
}

func TestWaitRetry_CancelledDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()

	err := waitRetry(ctx, 2*time.Second)

	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, elapsed, 200*time.Millisecond)
}
