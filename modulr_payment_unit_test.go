package gonetwork

// ---------------------------------------------------------------------------
// modulr_payment_unit_test.go
//
// Unit tests for ModulrPaymentProvider — no real network calls.
// All HTTP calls are intercepted by httptest.NewServer.
// ---------------------------------------------------------------------------

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	_, err := p.CreateVirtualAccount("wallet-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "customerID")
}

func TestModulrCreateVirtualAccount_NoProductCode_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "CUST1", "")
	_, err := p.CreateVirtualAccount("wallet-1")
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
	iban, err := p.CreateVirtualAccount("wallet-1")
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
	ref, err := p.CreateVirtualAccount("wallet-2")
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
	_, err := p.CreateVirtualAccount("wallet-3")
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
	_, err := p.CreateVirtualAccount("wallet-4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IBAN or sort code")
}

// ---------------------------------------------------------------------------
// CreateEURVirtualAccount
// ---------------------------------------------------------------------------

func TestModulrCreateEURVirtualAccount_NoCustomerID_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "", "P1")
	_, err := p.CreateEURVirtualAccount("w")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "customerID")
}

func TestModulrCreateEURVirtualAccount_NoProductCode_Error(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "C1", "")
	_, err := p.CreateEURVirtualAccount("w")
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
	iban, err := p.CreateEURVirtualAccount("eur-wallet")
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
	_, err := p.CreateEURVirtualAccount("w2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IBAN")
}

func TestModulrCreateEURVirtualAccount_Non201_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p, _ := NewModulrPaymentProvider("k", "s", srv.URL, "C1", "P1")
	_, err := p.CreateEURVirtualAccount("w3")
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
	status, err := p.GetPaymentStatus("ref-001")
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
	status, err := p.GetPaymentStatus("ref-002")
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
	status, err := p.GetPaymentStatus("ref-003")
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
	status, err := p.GetPaymentStatus("ref-004")
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
	status, err := p.GetPaymentStatus("ref-005")
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
	status, err := p.GetPaymentStatus("ref-006")
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
	_, err := p.GetPaymentStatus("ref-007")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ---------------------------------------------------------------------------
// ConfirmPayment — always returns error (webhook-only path)
// ---------------------------------------------------------------------------

func TestModulrConfirmPayment_AlwaysError(t *testing.T) {
	p, _ := NewModulrPaymentProvider("k", "s", "https://x", "", "")
	err := p.ConfirmPayment("ref", 100.0, "GBP")
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
