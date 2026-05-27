package gonetwork

// ---------------------------------------------------------------------------
// third_party_aml_test.go — ComplyAdvantage and Elliptic screener unit tests
//
// All HTTP calls are intercepted by httptest.Server — no real network access.
//
// ComplyAdvantage covers:
//   NewComplyAdvantageScreener
//   ScreenTransaction → screenEntity → callAPI
//   Cache hit (second call skips HTTP)
//   Sanction match → AMLSeverityBlock
//   PEP match → AMLSeverityFlag
//   No hits → nil
//   HTTP error → error propagated
//   Receiver blocked when receiver is in sanctions list
//
// Elliptic covers:
//   NewEllipticScreener
//   ScreenTransaction → scoreWallet → callAPI
//   risk_score ≥ 8 → Block
//   risk_score ≥ 5 → Flag
//   risk_score < 5 → nil
//   Cache hit
//   HTTP error → error propagated
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// caResponse builds a minimal ComplyAdvantage /v2/searches response with one hit.
func caResponse(score float64, hitType string) []byte {
	resp := map[string]any{
		"content": map[string]any{
			"data": map[string]any{
				"hits": []any{
					map[string]any{
						"doc_score": score,
						"doc": map[string]any{
							"types": []string{hitType},
							"name":  "Test Entity",
						},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// caEmptyResponse returns a ComplyAdvantage response with no hits.
func caEmptyResponse() []byte {
	resp := map[string]any{
		"content": map[string]any{
			"data": map[string]any{
				"hits": []any{},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// ellipticResponse builds a minimal Elliptic /v2/wallet/synchronous response.
func ellipticResponse(riskScore float64, reason string) []byte {
	resp := map[string]any{
		"risk_score":  riskScore,
		"risk_reason": reason,
		"blockchain_info": map[string]any{
			"cluster": "test-cluster",
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — constructor
// ---------------------------------------------------------------------------

func TestComplyAdvantage_Constructor_StoresFields(t *testing.T) {
	s := NewComplyAdvantageScreener("test-key", "https://api.test.com")
	require.NotNil(t, s)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — sanction hit → Block
// ---------------------------------------------------------------------------

func TestComplyAdvantage_SanctionHit_BlocksSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/v2/searches")
		assert.Contains(t, r.Header.Get("Authorization"), "Token ")
		w.Header().Set("Content-Type", "application/json")
		w.Write(caResponse(0.95, "sanction"))
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("wallet-a", "wallet-b", "asset-1", 100, "EUR")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
	assert.Contains(t, alert.MatchedList, "CA-SANCTION")
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — PEP hit → Flag
// ---------------------------------------------------------------------------

func TestComplyAdvantage_PEPHit_FlagsSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(caResponse(0.95, "pep"))
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("wallet-pep", "wallet-clean", "asset-1", 100, "EUR")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityFlag, alert.Severity)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — warning hit → Flag
// ---------------------------------------------------------------------------

func TestComplyAdvantage_WarningHit_FlagsSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(caResponse(0.92, "warning"))
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("wallet-warn", "wallet-clean", "a", 10, "GBP")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityFlag, alert.Severity)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — no hits → nil
// ---------------------------------------------------------------------------

func TestComplyAdvantage_NoHits_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(caEmptyResponse())
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("clean-sender", "clean-receiver", "a", 10, "EUR")
	require.NoError(t, err)
	assert.Nil(t, alert)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — low score (< 0.9) → ignored → nil
// ---------------------------------------------------------------------------

func TestComplyAdvantage_LowScore_Ignored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(caResponse(0.5, "sanction")) // score too low
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("w1", "w2", "a", 10, "EUR")
	require.NoError(t, err)
	assert.Nil(t, alert)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — cache: second call skips HTTP
// ---------------------------------------------------------------------------

func TestComplyAdvantage_Cache_SecondCallSkipsHTTP(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(caEmptyResponse())
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)

	// First call — hits server for both sender and receiver (2 requests).
	_, err := s.ScreenTransaction("wallet-x", "wallet-y", "a", 10, "EUR")
	require.NoError(t, err)

	countAfterFirst := atomic.LoadInt32(&callCount)

	// Second call — both keys cached; no new HTTP requests.
	_, err = s.ScreenTransaction("wallet-x", "wallet-y", "a", 10, "EUR")
	require.NoError(t, err)

	countAfterSecond := atomic.LoadInt32(&callCount)
	assert.Equal(t, countAfterFirst, countAfterSecond, "second call must use cache only")
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — HTTP server error → error returned
// ---------------------------------------------------------------------------

func TestComplyAdvantage_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	_, err := s.ScreenTransaction("w1", "w2", "a", 10, "EUR")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ComplyAdvantage — receiver blocked (sender clean, receiver in sanctions)
// ---------------------------------------------------------------------------

func TestComplyAdvantage_ReceiverBlocked_ReturnsBlockAlert(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		// First call = sender (clean), second call = receiver (blocked).
		if callCount == 1 {
			w.Write(caEmptyResponse())
		} else {
			w.Write(caResponse(0.95, "sanction"))
		}
	}))
	defer srv.Close()

	s := NewComplyAdvantageScreener("key", srv.URL)
	alert, err := s.ScreenTransaction("clean-sender", "blocked-receiver", "a", 50, "EUR")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
}

// ---------------------------------------------------------------------------
// Elliptic — constructor
// ---------------------------------------------------------------------------

func TestElliptic_Constructor_StoresFields(t *testing.T) {
	s := NewEllipticScreener("key", "secret", "https://elliptic.test")
	require.NotNil(t, s)
}

// ---------------------------------------------------------------------------
// Elliptic — risk_score ≥ 8 → Block
// ---------------------------------------------------------------------------

func TestElliptic_HighRisk_Blocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("x-access-key"))
		assert.NotEmpty(t, r.Header.Get("x-access-secret"))
		w.Header().Set("Content-Type", "application/json")
		w.Write(ellipticResponse(9.5, "darknet market"))
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)
	alert, err := s.ScreenTransaction("risky-sender", "clean-receiver", "", 0, "")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
	assert.Contains(t, alert.MatchedList, "ELLIPTIC")
}

// ---------------------------------------------------------------------------
// Elliptic — 5 ≤ risk_score < 8 → Flag
// ---------------------------------------------------------------------------

func TestElliptic_MediumRisk_Flags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(ellipticResponse(6.0, "gambling"))
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)
	alert, err := s.ScreenTransaction("medium-sender", "clean-receiver", "", 0, "")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityFlag, alert.Severity)
}

// ---------------------------------------------------------------------------
// Elliptic — risk_score < 5 → nil (clean)
// ---------------------------------------------------------------------------

func TestElliptic_LowRisk_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(ellipticResponse(2.0, ""))
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)
	alert, err := s.ScreenTransaction("clean-s", "clean-r", "", 0, "")
	require.NoError(t, err)
	assert.Nil(t, alert)
}

// ---------------------------------------------------------------------------
// Elliptic — cache: second call skips HTTP
// ---------------------------------------------------------------------------

func TestElliptic_Cache_SecondCallSkipsHTTP(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(ellipticResponse(1.0, ""))
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)

	// First call — server hit twice (sender + receiver).
	_, err := s.ScreenTransaction("w-s", "w-r", "", 0, "")
	require.NoError(t, err)
	first := atomic.LoadInt32(&callCount)

	// Second call — cached.
	_, err = s.ScreenTransaction("w-s", "w-r", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, first, atomic.LoadInt32(&callCount))
}

// ---------------------------------------------------------------------------
// Elliptic — HTTP server error → error returned
// ---------------------------------------------------------------------------

func TestElliptic_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)
	_, err := s.ScreenTransaction("w1", "w2", "", 0, "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Elliptic — receiver blocked when score is high
// ---------------------------------------------------------------------------

func TestElliptic_ReceiverHighRisk_ReturnsBlockAlert(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			w.Write(ellipticResponse(1.0, "clean")) // sender clean
		} else {
			w.Write(ellipticResponse(9.0, "sanctions")) // receiver risky
		}
	}))
	defer srv.Close()

	s := NewEllipticScreener("key", "secret", srv.URL)
	alert, err := s.ScreenTransaction("clean-s", "risky-r", "", 0, "")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, AMLSeverityBlock, alert.Severity)
}
