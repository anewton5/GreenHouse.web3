package gonetwork

// ---------------------------------------------------------------------------
// nca_reporting_test.go
//
// Tests for NCAReportingService — NCA/ARM HTTP report submission layer.
// Covers:
//   NewNCAReportingService — creates service correctly
//   GenerateReport (stub mode, no endpoint) — succeeds and returns report
//   GenerateReport with live endpoint (mock HTTP server) — success path
//   GenerateReport with live endpoint — server error is non-fatal
//   submitToNCA — 4xx returns error; missing API key omits header
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeMiFIRTrade builds a minimal Trade suitable for MiFIR/AIFMD report generation.
func makeMiFIRTrade(assetID, sellerID string) Trade {
	return Trade{
		ID:         generateID("TRD"),
		AssetID:    assetID,
		SellerID:   sellerID,
		BuyerID:    "buyer-pub",
		Quantity:   100,
		Price:      12.50,
		Currency:   "EUR",
		ExecutedAt: time.Now().Unix(),
	}
}

func makeMiFIRAsset(id string) *Asset {
	return &Asset{
		ID:        id,
		AssetType: AssetTypeEquity,
		Currency:  "EUR",
		Metadata: AssetMetadata{
			CompanyName: "Test Corp",
			ISIN:        "GB00B1YW4409",
		},
	}
}

// ---------------------------------------------------------------------------
// NewNCAReportingService
// ---------------------------------------------------------------------------

func TestNewNCAReportingService_CreatesService(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "")
	t.Setenv("GREENHOUSE_ARM_API_KEY", "")
	svc := NewNCAReportingService()
	require.NotNil(t, svc)
	require.NotNil(t, svc.inner)
	assert.Empty(t, svc.endpoint)
	assert.Empty(t, svc.apiKey)
}

func TestNewNCAReportingService_SetsEndpointFromEnv(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "https://nca.test/api")
	t.Setenv("GREENHOUSE_ARM_API_KEY", "bearer-token-xyz")
	svc := NewNCAReportingService()
	assert.Equal(t, "https://nca.test/api", svc.endpoint)
	assert.Equal(t, "bearer-token-xyz", svc.apiKey)
}

// ---------------------------------------------------------------------------
// GenerateReport — stub mode (no endpoint configured)
// ---------------------------------------------------------------------------

func TestNCAGenerateReport_StubMode_MiFIR(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "")
	svc := NewNCAReportingService()

	trade := makeMiFIRTrade("equity-A", "seller-pub")
	asset := makeMiFIRAsset("equity-A")

	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 1)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, ReportTypeMiFIR, report.ReportType)
	assert.Equal(t, "equity-A", report.AssetID)
}

func TestNCAGenerateReport_StubMode_AIFMD(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "")
	svc := NewNCAReportingService()

	trade := makeMiFIRTrade("fund-A", "manager-pub")
	asset := makeMiFIRAsset("fund-A")

	report, err := svc.GenerateReport(ReportTypeAIFMD, trade, asset, 5)
	require.NoError(t, err)
	assert.Equal(t, ReportTypeAIFMD, report.ReportType)
}

// ---------------------------------------------------------------------------
// GenerateReport — with live endpoint (HTTP mock server)
// ---------------------------------------------------------------------------

func TestNCAGenerateReport_WithEndpoint_SubmitsReport(t *testing.T) {
	submitted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/reports")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

		var report RegulatoryReport
		require.NoError(t, json.NewDecoder(r.Body).Decode(&report))
		assert.Equal(t, "equity-A", report.AssetID)

		submitted = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   srv.URL,
		apiKey:     "test-api-key",
		httpClient: srv.Client(),
	}

	trade := makeMiFIRTrade("equity-A", "seller")
	asset := makeMiFIRAsset("equity-A")
	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 1)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.True(t, submitted)
}

func TestNCAGenerateReport_EndpointServerError_NonFatal(t *testing.T) {
	// Submission failure must be non-fatal — report still returned
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	svc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   srv.URL,
		httpClient: srv.Client(),
	}

	trade := makeMiFIRTrade("equity-B", "seller")
	asset := makeMiFIRAsset("equity-B")
	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 2)
	// Must still succeed on-chain even though NCA submission failed
	require.NoError(t, err)
	require.NotNil(t, report)
}

func TestNCAGenerateReport_NoAPIKey_OmitsAuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   srv.URL,
		apiKey:     "", // no key
		httpClient: srv.Client(),
	}

	trade := makeMiFIRTrade("equity-C", "s")
	asset := makeMiFIRAsset("equity-C")
	_, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 3)
	require.NoError(t, err)
	assert.Empty(t, capturedAuth, "Authorization header should be absent when apiKey is empty")
}

func TestNCAGenerateReport_UnreachableEndpoint_NonFatal(t *testing.T) {
	svc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   "http://127.0.0.1:0", // unreachable
		httpClient: &http.Client{},
	}

	trade := makeMiFIRTrade("equity-D", "s")
	asset := makeMiFIRAsset("equity-D")
	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 4)
	// On-chain storage must succeed even if NCA endpoint unreachable
	require.NoError(t, err)
	require.NotNil(t, report)
}

// ---------------------------------------------------------------------------
// DefaultReportingService — inner used by NCA wrapper
// ---------------------------------------------------------------------------

func TestDefaultReportingService_GenerateReport_MiFIR(t *testing.T) {
	svc := &DefaultReportingService{}
	trade := makeMiFIRTrade("equity-E", "seller-pub")
	asset := makeMiFIRAsset("equity-E")
	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 10)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, ReportTypeMiFIR, report.ReportType)
	assert.NotEmpty(t, report.ID)
}

func TestDefaultReportingService_GenerateReport_AIFMD(t *testing.T) {
	svc := &DefaultReportingService{}
	trade := makeMiFIRTrade("fund-B", "mgr")
	asset := makeMiFIRAsset("fund-B")
	report, err := svc.GenerateReport(ReportTypeAIFMD, trade, asset, 20)
	require.NoError(t, err)
	assert.Equal(t, ReportTypeAIFMD, report.ReportType)
}
