package gonetwork

// ---------------------------------------------------------------------------
// nca_reporting_wiring_test.go
//
// Item 14 acceptance tests — NCAReportingService wired into SealBlock.
//
// Covers:
//   A. Dev/test mode: bc.ReportingService is DefaultReportingService (not NCA).
//   B. NCAReportingService replaces DefaultReportingService when injected.
//   C. GenerateMiFIRReport routes through bc.ReportingService (NCA path).
//   D. Failed NCA submission writes report to BBolt reporting_outbox.
//   E. Retry goroutine eventually submits the outbox report and clears it.
//   F. BlockStore outbox CRUD unit tests.
//   G. NCAReportingService.SubmitReport exported helper.
//   H. GenerateAIFMDReport routes through bc.ReportingService (NCA path).
//   I. Nil ReportingService falls back to DefaultReportingService (robustness).
//   J. NewNCAReportingService reads env vars (regression guard).
// ---------------------------------------------------------------------------

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// devBlockchain creates a NewBlockchain in dev/test mode (no P2P, no production
// guard). The returned bc has DefaultReportingService set.
func devBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	t.Setenv("GONETWORK_NO_P2P", "1")
	bc := NewBlockchain(context.Background(), t.Name())
	t.Cleanup(func() {
		if bc.BlockStore != nil {
			bc.BlockStore.Close()
		}
	})
	return bc
}

// devBlockchainWithDB is like devBlockchain but also opens a real BBolt database.
func devBlockchainWithDB(t *testing.T) *Blockchain {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	t.Setenv("GREENHOUSE_DB_PATH", dbPath)
	return devBlockchain(t)
}

// injectNCAService wires a fresh NCAReportingService (pointing at ncaURL) into
// bc and, if bc.BlockStore is set, also wires the outbox so failed submissions
// are persisted. This mirrors what NewBlockchain does in production mode without
// needing GH_ENV=production (which triggers a log.Fatal when mock services are
// present, as production deployments require real providers).
func injectNCAService(t *testing.T, bc *Blockchain, ncaURL string, httpClient *http.Client) *NCAReportingService {
	t.Helper()
	ncaSvc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   ncaURL,
		httpClient: httpClient,
	}
	if bc.BlockStore != nil {
		ncaSvc.outbox = bc.BlockStore.SaveToReportingOutbox
	}
	bc.ReportingService = ncaSvc
	return ncaSvc
}

// issueEquityAsset registers a minimal equity asset on bc.
func issueEquityAsset(t *testing.T, bc *Blockchain, assetID string) {
	t.Helper()
	bc.Assets[assetID] = &Asset{
		ID:                assetID,
		AssetType:         AssetTypeEquity,
		Currency:          "EUR",
		Issuer:            "issuer-key",
		CirculatingSupply: 0,
		Metadata:          AssetMetadata{ISIN: "GB0001234567"},
	}
}

// ---------------------------------------------------------------------------
// A. Dev/test mode — DefaultReportingService
// ---------------------------------------------------------------------------

func TestItem14_DevMode_UsesDefaultReportingService(t *testing.T) {
	bc := devBlockchain(t)
	_, isDefault := bc.ReportingService.(*DefaultReportingService)
	assert.True(t, isDefault, "dev mode should use DefaultReportingService")
}

// ---------------------------------------------------------------------------
// B. NCAReportingService replaces DefaultReportingService when injected
// ---------------------------------------------------------------------------

func TestItem14_InjectedNCAService_ReplacesDefault(t *testing.T) {
	bc := devBlockchain(t)

	_, wasDefault := bc.ReportingService.(*DefaultReportingService)
	require.True(t, wasDefault, "pre-condition: should start as DefaultReportingService")

	ncaSvc := injectNCAService(t, bc, "https://nca.example.com/api", &http.Client{})

	_, isNCA := bc.ReportingService.(*NCAReportingService)
	assert.True(t, isNCA, "after injection should be NCAReportingService")
	assert.Equal(t, "https://nca.example.com/api", ncaSvc.endpoint)
}

// ---------------------------------------------------------------------------
// C. GenerateMiFIRReport routes through bc.ReportingService (NCA path)
// ---------------------------------------------------------------------------

func TestItem14_GenerateMiFIRReport_RoutedThroughNCAService(t *testing.T) {
	var submitted int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&submitted, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bc := devBlockchain(t)
	injectNCAService(t, bc, srv.URL, srv.Client())
	issueEquityAsset(t, bc, "equity-wire")

	trade := Trade{
		ID: "trade-wire-001", AssetID: "equity-wire",
		BuyerID: "buyer-key", SellerID: "seller-key",
		Quantity: 10, Price: 100, Currency: "EUR",
		ExecutedAt: time.Now().Unix(),
	}

	GenerateMiFIRReport(bc, trade, 1)

	require.Len(t, bc.RegulatoryReports, 1)
	assert.Equal(t, ReportTypeMiFIR, bc.RegulatoryReports[0].ReportType)
	assert.Equal(t, "equity-wire", bc.RegulatoryReports[0].AssetID)
	// The NCA HTTP endpoint should have been called exactly once.
	assert.EqualValues(t, 1, atomic.LoadInt32(&submitted))
}

// ---------------------------------------------------------------------------
// H. GenerateAIFMDReport routes through bc.ReportingService (NCA path)
// ---------------------------------------------------------------------------

func TestItem14_GenerateAIFMDReport_RoutedThroughNCAService(t *testing.T) {
	var submitted int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&submitted, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bc := devBlockchain(t)
	injectNCAService(t, bc, srv.URL, srv.Client())
	bc.Assets["fund-wire"] = &Asset{
		ID: "fund-wire", AssetType: AssetTypeFundUnit, Currency: "EUR",
	}

	trade := Trade{
		ID: "trade-fund-001", AssetID: "fund-wire",
		BuyerID: "buyer-key", SellerID: "seller-key",
		Quantity: 5, Price: 200, Currency: "EUR",
		ExecutedAt: time.Now().Unix(),
	}

	GenerateAIFMDReport(bc, trade, 2)

	require.Len(t, bc.RegulatoryReports, 1)
	assert.Equal(t, ReportTypeAIFMD, bc.RegulatoryReports[0].ReportType)
	assert.EqualValues(t, 1, atomic.LoadInt32(&submitted))
}

// ---------------------------------------------------------------------------
// D. Failed NCA submission writes report to BBolt reporting_outbox
// ---------------------------------------------------------------------------

func TestItem14_FailedSubmission_WritesToOutbox(t *testing.T) {
	// NCA endpoint returns 503 so every submission fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	bc := devBlockchainWithDB(t)
	injectNCAService(t, bc, srv.URL, srv.Client())
	issueEquityAsset(t, bc, "equity-outbox")

	trade := Trade{
		ID: "trade-outbox-001", AssetID: "equity-outbox",
		BuyerID: "b", SellerID: "s",
		Quantity: 1, Price: 50, Currency: "EUR",
		ExecutedAt: time.Now().Unix(),
	}

	GenerateMiFIRReport(bc, trade, 1)

	// Report still lands in bc.RegulatoryReports (on-chain storage succeeds).
	require.Len(t, bc.RegulatoryReports, 1)

	// The failed submission should have been written to the outbox.
	require.NotNil(t, bc.BlockStore)
	outbox, err := bc.BlockStore.LoadReportingOutbox()
	require.NoError(t, err)
	require.Len(t, outbox, 1, "failed report should be in outbox")
	assert.Equal(t, bc.RegulatoryReports[0].ID, outbox[0].ID)
}

// ---------------------------------------------------------------------------
// E. Retry goroutine submits outbox reports and removes them on success
// ---------------------------------------------------------------------------

func TestItem14_RetryGoroutine_ClearsOutboxOnSuccess(t *testing.T) {
	// Phase 1: NCA returns 503 → first attempt fails and goes to outbox.
	// Phase 2: NCA returns 200 → the retry goroutine succeeds.
	var failCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&failCount) < 1 {
			atomic.AddInt32(&failCount, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bc := devBlockchainWithDB(t)
	ncaSvc := injectNCAService(t, bc, srv.URL, srv.Client())
	issueEquityAsset(t, bc, "equity-retry")

	// Start the retry goroutine now that BlockStore and NCA service are wired.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go bc.runReportingOutboxRetry(ctx, ncaSvc)

	trade := Trade{
		ID: "trade-retry-001", AssetID: "equity-retry",
		BuyerID: "b", SellerID: "s",
		Quantity: 3, Price: 75, Currency: "EUR",
		ExecutedAt: time.Now().Unix(),
	}

	GenerateMiFIRReport(bc, trade, 1)

	// Report must be in the outbox after the first (failing) attempt.
	require.NotNil(t, bc.BlockStore)
	outbox, err := bc.BlockStore.LoadReportingOutbox()
	require.NoError(t, err)
	require.Len(t, outbox, 1, "report should be in outbox after failed submission")

	// Wait for the retry goroutine to drain the outbox (polls every 100 ms).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		remaining, _ := bc.BlockStore.LoadReportingOutbox()
		if len(remaining) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	remaining, err := bc.BlockStore.LoadReportingOutbox()
	require.NoError(t, err)
	assert.Empty(t, remaining, "retry goroutine should have cleared the outbox")
}

// ---------------------------------------------------------------------------
// F. BlockStore outbox CRUD — unit tests
// ---------------------------------------------------------------------------

func TestItem14_BlockStore_SaveLoadDeleteOutbox(t *testing.T) {
	store, err := OpenBlockStore(filepath.Join(t.TempDir(), "outbox.db"))
	require.NoError(t, err)
	defer store.Close()

	report := &RegulatoryReport{
		ID:         "rpt-001",
		ReportType: ReportTypeMiFIR,
		TradeID:    "trade-001",
		AssetID:    "asset-001",
	}

	// Save
	require.NoError(t, store.SaveToReportingOutbox(report))

	// Load
	items, err := store.LoadReportingOutbox()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "rpt-001", items[0].ID)

	// Delete
	require.NoError(t, store.DeleteFromReportingOutbox("rpt-001"))

	// Confirm empty
	items, err = store.LoadReportingOutbox()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestItem14_BlockStore_LoadOutbox_EmptyOnNewDB(t *testing.T) {
	store, err := OpenBlockStore(filepath.Join(t.TempDir(), "empty.db"))
	require.NoError(t, err)
	defer store.Close()

	items, err := store.LoadReportingOutbox()
	require.NoError(t, err)
	assert.Empty(t, items)
}

// ---------------------------------------------------------------------------
// G. NCAReportingService.SubmitReport — exported helper
// ---------------------------------------------------------------------------

func TestItem14_NCAReportingService_SubmitReport_StubMode(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "")
	svc := NewNCAReportingService()

	// Stub mode (no endpoint): SubmitReport must be a no-op.
	report := &RegulatoryReport{ID: "stub-001", ReportType: ReportTypeMiFIR}
	assert.NoError(t, svc.SubmitReport(report))
}

func TestItem14_NCAReportingService_SubmitReport_LiveEndpoint(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := &NCAReportingService{
		inner:      &DefaultReportingService{},
		endpoint:   srv.URL,
		httpClient: srv.Client(),
	}
	report := &RegulatoryReport{ID: "live-001", ReportType: ReportTypeMiFIR}
	require.NoError(t, svc.SubmitReport(report))
	assert.EqualValues(t, 1, atomic.LoadInt32(&received))
}

// ---------------------------------------------------------------------------
// I. Nil ReportingService falls back to DefaultReportingService (robustness)
// ---------------------------------------------------------------------------

func TestItem14_NilReportingService_FallsBackToDefault(t *testing.T) {
	bc := devBlockchain(t)
	// Explicitly nil out the service to test the nil guard in GenerateMiFIRReport.
	bc.ReportingService = nil
	issueEquityAsset(t, bc, "equity-nil")

	trade := Trade{
		ID: "trade-nil-001", AssetID: "equity-nil",
		BuyerID: "b", SellerID: "s",
		Quantity: 1, Price: 10, Currency: "EUR",
		ExecutedAt: time.Now().Unix(),
	}

	// Must not panic; report is generated via DefaultReportingService fallback.
	require.NotPanics(t, func() { GenerateMiFIRReport(bc, trade, 0) })
	require.Len(t, bc.RegulatoryReports, 1)
}

// ---------------------------------------------------------------------------
// J. NewNCAReportingService reads env vars (regression guard)
// ---------------------------------------------------------------------------

func TestItem14_NewNCAReportingService_ReadsEnvVars(t *testing.T) {
	t.Setenv("GREENHOUSE_NCA_REPORTING_ENDPOINT", "https://arm.example.com")
	t.Setenv("GREENHOUSE_ARM_API_KEY", "secret-key-xyz")
	svc := NewNCAReportingService()
	assert.Equal(t, "https://arm.example.com", svc.endpoint)
	assert.Equal(t, "secret-key-xyz", svc.apiKey)
}
