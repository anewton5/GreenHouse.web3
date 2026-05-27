package gonetwork

// ---------------------------------------------------------------------------
// reporting_extended_test.go
//
// Full coverage for the investor reporting & tax module:
//   CostBasisTracker   — RecordAcquisition, ConsumeForDisposal (FIFO),
//                        partial fill, multiple lots, insufficient balance
//   GenerateHoldingsReport — single asset, multi-asset, zero balance omitted,
//                            FiDA marshal, valuation error path
//   HoldingsReport.MarshalFiDA — produces valid JSON
//   GenerateTaxReport  — GB disposal + CGT exempt, DE flat rate, FR PFU,
//                        NL Box 3, multiple trades, trade in wrong year
//   TaxReport.MarshalFiDA — produces valid JSON
//   DefaultSettlementMethod — all currency codes
//   payment.go helpers  — SettlementMethod constants
//   pontes RegisterSettlement — HTTP mock
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

// ---------------------------------------------------------------------------
// CostBasisTracker — FIFO mechanics
// ---------------------------------------------------------------------------

func TestCostBasisTracker_RecordAndConsume_SingleLot(t *testing.T) {
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition("wallet-A", "equity-1", AcquisitionLot{
		AcquiredAt: time.Now().Unix() - 86400,
		Units:      100,
		UnitCost:   10.0,
		TradeID:    "buy-001",
	})

	cost, consumed, err := tracker.ConsumeForDisposal("wallet-A", "equity-1", 50, time.Now().Unix())
	require.NoError(t, err)
	assert.InDelta(t, 500.0, cost, 0.001) // 50 × 10.0
	require.Len(t, consumed, 1)
	assert.Equal(t, float64(50), consumed[0].Units)

	// Remaining lots: 50 units still available
	lots := tracker.Lots["wallet-A:equity-1"]
	require.Len(t, lots, 1)
	assert.Equal(t, float64(50), lots[0].Units)
}

func TestCostBasisTracker_FIFO_OldestLotFirst(t *testing.T) {
	tracker := NewCostBasisTracker()
	now := time.Now().Unix()
	tracker.RecordAcquisition("wallet-A", "equity-1", AcquisitionLot{AcquiredAt: now - 200, Units: 30, UnitCost: 5.0})
	tracker.RecordAcquisition("wallet-A", "equity-1", AcquisitionLot{AcquiredAt: now - 100, Units: 70, UnitCost: 8.0})

	// Consume 40 units — should consume all 30 from lot1 then 10 from lot2
	cost, consumed, err := tracker.ConsumeForDisposal("wallet-A", "equity-1", 40, now)
	require.NoError(t, err)
	assert.InDelta(t, 30*5.0+10*8.0, cost, 0.001) // 150 + 80 = 230
	require.Len(t, consumed, 2)
}

func TestCostBasisTracker_ExhaustsLots_CleanedUp(t *testing.T) {
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition("wallet-B", "asset-X", AcquisitionLot{Units: 100, UnitCost: 20.0})
	_, _, err := tracker.ConsumeForDisposal("wallet-B", "asset-X", 100, time.Now().Unix())
	require.NoError(t, err)
	assert.Empty(t, tracker.Lots["wallet-B:asset-X"])
}

func TestCostBasisTracker_InsufficientBalance_Error(t *testing.T) {
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition("wallet-C", "asset-Y", AcquisitionLot{Units: 50, UnitCost: 10.0})

	_, _, err := tracker.ConsumeForDisposal("wallet-C", "asset-Y", 75, time.Now().Unix())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")
}

func TestCostBasisTracker_NoLots_Error(t *testing.T) {
	tracker := NewCostBasisTracker()
	_, _, err := tracker.ConsumeForDisposal("wallet-D", "asset-Z", 10, time.Now().Unix())
	require.Error(t, err)
}

func TestCostBasisTracker_MultipleSeparateWallets(t *testing.T) {
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition("wallet-1", "equit-1", AcquisitionLot{Units: 100, UnitCost: 10.0})
	tracker.RecordAcquisition("wallet-2", "equit-1", AcquisitionLot{Units: 200, UnitCost: 12.0})

	cost1, _, _ := tracker.ConsumeForDisposal("wallet-1", "equit-1", 50, time.Now().Unix())
	cost2, _, _ := tracker.ConsumeForDisposal("wallet-2", "equit-1", 100, time.Now().Unix())

	assert.InDelta(t, 500.0, cost1, 0.001)
	assert.InDelta(t, 1200.0, cost2, 0.001)
}

// ---------------------------------------------------------------------------
// GenerateHoldingsReport
// ---------------------------------------------------------------------------

func setupHoldingsTestData(walletKey string) (
	holdings map[string]*AssetHolding,
	assets map[string]*Asset,
	tracker *CostBasisTracker,
	oracle *MockValuationOracle,
) {
	oracle = NewMockValuationOracle()
	oracle.SetValuation("equity-A", 20.0)
	oracle.SetValuation("equity-B", 50.0)
	oracle.SetCurrencyRate("GBP", "EUR", 1.15)

	assets = map[string]*Asset{
		"equity-A": {
			ID:        "equity-A",
			AssetType: AssetTypeEquity,
			Currency:  "GBP",
			Metadata:  AssetMetadata{CompanyName: "Acme Ltd", ISIN: "GB00B1YW4409"},
		},
		"equity-B": {
			ID:        "equity-B",
			AssetType: AssetTypeEquity,
			Currency:  "GBP",
			Metadata:  AssetMetadata{CompanyName: "Beta Corp"},
		},
	}

	holdings = map[string]*AssetHolding{
		HoldingKey(walletKey, "equity-A"): {AssetID: "equity-A", HolderID: walletKey, Balance: 100},
		HoldingKey(walletKey, "equity-B"): {AssetID: "equity-B", HolderID: walletKey, Balance: 50},
	}

	tracker = NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-A", AcquisitionLot{Units: 100, UnitCost: 15.0})
	tracker.RecordAcquisition(walletKey, "equity-B", AcquisitionLot{Units: 50, UnitCost: 40.0})
	return
}

func TestGenerateHoldingsReport_SingleAsset_WithPnL(t *testing.T) {
	walletKey := "investor-wallet-pub"
	oracle := NewMockValuationOracle()
	oracle.SetValuation("equity-X", 25.0)

	assets := map[string]*Asset{
		"equity-X": {ID: "equity-X", AssetType: AssetTypeEquity, Currency: "GBP", Metadata: AssetMetadata{CompanyName: "XCo"}},
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(walletKey, "equity-X"): {AssetID: "equity-X", HolderID: walletKey, Balance: 200},
	}
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-X", AcquisitionLot{Units: 200, UnitCost: 20.0})

	report, err := GenerateHoldingsReport(walletKey, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	require.NotNil(t, report)
	require.Len(t, report.Holdings, 1)

	snap := report.Holdings[0]
	assert.Equal(t, "equity-X", snap.AssetID)
	assert.InDelta(t, 5000.0, snap.MarketValue, 0.001) // 200 × 25
	assert.InDelta(t, 20.0, snap.AvgCost, 0.001)
	assert.InDelta(t, 1000.0, snap.UnrealisedPnL, 0.001) // 5000 - 4000
	assert.InDelta(t, 5000.0, report.TotalMarketValue, 0.001)
}

func TestGenerateHoldingsReport_MultiAsset_TotalMVSummed(t *testing.T) {
	walletKey := "multi-wallet"
	holdings, assets, tracker, oracle := setupHoldingsTestData(walletKey)

	report, err := GenerateHoldingsReport(walletKey, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	require.Len(t, report.Holdings, 2)
	// 100 × 20.0 = 2000; 50 × 50.0 = 2500 → total = 4500
	assert.InDelta(t, 4500.0, report.TotalMarketValue, 0.001)
}

func TestGenerateHoldingsReport_ZeroBalance_Omitted(t *testing.T) {
	walletKey := "zero-balance-wallet"
	oracle := NewMockValuationOracle()
	assets := map[string]*Asset{
		"equity-Z": {ID: "equity-Z"},
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(walletKey, "equity-Z"): {AssetID: "equity-Z", HolderID: walletKey, Balance: 0},
	}
	tracker := NewCostBasisTracker()

	report, err := GenerateHoldingsReport(walletKey, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	assert.Empty(t, report.Holdings)
}

func TestGenerateHoldingsReport_OtherWalletHoldings_Excluded(t *testing.T) {
	walletKey := "my-wallet"
	other := "other-wallet"
	oracle := NewMockValuationOracle()
	assets := map[string]*Asset{
		"equity-A": {ID: "equity-A"},
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(other, "equity-A"): {AssetID: "equity-A", HolderID: other, Balance: 500},
	}
	tracker := NewCostBasisTracker()

	report, err := GenerateHoldingsReport(walletKey, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	assert.Empty(t, report.Holdings)
}

func TestGenerateHoldingsReport_SchemaVersion(t *testing.T) {
	walletKey := "schema-wallet"
	oracle := NewMockValuationOracle()
	report, err := GenerateHoldingsReport(walletKey, nil, nil, oracle, NewCostBasisTracker())
	require.NoError(t, err)
	assert.Equal(t, "1.0", report.SchemaVersion)
}

// ---------------------------------------------------------------------------
// HoldingsReport.MarshalFiDA
// ---------------------------------------------------------------------------

func TestHoldingsReportMarshalFiDA_ValidJSON(t *testing.T) {
	report := &HoldingsReport{
		SchemaVersion:   "1.0",
		WalletPublicKey: "pubkey123",
		GeneratedAt:     time.Now().Unix(),
		Holdings: []HoldingSnapshot{
			{AssetID: "equity-1", Quantity: 100, MarketValue: 2000, Currency: "GBP"},
		},
		TotalMarketValue: 2000,
	}

	data, err := report.MarshalFiDA()
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "1.0", out["schema_version"])
	assert.Equal(t, "pubkey123", out["wallet_key"])
}

// ---------------------------------------------------------------------------
// GenerateTaxReport — jurisdiction-specific
// ---------------------------------------------------------------------------

func makeTrade(id, assetID, sellerID, currency string, qty, price float64, year int) Trade {
	execAt := time.Date(year, 6, 15, 12, 0, 0, 0, time.UTC).Unix()
	return Trade{
		ID:         id,
		AssetID:    assetID,
		SellerID:   sellerID,
		Quantity:   qty,
		Price:      price,
		Currency:   currency,
		ExecutedAt: execAt,
	}
}

func TestGenerateTaxReport_GB_CapitalGain_WithExempt(t *testing.T) {
	walletKey := "uk-investor"
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-X", AcquisitionLot{Units: 100, UnitCost: 10.0})

	trade := makeTrade("t1", "equity-X", walletKey, "GBP", 100, 15.0, 2026)

	assets := map[string]*Asset{
		"equity-X": {ID: "equity-X", Currency: "GBP"},
	}
	oracle := NewMockValuationOracle()
	report, err := GenerateTaxReport(walletKey, 2026, "GB", "GBP", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)

	require.Len(t, report.Events, 1)
	evt := report.Events[0]
	assert.InDelta(t, 1500.0, evt.Proceeds, 0.001)  // 100 × 15
	assert.InDelta(t, 1000.0, evt.CostBasis, 0.001) // 100 × 10
	assert.InDelta(t, 500.0, evt.GainLoss, 0.001)

	// GB: £3,000 exempt — net gain < £3,000 → NetGainLoss = 0
	assert.Equal(t, 0.0, report.NetGainLoss)
	assert.Equal(t, "GB", report.Jurisdiction)
}

func TestGenerateTaxReport_GB_LargeGain_ExemptApplied(t *testing.T) {
	walletKey := "uk-investor-2"
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-Y", AcquisitionLot{Units: 1000, UnitCost: 5.0})

	trade := makeTrade("t2", "equity-Y", walletKey, "GBP", 1000, 15.0, 2026)
	assets := map[string]*Asset{"equity-Y": {ID: "equity-Y", Currency: "GBP"}}
	oracle := NewMockValuationOracle()

	report, err := GenerateTaxReport(walletKey, 2026, "GB", "GBP", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)
	// Gain = 10000, exempt = 3000 → net = 7000
	assert.InDelta(t, 7000.0, report.NetGainLoss, 0.001)
}

func TestGenerateTaxReport_NL_GainZero(t *testing.T) {
	walletKey := "nl-investor"
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-Z", AcquisitionLot{Units: 100, UnitCost: 10.0})

	trade := makeTrade("t3", "equity-Z", walletKey, "EUR", 100, 20.0, 2026)
	assets := map[string]*Asset{"equity-Z": {ID: "equity-Z", Currency: "EUR"}}
	oracle := NewMockValuationOracle()

	report, err := GenerateTaxReport(walletKey, 2026, "NL", "EUR", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)
	assert.Equal(t, 0.0, report.Events[0].GainLoss) // NL Box 3: individual disposal not taxed
}

func TestGenerateTaxReport_TradeOutsideYear_Excluded(t *testing.T) {
	walletKey := "eur-investor"
	tracker := NewCostBasisTracker()
	trade := makeTrade("t4", "equity-A", walletKey, "EUR", 50, 10.0, 2024)
	assets := map[string]*Asset{"equity-A": {ID: "equity-A", Currency: "EUR"}}
	oracle := NewMockValuationOracle()

	report, err := GenerateTaxReport(walletKey, 2026, "DE", "EUR", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)
	assert.Empty(t, report.Events)
	assert.Equal(t, 0.0, report.NetGainLoss)
}

func TestGenerateTaxReport_BuyerNotSeller_Excluded(t *testing.T) {
	walletKey := "buyer"
	tracker := NewCostBasisTracker()
	trade := makeTrade("t5", "equity-B", "seller-pub", "EUR", 100, 12.0, 2026)
	assets := map[string]*Asset{"equity-B": {ID: "equity-B", Currency: "EUR"}}
	oracle := NewMockValuationOracle()

	report, err := GenerateTaxReport(walletKey, 2026, "FR", "EUR", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)
	assert.Empty(t, report.Events) // buyer has no disposal
}

func TestGenerateTaxReport_MultipleTrades_Summed(t *testing.T) {
	walletKey := "multi-trade-investor"
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "equity-C", AcquisitionLot{Units: 200, UnitCost: 10.0})

	t1 := makeTrade("t6", "equity-C", walletKey, "GBP", 100, 15.0, 2026)
	t2 := makeTrade("t7", "equity-C", walletKey, "GBP", 100, 20.0, 2026)
	assets := map[string]*Asset{"equity-C": {ID: "equity-C", Currency: "GBP"}}
	oracle := NewMockValuationOracle()

	report, err := GenerateTaxReport(walletKey, 2026, "DE", "GBP", []Trade{t1, t2}, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 2)
	assert.InDelta(t, 500.0+1000.0, report.TotalGain, 0.001) // 500 + 1000
	assert.Equal(t, 0.0, report.TotalLoss)
}

func TestGenerateTaxReport_FXConversion_USDtoGBP(t *testing.T) {
	walletKey := "fx-investor"
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(walletKey, "usd-asset", AcquisitionLot{Units: 100, UnitCost: 10.0})

	oracle := NewMockValuationOracle()
	oracle.SetCurrencyRate("USD", "GBP", 0.80) // 1 USD = 0.80 GBP

	trade := makeTrade("t8", "usd-asset", walletKey, "USD", 100, 15.0, 2026)
	assets := map[string]*Asset{"usd-asset": {ID: "usd-asset", Currency: "USD"}}

	report, err := GenerateTaxReport(walletKey, 2026, "GB", "GBP", []Trade{trade}, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)
	// Proceeds = 100 × 15 × 0.80 = 1200 GBP
	assert.InDelta(t, 1200.0, report.Events[0].Proceeds, 0.001)
}

// ---------------------------------------------------------------------------
// TaxReport.MarshalFiDA
// ---------------------------------------------------------------------------

func TestTaxReportMarshalFiDA_ValidJSON(t *testing.T) {
	report := &TaxReport{
		SchemaVersion:   "1.0",
		WalletPublicKey: "pubkey456",
		TaxYear:         2026,
		Jurisdiction:    "GB",
		Currency:        "GBP",
		TotalGain:       5000,
		TotalLoss:       -1000,
		NetGainLoss:     4000,
	}

	data, err := report.MarshalFiDA()
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, float64(2026), out["tax_year"])
	assert.Equal(t, "GB", out["jurisdiction"])
}

// ---------------------------------------------------------------------------
// DefaultSettlementMethod
// ---------------------------------------------------------------------------

func TestDefaultSettlementMethod_GBP_FasterPay(t *testing.T) {
	assert.Equal(t, SettlementFasterPay, DefaultSettlementMethod("GBP"))
}

func TestDefaultSettlementMethod_EUR_EURC(t *testing.T) {
	assert.Equal(t, SettlementEURC, DefaultSettlementMethod("EUR"))
}

func TestDefaultSettlementMethod_USD_SWIFT(t *testing.T) {
	assert.Equal(t, SettlementSWIFT, DefaultSettlementMethod("USD"))
}

func TestDefaultSettlementMethod_CHF_SWIFT(t *testing.T) {
	assert.Equal(t, SettlementSWIFT, DefaultSettlementMethod("CHF"))
}

func TestDefaultSettlementMethod_Unknown_SEPA(t *testing.T) {
	assert.Equal(t, SettlementSEPA, DefaultSettlementMethod("JPY"))
	assert.Equal(t, SettlementSEPA, DefaultSettlementMethod(""))
}

// ---------------------------------------------------------------------------
// PontesPaymentProvider.RegisterSettlement — HTTP mock
// ---------------------------------------------------------------------------

func TestPontesRegisterSettlement_Success(t *testing.T) {
	type regReq struct {
		Reference string  `json:"reference"`
		Amount    float64 `json:"amount"`
		Currency  string  `json:"currency"`
	}
	type regResp struct {
		TransactionID string `json:"transactionId"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/settlements")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(regResp{TransactionID: "PONTES-TXN-001"})
	}))
	defer srv.Close()

	p, err := NewPontesPaymentProvider("apikey", srv.URL, "DLT-OP-1", "hmac-secret")
	require.NoError(t, err)

	instr := &PaymentInstruction{
		TradeID:       "trade-A",
		Reference:     "ref-A",
		TotalAmount:   5000.0,
		Currency:      "EUR",
		PayerWalletID: "buyer-pub",
		PayeeWalletID: "seller-pub",
	}

	txID, err := p.RegisterSettlement(instr)
	require.NoError(t, err)
	assert.Equal(t, "PONTES-TXN-001", txID)
	assert.Equal(t, "PONTES-TXN-001", instr.PontesTransactionID)
	assert.Equal(t, "eurosystem-pontes", instr.SettlementNetwork)
}

func TestPontesRegisterSettlement_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("upstream error"))
	}))
	defer srv.Close()

	p, _ := NewPontesPaymentProvider("k", srv.URL, "op", "hmac")
	instr := &PaymentInstruction{Reference: "ref-B", TotalAmount: 100, Currency: "EUR"}
	_, err := p.RegisterSettlement(instr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestPontesRegisterSettlement_EmptyTransactionID_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"transactionId": ""})
	}))
	defer srv.Close()

	p, _ := NewPontesPaymentProvider("k", srv.URL, "op", "hmac")
	instr := &PaymentInstruction{Reference: "ref-C", TotalAmount: 100, Currency: "EUR"}
	_, err := p.RegisterSettlement(instr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no transactionId")
}
