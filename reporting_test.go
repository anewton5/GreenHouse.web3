package gonetwork

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newReportingTestAsset(id, name, assetType, isin, currency string) *Asset {
	return &Asset{
		ID:        id,
		AssetType: AssetType(assetType),
		Currency:  currency,
		Metadata: AssetMetadata{
			CompanyName: name,
			ISIN:        isin,
		},
	}
}

func newReportingTestHolding(assetID, holderID string, balance float64) *AssetHolding {
	return &AssetHolding{
		AssetID:  assetID,
		HolderID: holderID,
		Balance:  balance,
	}
}

// ---------------------------------------------------------------------------
// HoldingsReport tests
// ---------------------------------------------------------------------------

func TestGenerateHoldingsReport_SingleAsset(t *testing.T) {
	wallet := "wallet-alice"
	assetID := "ASSET-1"

	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "Acme Corp", "equity", "DE000A0Z1234", "EUR"),
	}
	holdingKey := HoldingKey(wallet, assetID)
	holdings := map[string]*AssetHolding{
		holdingKey: newReportingTestHolding(assetID, wallet, 100),
	}

	oracle := NewMockValuationOracle()
	oracle.SetValuation(assetID, 12.50) // €12.50 per unit

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{
		AcquiredAt: time.Now().Add(-30 * 24 * time.Hour).Unix(),
		Units:      100,
		UnitCost:   10.00, // bought at €10
		TradeID:    "T1",
	})

	report, err := GenerateHoldingsReport(wallet, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	require.Len(t, report.Holdings, 1)

	h := report.Holdings[0]
	assert.Equal(t, assetID, h.AssetID)
	assert.Equal(t, "Acme Corp", h.AssetName)
	assert.Equal(t, AssetType("equity"), h.AssetType)
	assert.Equal(t, "DE000A0Z1234", h.ISIN)
	assert.InDelta(t, 100.0, h.Balance, 1e-9)
	assert.InDelta(t, 12.50, h.NAVPerUnit, 1e-9)
	assert.InDelta(t, 1250.0, h.TotalValue, 1e-9)
	assert.InDelta(t, 1000.0, h.AcquisitionCost, 1e-9)
	assert.InDelta(t, 250.0, h.UnrealisedPnL, 1e-9)
}

func TestGenerateHoldingsReport_MultiAsset(t *testing.T) {
	wallet := "wallet-bob"
	assets := map[string]*Asset{
		"A1": newReportingTestAsset("A1", "Fund Alpha", "fund_unit", "LU0000001111", "EUR"),
		"A2": newReportingTestAsset("A2", "Bond Beta", "debt", "DE000000002", "EUR"),
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(wallet, "A1"): newReportingTestHolding("A1", wallet, 50),
		HoldingKey(wallet, "A2"): newReportingTestHolding("A2", wallet, 200),
	}

	oracle := NewMockValuationOracle()
	oracle.SetValuation("A1", 100.0)
	oracle.SetValuation("A2", 1.05)

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, "A1", AcquisitionLot{Units: 50, UnitCost: 90.0, TradeID: "T1"})
	tracker.RecordAcquisition(wallet, "A2", AcquisitionLot{Units: 200, UnitCost: 1.0, TradeID: "T2"})

	report, err := GenerateHoldingsReport(wallet, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	require.Len(t, report.Holdings, 2)
	assert.Equal(t, "1.0", report.SchemaVersion)

	totalValue := 0.0
	for _, h := range report.Holdings {
		totalValue += h.TotalValue
	}
	// A1: 50×100=5000; A2: 200×1.05=210
	assert.InDelta(t, 5210.0, totalValue, 1e-6)
}

func TestGenerateHoldingsReport_EmptyWallet(t *testing.T) {
	wallet := "wallet-empty"
	assets := map[string]*Asset{
		"A1": newReportingTestAsset("A1", "X Corp", "equity", "", "EUR"),
	}
	// no holdings for this wallet
	holdings := map[string]*AssetHolding{}
	oracle := NewMockValuationOracle()
	tracker := NewCostBasisTracker()

	report, err := GenerateHoldingsReport(wallet, holdings, assets, oracle, tracker)
	require.NoError(t, err)
	assert.Empty(t, report.Holdings)
	assert.Equal(t, wallet, report.WalletPublicKey)
}

// ---------------------------------------------------------------------------
// CostBasisTracker tests
// ---------------------------------------------------------------------------

func TestCostBasisTracker_FIFO(t *testing.T) {
	tracker := NewCostBasisTracker()
	wallet, asset := "w1", "ASSET-X"

	tracker.RecordAcquisition(wallet, asset, AcquisitionLot{AcquiredAt: 1000, Units: 50, UnitCost: 10.0, TradeID: "old"})
	tracker.RecordAcquisition(wallet, asset, AcquisitionLot{AcquiredAt: 2000, Units: 50, UnitCost: 20.0, TradeID: "new"})

	// Dispose 60 units: should consume 50 from old lot (cost 500) + 10 from new (cost 200)
	costBasis, consumed, err := tracker.ConsumeForDisposal(wallet, asset, 60, time.Now().Unix())
	require.NoError(t, err)
	assert.InDelta(t, 700.0, costBasis, 1e-9) // 50×10 + 10×20
	require.Len(t, consumed, 2)
	assert.Equal(t, "old", consumed[0].TradeID)
	assert.Equal(t, "new", consumed[1].TradeID)

	// Remaining lot should have 40 units at €20
	remaining := tracker.Lots[wallet+":"+asset]
	require.Len(t, remaining, 1)
	assert.InDelta(t, 40.0, remaining[0].Units, 1e-9)
	assert.InDelta(t, 20.0, remaining[0].UnitCost, 1e-9)
}

func TestCostBasisTracker_PartialLot(t *testing.T) {
	tracker := NewCostBasisTracker()
	wallet, asset := "w2", "ASSET-Y"
	tracker.RecordAcquisition(wallet, asset, AcquisitionLot{Units: 100, UnitCost: 5.0, TradeID: "T1"})

	// Only consume 30 units
	costBasis, _, err := tracker.ConsumeForDisposal(wallet, asset, 30, time.Now().Unix())
	require.NoError(t, err)
	assert.InDelta(t, 150.0, costBasis, 1e-9) // 30×5

	remaining := tracker.Lots[wallet+":"+asset]
	require.Len(t, remaining, 1)
	assert.InDelta(t, 70.0, remaining[0].Units, 1e-9)
}

func TestCostBasisTracker_InsufficientUnits(t *testing.T) {
	tracker := NewCostBasisTracker()
	wallet, asset := "w3", "ASSET-Z"
	tracker.RecordAcquisition(wallet, asset, AcquisitionLot{Units: 10, UnitCost: 5.0, TradeID: "T1"})

	_, _, err := tracker.ConsumeForDisposal(wallet, asset, 50, time.Now().Unix())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient cost-basis lots")
}

// ---------------------------------------------------------------------------
// TaxReport tests
// ---------------------------------------------------------------------------

func newTestTrade(id, assetID, buyerID, sellerID string, price, qty float64, executedAt int64) Trade {
	return Trade{
		ID:         id,
		AssetID:    assetID,
		BuyerID:    buyerID,
		SellerID:   sellerID,
		Price:      price,
		Quantity:   qty,
		Currency:   "EUR",
		ExecutedAt: executedAt,
	}
}

func TestGenerateTaxReport_Gain(t *testing.T) {
	wallet := "seller-wallet"
	assetID := "ASSET-1"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "Corp", "equity", "", "EUR"),
	}

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{
		Units: 100, UnitCost: 10.0, TradeID: "buy1",
		AcquiredAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	})

	saleDate := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC).Unix()
	trades := []Trade{newTestTrade("T1", assetID, "buyer", wallet, 15.0, 100, saleDate)}

	oracle := NewMockValuationOracle()
	report, err := GenerateTaxReport(wallet, 2025, "DE", "EUR", trades, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)

	ev := report.Events[0]
	assert.Equal(t, TaxEventDisposal, ev.Type)
	assert.InDelta(t, 1500.0, ev.Proceeds, 1e-9)  // 100×15
	assert.InDelta(t, 1000.0, ev.CostBasis, 1e-9) // 100×10
	assert.InDelta(t, 500.0, ev.GainLoss, 1e-9)
	assert.InDelta(t, 500.0, report.TotalGain, 1e-9)
	assert.InDelta(t, 500.0, report.NetGainLoss, 1e-9)
}

func TestGenerateTaxReport_Loss(t *testing.T) {
	wallet := "seller-wallet-2"
	assetID := "ASSET-2"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "Corp", "equity", "", "EUR"),
	}

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{
		Units: 50, UnitCost: 20.0, TradeID: "buy1",
	})

	saleDate := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	trades := []Trade{newTestTrade("T2", assetID, "buyer2", wallet, 12.0, 50, saleDate)}

	oracle := NewMockValuationOracle()
	report, err := GenerateTaxReport(wallet, 2025, "FR", "EUR", trades, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)

	ev := report.Events[0]
	assert.InDelta(t, 600.0, ev.Proceeds, 1e-9)   // 50×12
	assert.InDelta(t, 1000.0, ev.CostBasis, 1e-9) // 50×20
	assert.InDelta(t, -400.0, ev.GainLoss, 1e-9)
	assert.InDelta(t, -400.0, report.TotalLoss, 1e-9)
	assert.InDelta(t, -400.0, report.NetGainLoss, 1e-9)
}

func TestGenerateTaxReport_GBExemptAmount(t *testing.T) {
	wallet := "gb-seller"
	assetID := "ASSET-GB"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "UK Corp", "equity", "", "GBP"),
	}

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{
		Units: 100, UnitCost: 10.0, TradeID: "buy1",
	})

	// Net gain = £500 — below £3,000 exempt → NetGainLoss should be 0
	saleDate := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC).Unix()
	trades := []Trade{
		{ID: "T-GB", AssetID: assetID, BuyerID: "buyer", SellerID: wallet,
			Price: 15.0, Quantity: 100, Currency: "GBP", ExecutedAt: saleDate},
	}

	oracle := NewMockValuationOracle()
	report, err := GenerateTaxReport(wallet, 2025, "GB", "GBP", trades, assets, tracker, oracle)
	require.NoError(t, err)
	assert.InDelta(t, 500.0, report.TotalGain, 1e-9)
	assert.InDelta(t, 0.0, report.NetGainLoss, 1e-9) // exempted

	// Now test a gain ABOVE the £3,000 exemption
	tracker2 := NewCostBasisTracker()
	tracker2.RecordAcquisition(wallet, assetID, AcquisitionLot{Units: 100, UnitCost: 10.0, TradeID: "buy2"})
	trades2 := []Trade{
		{ID: "T-GB2", AssetID: assetID, BuyerID: "buyer", SellerID: wallet,
			Price: 50.0, Quantity: 100, Currency: "GBP", ExecutedAt: saleDate},
	}
	report2, err := GenerateTaxReport(wallet, 2025, "GB", "GBP", trades2, assets, tracker2, oracle)
	require.NoError(t, err)
	assert.InDelta(t, 4000.0, report2.TotalGain, 1e-9)
	assert.InDelta(t, 1000.0, report2.NetGainLoss, 1e-9) // 4000 − 3000 = 1000
}

func TestGenerateTaxReport_FXConversion(t *testing.T) {
	wallet := "gb-investor"
	assetID := "ASSET-EUR"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "EU Corp", "equity", "", "EUR"),
	}

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{
		Units: 100, UnitCost: 10.0, TradeID: "buy1",
	})

	oracle := NewMockValuationOracle()
	oracle.SetCurrencyRate("EUR", "GBP", 0.85) // 1 EUR = 0.85 GBP

	saleDate := time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC).Unix()
	trades := []Trade{
		{ID: "T-FX", AssetID: assetID, BuyerID: "buyer", SellerID: wallet,
			Price: 20.0, Quantity: 100, Currency: "EUR", ExecutedAt: saleDate},
	}

	report, err := GenerateTaxReport(wallet, 2025, "GB", "GBP", trades, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)

	ev := report.Events[0]
	// Proceeds: 100×20×0.85 = 1700 GBP
	assert.InDelta(t, 1700.0, ev.Proceeds, 1e-6)
	// Cost basis: 100×10×0.85 = 850 GBP
	assert.InDelta(t, 850.0, ev.CostBasis, 1e-6)
	// Gain: 850 GBP; after £3,000 exempt (gain < exempt) → NetGainLoss = 0
	assert.InDelta(t, 0.0, report.NetGainLoss, 1e-6)
}

func TestGenerateTaxReport_FiltersByYear(t *testing.T) {
	wallet := "filter-seller"
	assetID := "ASSET-F"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "Corp", "equity", "", "EUR"),
	}

	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{Units: 200, UnitCost: 5.0, TradeID: "buy1"})

	date2024 := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC).Unix()
	date2025 := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC).Unix()
	date2026 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC).Unix()

	trades := []Trade{
		newTestTrade("T-2024", assetID, "buyer", wallet, 10.0, 50, date2024),
		newTestTrade("T-2025", assetID, "buyer", wallet, 10.0, 50, date2025),
		newTestTrade("T-2026", assetID, "buyer", wallet, 10.0, 50, date2026),
	}

	oracle := NewMockValuationOracle()
	report, err := GenerateTaxReport(wallet, 2025, "DE", "EUR", trades, assets, tracker, oracle)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)
	assert.Equal(t, "T-2025", report.Events[0].TradeID)
}

// ---------------------------------------------------------------------------
// MarshalFiDA tests
// ---------------------------------------------------------------------------

func TestMarshalFiDA_HoldingsReport(t *testing.T) {
	wallet := "alice"
	assetID := "ASSET-M"
	assets := map[string]*Asset{
		assetID: newReportingTestAsset(assetID, "Marshal Corp", "equity", "LU0001", "EUR"),
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(wallet, assetID): newReportingTestHolding(assetID, wallet, 10),
	}
	oracle := NewMockValuationOracle()
	oracle.SetValuation(assetID, 2.0)
	tracker := NewCostBasisTracker()
	tracker.RecordAcquisition(wallet, assetID, AcquisitionLot{Units: 10, UnitCost: 1.5, TradeID: "TX"})

	report, err := GenerateHoldingsReport(wallet, holdings, assets, oracle, tracker)
	require.NoError(t, err)

	data, err := report.MarshalFiDA()
	require.NoError(t, err)

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "1.0", out["schema_version"])
	assert.Equal(t, wallet, out["wallet_public_key"])
	assert.NotNil(t, out["generated_at"])
	assert.NotNil(t, out["holdings"])
}
