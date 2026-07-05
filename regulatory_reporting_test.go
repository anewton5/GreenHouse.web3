package gonetwork

// ---------------------------------------------------------------------------
// regulatory_reporting_test.go
//
// Covers:
//   DefaultReportingService.GenerateReport  — MiFIR, AIFMD, nil asset error
//   GenerateMiFIRReport                     — equities/debt trigger, fund skips
//   GenerateAIFMDReport                     — fund triggers, equity skips
//   RegulatoryReport.MarshalJSON            — produces valid JSON
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testTrade(assetID string) Trade {
	return Trade{
		ID:         "trade-001",
		AssetID:    assetID,
		BuyerID:    "buyer-wallet",
		SellerID:   "seller-wallet",
		Quantity:   100,
		Price:      50.0,
		ExecutedAt: time.Now().Unix(),
	}
}

func testEquityAsset(id string) *Asset {
	return &Asset{
		ID:        id,
		AssetType: AssetTypeEquity,
		Currency:  "EUR",
		Issuer:    "issuer-wallet",
		Metadata:  AssetMetadata{ISIN: "GB0001234567", DTI: "AB12CD34E"},
	}
}

// ---------------------------------------------------------------------------
// DefaultReportingService.GenerateReport
// ---------------------------------------------------------------------------

func TestGenerateReport_MiFIR_FieldsSetCorrectly(t *testing.T) {
	svc := &DefaultReportingService{}
	asset := testEquityAsset("equity-001")
	trade := testTrade("equity-001")

	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, 5)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, ReportTypeMiFIR, report.ReportType)
	assert.Equal(t, "trade-001", report.TradeID)
	assert.Equal(t, "equity-001", report.AssetID)
	assert.Equal(t, "GB0001234567", report.ISIN)
	assert.Equal(t, "AB12CD34E", report.DTI)
	assert.Equal(t, "buyer-wallet", report.BuyerID)
	assert.Equal(t, "seller-wallet", report.SellerID)
	assert.InDelta(t, 100.0, report.Quantity, 0.01)
	assert.InDelta(t, 50.0, report.Price, 0.01)
	assert.Equal(t, "EUR", report.Currency)
	assert.Equal(t, 5, report.BlockIndex)
	assert.Equal(t, "GreenHouse-MTF", report.Venue)
	assert.NotEmpty(t, report.ID)
	assert.Greater(t, report.ReportedAt, int64(0))
}

func TestGenerateReport_AIFMD_FundUnit(t *testing.T) {
	svc := &DefaultReportingService{}
	asset := &Asset{ID: "fund-001", AssetType: AssetTypeFundUnit, Currency: "EUR"}
	trade := testTrade("fund-001")

	report, err := svc.GenerateReport(ReportTypeAIFMD, trade, asset, 2)
	require.NoError(t, err)
	assert.Equal(t, ReportTypeAIFMD, report.ReportType)
	assert.Equal(t, string(AssetTypeFundUnit), report.InstrumentType)
}

func TestGenerateReport_NilAsset_Error(t *testing.T) {
	svc := &DefaultReportingService{}
	_, err := svc.GenerateReport(ReportTypeMiFIR, testTrade("x"), nil, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "asset must not be nil")
}

func TestGenerateReport_NoISIN_EmptyISINField(t *testing.T) {
	svc := &DefaultReportingService{}
	asset := &Asset{ID: "no-isin", AssetType: AssetTypeDebt, Currency: "EUR"}
	report, err := svc.GenerateReport(ReportTypeMiFIR, testTrade("no-isin"), asset, 0)
	require.NoError(t, err)
	assert.Equal(t, "", report.ISIN)
	assert.Equal(t, "", report.DTI)
}

// ---------------------------------------------------------------------------
// GenerateMiFIRReport
// ---------------------------------------------------------------------------

func TestGenerateMiFIRReport_EquityTriggers(t *testing.T) {
	bc := NewBlockchain(context.Background(), "mifir-test")
	asset := testEquityAsset("equity-report")
	bc.Assets["equity-report"] = asset
	trade := testTrade("equity-report")

	GenerateMiFIRReport(bc, trade, 1)

	require.Len(t, bc.RegulatoryReports, 1)
	assert.Equal(t, ReportTypeMiFIR, bc.RegulatoryReports[0].ReportType)
}

func TestGenerateMiFIRReport_DebtTriggers(t *testing.T) {
	bc := NewBlockchain(context.Background(), "mifir-debt")
	asset := &Asset{ID: "bond-001", AssetType: AssetTypeDebt, Currency: "EUR"}
	bc.Assets["bond-001"] = asset

	GenerateMiFIRReport(bc, testTrade("bond-001"), 0)
	assert.Len(t, bc.RegulatoryReports, 1)
}

func TestGenerateMiFIRReport_WarrantTriggers(t *testing.T) {
	bc := NewBlockchain(context.Background(), "mifir-warrant")
	asset := &Asset{ID: "warrant-001", AssetType: AssetTypeWarrant, Currency: "EUR"}
	bc.Assets["warrant-001"] = asset

	GenerateMiFIRReport(bc, testTrade("warrant-001"), 0)
	assert.Len(t, bc.RegulatoryReports, 1)
}

func TestGenerateMiFIRReport_FundUnit_DoesNotTrigger(t *testing.T) {
	bc := NewBlockchain(context.Background(), "mifir-fund")
	asset := &Asset{ID: "fund-001", AssetType: AssetTypeFundUnit, Currency: "EUR"}
	bc.Assets["fund-001"] = asset

	GenerateMiFIRReport(bc, testTrade("fund-001"), 0)
	assert.Empty(t, bc.RegulatoryReports, "fund units do not trigger MiFIR reporting")
}

func TestGenerateMiFIRReport_UnknownAsset_NoReport(t *testing.T) {
	bc := NewBlockchain(context.Background(), "mifir-unknown")
	GenerateMiFIRReport(bc, testTrade("missing-asset"), 0)
	assert.Empty(t, bc.RegulatoryReports)
}

// ---------------------------------------------------------------------------
// GenerateAIFMDReport
// ---------------------------------------------------------------------------

func TestGenerateAIFMDReport_FundUnitTriggers(t *testing.T) {
	bc := NewBlockchain(context.Background(), "aifmd-test")
	asset := &Asset{ID: "fund-001", AssetType: AssetTypeFundUnit, Currency: "EUR"}
	bc.Assets["fund-001"] = asset

	GenerateAIFMDReport(bc, testTrade("fund-001"), 0)

	require.Len(t, bc.RegulatoryReports, 1)
	assert.Equal(t, ReportTypeAIFMD, bc.RegulatoryReports[0].ReportType)
}

func TestGenerateAIFMDReport_EquityDoesNotTrigger(t *testing.T) {
	bc := NewBlockchain(context.Background(), "aifmd-equity")
	asset := testEquityAsset("equity-001")
	bc.Assets["equity-001"] = asset

	GenerateAIFMDReport(bc, testTrade("equity-001"), 0)
	assert.Empty(t, bc.RegulatoryReports)
}

func TestGenerateAIFMDReport_UnknownAsset_NoReport(t *testing.T) {
	bc := NewBlockchain(context.Background(), "aifmd-unknown")
	GenerateAIFMDReport(bc, testTrade("missing-asset"), 0)
	assert.Empty(t, bc.RegulatoryReports)
}

// ---------------------------------------------------------------------------
// RegulatoryReport.MarshalJSON
// ---------------------------------------------------------------------------

func TestRegulatoryReport_MarshalJSON_ValidJSON(t *testing.T) {
	report := &RegulatoryReport{
		ID:         "RPT-001",
		ReportType: ReportTypeMiFIR,
		TradeID:    "trade-001",
		AssetID:    "equity-001",
		BuyerID:    "buyer",
		SellerID:   "seller",
		Quantity:   50,
		Price:      100,
		Currency:   "EUR",
	}
	data, err := report.MarshalJSON()
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "RPT-001", out["id"])
	assert.Equal(t, "mifir", out["report_type"])
}

// ---------------------------------------------------------------------------
// MiFIRReportableAssetTypes / AIFMDReportableAssetTypes — sanity checks
// ---------------------------------------------------------------------------

func TestMiFIRReportableAssetTypes_ContainsExpected(t *testing.T) {
	assert.True(t, MiFIRReportableAssetTypes[AssetTypeEquity])
	assert.True(t, MiFIRReportableAssetTypes[AssetTypeDebt])
	assert.True(t, MiFIRReportableAssetTypes[AssetTypeWarrant])
	assert.True(t, MiFIRReportableAssetTypes[AssetTypeConvertible])
	assert.False(t, MiFIRReportableAssetTypes[AssetTypeFundUnit])
}

func TestAIFMDReportableAssetTypes_ContainsExpected(t *testing.T) {
	assert.True(t, AIFMDReportableAssetTypes[AssetTypeFundUnit])
	assert.False(t, AIFMDReportableAssetTypes[AssetTypeEquity])
}
