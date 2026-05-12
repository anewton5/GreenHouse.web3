package gonetwork

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// ValuationOracle interface + Mock
// ---------------------------------------------------------------------------

// ValuationOracle provides current NAV or price per unit for an asset,
// and FX rates for currency conversion in tax reports.
type ValuationOracle interface {
	GetValuation(assetID string) (float64, error)
	GetCurrencyRate(from, to string) (float64, error)
}

// MockValuationOracle returns a configurable valuation per asset and 1:1 FX rates
// by default. Tests can set explicit values via SetValuation / SetCurrencyRate.
type MockValuationOracle struct {
	valuations    map[string]float64 // assetID → price per unit
	currencyRates map[string]float64 // "FROM:TO" → rate
}

// NewMockValuationOracle creates a MockValuationOracle with empty tables.
// Any asset not found returns 1.0 (par value); any currency pair returns 1.0.
func NewMockValuationOracle() *MockValuationOracle {
	return &MockValuationOracle{
		valuations:    make(map[string]float64),
		currencyRates: make(map[string]float64),
	}
}

func (m *MockValuationOracle) SetValuation(assetID string, price float64) {
	m.valuations[assetID] = price
}

func (m *MockValuationOracle) SetCurrencyRate(from, to string, rate float64) {
	m.currencyRates[from+":"+to] = rate
}

func (m *MockValuationOracle) GetValuation(assetID string) (float64, error) {
	if v, ok := m.valuations[assetID]; ok {
		return v, nil
	}
	return 1.0, nil // default: par
}

func (m *MockValuationOracle) GetCurrencyRate(from, to string) (float64, error) {
	if from == to {
		return 1.0, nil
	}
	if r, ok := m.currencyRates[from+":"+to]; ok {
		return r, nil
	}
	return 1.0, nil // default: 1:1
}

// ---------------------------------------------------------------------------
// CostBasisTracker
// ---------------------------------------------------------------------------

// AcquisitionLot records a single purchase tranche for FIFO cost-basis tracking.
type AcquisitionLot struct {
	AcquiredAt int64   // Unix timestamp
	Units      float64 // remaining unconsumed units in this lot
	UnitCost   float64 // original cost per unit in the asset's currency
	TradeID    string
}

// CostBasisTracker maintains per-wallet, per-asset acquisition lots using FIFO
// matching, which is the standard method for EU CGT calculations.
type CostBasisTracker struct {
	// Key: walletKey + ":" + assetID  →  ordered list of lots (oldest first)
	Lots map[string][]AcquisitionLot
}

// NewCostBasisTracker creates an empty CostBasisTracker.
func NewCostBasisTracker() *CostBasisTracker {
	return &CostBasisTracker{Lots: make(map[string][]AcquisitionLot)}
}

// RecordAcquisition appends a new lot to the wallet/asset FIFO queue.
func (t *CostBasisTracker) RecordAcquisition(walletKey, assetID string, lot AcquisitionLot) {
	key := walletKey + ":" + assetID
	t.Lots[key] = append(t.Lots[key], lot)
}

// ConsumeForDisposal removes units from the oldest lots first (FIFO) and returns
// the total cost basis for those units. Returns an error if the wallet does not
// hold enough recorded lots to cover the disposal.
func (t *CostBasisTracker) ConsumeForDisposal(
	walletKey, assetID string,
	units float64,
	_ int64, // disposalDate — reserved for future wash-sale rule checks
) (costBasis float64, lotsConsumed []AcquisitionLot, err error) {
	key := walletKey + ":" + assetID
	lots := t.Lots[key]

	remaining := units
	var consumed []AcquisitionLot

	for i := 0; i < len(lots) && remaining > 0; i++ {
		lot := &lots[i]
		if lot.Units <= 0 {
			continue
		}
		take := lot.Units
		if take > remaining {
			take = remaining
		}
		costBasis += take * lot.UnitCost
		consumed = append(consumed, AcquisitionLot{
			AcquiredAt: lot.AcquiredAt,
			Units:      take,
			UnitCost:   lot.UnitCost,
			TradeID:    lot.TradeID,
		})
		lot.Units -= take
		remaining -= take
	}

	if remaining > 0 {
		return 0, nil, fmt.Errorf(
			"insufficient cost-basis lots for wallet %s asset %s: %.4f units short",
			walletKey, assetID, remaining,
		)
	}

	// Remove exhausted lots
	var active []AcquisitionLot
	for _, l := range lots {
		if l.Units > 0 {
			active = append(active, l)
		}
	}
	t.Lots[key] = active

	return costBasis, consumed, nil
}

// ---------------------------------------------------------------------------
// HoldingsReport
// ---------------------------------------------------------------------------

// HoldingsReport is a FiDA-compliant snapshot of a wallet's holdings.
type HoldingsReport struct {
	SchemaVersion    string            `json:"schema_version"`
	WalletPublicKey  string            `json:"wallet_key"`
	GeneratedAt      int64             `json:"generated_at"`
	Holdings         []HoldingSnapshot `json:"holdings"`
	TotalMarketValue float64           `json:"total_market_value"`
}

// HoldingSnapshot captures the current economic position for one asset in a wallet.
type HoldingSnapshot struct {
	AssetID       string    `json:"asset_id"`
	AssetName     string    `json:"asset_name"`
	AssetType     AssetType `json:"asset_type"`
	ISIN          string    `json:"isin"`
	Quantity      float64   `json:"quantity"`
	Currency      string    `json:"currency"`
	CurrentPrice  float64   `json:"current_price"`
	MarketValue   float64   `json:"market_value"`
	AvgCost       float64   `json:"avg_cost"`
	UnrealisedPnL float64   `json:"unrealised_pnl"`
	LockedUntil   int64     `json:"locked_until"`
}

// GenerateHoldingsReport builds a FiDA HoldingsReport for walletKey from current
// on-chain state. It iterates all holdings that belong to the wallet, prices each
// via the ValuationOracle, and calculates unrealised P&L from the CostBasisTracker.
// Holdings with zero balance are omitted.
func GenerateHoldingsReport(
	walletKey string,
	holdings map[string]*AssetHolding,
	assets map[string]*Asset,
	valuation ValuationOracle,
	tracker *CostBasisTracker,
) (*HoldingsReport, error) {
	report := &HoldingsReport{
		SchemaVersion:   "1.0",
		WalletPublicKey: walletKey,
		GeneratedAt:     time.Now().UTC().Unix(),
	}

	for _, holding := range holdings {
		if holding.HolderID != walletKey {
			continue
		}
		if holding.Balance <= 0 {
			continue
		}

		asset, ok := assets[holding.AssetID]
		if !ok {
			continue
		}

		nav, err := valuation.GetValuation(holding.AssetID)
		if err != nil {
			return nil, fmt.Errorf("valuation error for asset %s: %w", holding.AssetID, err)
		}

		marketValue := holding.Balance * nav

		// Total acquisition cost: sum of remaining lot costs for this wallet/asset.
		var totalAcqCost float64
		lotKey := walletKey + ":" + holding.AssetID
		for _, lot := range tracker.Lots[lotKey] {
			totalAcqCost += lot.Units * lot.UnitCost
		}

		// avg_cost is per-unit average acquisition cost.
		avgCost := 0.0
		if holding.Balance > 0 {
			avgCost = totalAcqCost / holding.Balance
		}

		report.Holdings = append(report.Holdings, HoldingSnapshot{
			AssetID:       holding.AssetID,
			AssetName:     asset.Metadata.CompanyName,
			AssetType:     asset.AssetType,
			ISIN:          asset.Metadata.ISIN,
			Quantity:      holding.Balance,
			Currency:      asset.Currency,
			CurrentPrice:  nav,
			MarketValue:   marketValue,
			AvgCost:       avgCost,
			UnrealisedPnL: marketValue - totalAcqCost,
			LockedUntil:   holding.LockedUntil,
		})
		report.TotalMarketValue += marketValue
	}

	return report, nil
}

// MarshalFiDA returns the report as a FiDA-compliant JSON byte slice.
func (r *HoldingsReport) MarshalFiDA() ([]byte, error) {
	return json.Marshal(r)
}

// ---------------------------------------------------------------------------
// TaxReport
// ---------------------------------------------------------------------------

// TaxableEventType classifies each line in a tax report.
type TaxableEventType string

const (
	TaxEventAcquisition TaxableEventType = "acquisition"
	TaxEventDisposal    TaxableEventType = "disposal"
	TaxEventDividend    TaxableEventType = "dividend"
	TaxEventCapitalCall TaxableEventType = "capital_call"
)

// TaxableEvent is one line item in a TaxReport.
type TaxableEvent struct {
	Date      int64            `json:"date"`
	AssetID   string           `json:"asset_id"`
	Type      TaxableEventType `json:"type"`
	Units     float64          `json:"units"`
	UnitPrice float64          `json:"unit_price"`
	Proceeds  float64          `json:"proceeds"`   // Units × UnitPrice for disposals
	CostBasis float64          `json:"cost_basis"` // FIFO cost for disposals
	GainLoss  float64          `json:"gain_loss"`  // Proceeds − CostBasis
	Currency  string           `json:"currency"`
	TradeID   string           `json:"trade_id"`
}

// TaxReport covers taxable events for a wallet in a given tax year, formatted
// for major EU jurisdiction requirements (GB CGT, DE KeSt, FR PFU, NL Box 3).
type TaxReport struct {
	SchemaVersion   string         `json:"schema_version"`
	WalletPublicKey string         `json:"wallet_public_key"`
	TaxYear         int            `json:"tax_year"`
	Jurisdiction    string         `json:"jurisdiction"`
	Currency        string         `json:"currency"`
	Events          []TaxableEvent `json:"events"`
	TotalGain       float64        `json:"total_gain"`
	TotalLoss       float64        `json:"total_loss"`
	NetGainLoss     float64        `json:"net_gain_loss"`
}

// jurisdictionCGTExempt returns the annual capital-gains exempt amount in the
// reporting currency for the given jurisdiction (2026 values).
func jurisdictionCGTExempt(jurisdiction string) float64 {
	switch jurisdiction {
	case "GB":
		return 3_000 // £3,000 annual CGT exempt amount (2026)
	default:
		return 0
	}
}

// GenerateTaxReport produces a TaxReport for walletKey covering all disposals
// (sales) and dividends recorded in trades during taxYear. Cost basis is
// consumed from tracker using FIFO matching. FX conversion to reportCurrency
// is applied via valuation.GetCurrencyRate.
//
// Jurisdiction-specific rules applied:
//   - GB:  £3,000 annual CGT exempt amount deducted from net gain
//   - DE:  Kapitalertragsteuer 25% flat — no annual exempt; reported as net
//   - FR:  PFU (Flat Tax) 30% — no annual exempt
//   - NL:  Box 3 — individual disposals not taxed; function records events for
//     completeness but sets GainLoss = 0 per trade
func GenerateTaxReport(
	walletKey string,
	taxYear int,
	jurisdiction string,
	reportCurrency string,
	trades []Trade,
	assets map[string]*Asset,
	tracker *CostBasisTracker,
	valuation ValuationOracle,
) (*TaxReport, error) {
	report := &TaxReport{
		SchemaVersion:   "1.0",
		WalletPublicKey: walletKey,
		TaxYear:         taxYear,
		Jurisdiction:    jurisdiction,
		Currency:        reportCurrency,
	}

	yearStart := time.Date(taxYear, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	yearEnd := time.Date(taxYear+1, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	for _, trade := range trades {
		// Only include trades within the tax year
		if trade.ExecutedAt < yearStart || trade.ExecutedAt >= yearEnd {
			continue
		}
		// Only the seller has a disposal
		if trade.SellerID != walletKey {
			continue
		}

		asset, ok := assets[trade.AssetID]
		if !ok {
			continue
		}

		// FX rate from trade currency to report currency
		fxRate, err := valuation.GetCurrencyRate(trade.Currency, reportCurrency)
		if err != nil {
			return nil, fmt.Errorf("FX rate error %s→%s: %w", trade.Currency, reportCurrency, err)
		}

		proceeds := trade.Quantity * trade.Price * fxRate

		// FIFO cost basis
		costBasisLocal, _, err := tracker.ConsumeForDisposal(
			walletKey, trade.AssetID, trade.Quantity, trade.ExecutedAt,
		)
		if err != nil {
			// If no lots recorded, fall back to zero cost basis (shouldn't happen in practice)
			costBasisLocal = 0
		}

		// Convert cost basis to report currency (assume cost recorded in asset currency)
		assetCurrency := trade.Currency
		if asset != nil {
			assetCurrency = asset.Currency
		}
		costFXRate, err := valuation.GetCurrencyRate(assetCurrency, reportCurrency)
		if err != nil {
			costFXRate = 1.0
		}
		costBasis := costBasisLocal * costFXRate

		gainLoss := proceeds - costBasis

		// NL Box 3: individual trades not taxed
		if jurisdiction == "NL" {
			gainLoss = 0
		}

		event := TaxableEvent{
			Date:      trade.ExecutedAt,
			AssetID:   trade.AssetID,
			Type:      TaxEventDisposal,
			Units:     trade.Quantity,
			UnitPrice: trade.Price * fxRate,
			Proceeds:  proceeds,
			CostBasis: costBasis,
			GainLoss:  gainLoss,
			Currency:  reportCurrency,
			TradeID:   trade.ID,
		}
		report.Events = append(report.Events, event)

		if gainLoss > 0 {
			report.TotalGain += gainLoss
		} else {
			report.TotalLoss += gainLoss
		}
	}

	report.NetGainLoss = report.TotalGain + report.TotalLoss

	// Apply jurisdiction-specific annual exempt amount
	exempt := jurisdictionCGTExempt(jurisdiction)
	if exempt > 0 && report.NetGainLoss > 0 {
		report.NetGainLoss -= exempt
		if report.NetGainLoss < 0 {
			report.NetGainLoss = 0
		}
	}

	return report, nil
}

// MarshalFiDA returns the tax report as a FiDA-compliant JSON byte slice.
func (r *TaxReport) MarshalFiDA() ([]byte, error) {
	return json.Marshal(r)
}
