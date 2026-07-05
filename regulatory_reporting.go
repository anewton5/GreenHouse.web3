package gonetwork

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Regulatory Reporting
// ---------------------------------------------------------------------------

// ReportType identifies the regulatory framework a report targets.
type ReportType string

const (
	// ReportTypeMiFIR is a Markets in Financial Instruments Regulation transaction
	// report (EU 600/2014, RTS 22).  Required for every trade in a financial
	// instrument admitted to trading on an EU regulated venue.
	ReportTypeMiFIR ReportType = "mifir"

	// ReportTypeCMAR is a Capital Markets and Services Act Report used for
	// Singapore MAS-regulated transaction reporting.
	ReportTypeCMAR ReportType = "cmar"

	// ReportTypeAIFMD is an Alternative Investment Fund Managers Directive
	// Annex IV report (EU 2011/61).  Required for AIF fund-unit tokens.
	ReportTypeAIFMD ReportType = "aifmd"
)

// RegulatoryReport is the on-chain record of a completed regulatory transaction
// report.  Each trade that triggers a reporting obligation generates one or more
// RegulatoryReport entries, which are stored in bc.RegulatoryReports.
type RegulatoryReport struct {
	ID         string     `json:"id"`
	ReportType ReportType `json:"report_type"`
	TradeID    string     `json:"trade_id"`
	AssetID    string     `json:"asset_id"`
	ISIN       string     `json:"isin,omitempty"`
	DTI        string     `json:"dti,omitempty"`
	BuyerID    string     `json:"buyer_id"`
	SellerID   string     `json:"seller_id"`
	Quantity   float64    `json:"quantity"`
	Price      float64    `json:"price"`
	Currency   string     `json:"currency"`
	TradeDate  int64      `json:"trade_date"`  // Unix timestamp of execution
	ReportedAt int64      `json:"reported_at"` // Unix timestamp of this report
	BlockIndex int        `json:"block_index"`
	// Fields filled by the RegulatoryReportingService
	Venue          string `json:"venue,omitempty"`           // trading venue (e.g. "GreenHouse-MTF")
	InstrumentType string `json:"instrument_type,omitempty"` // MiFIR instrument category
	// BuyerLEI / SellerLEI (Phase 3) carry the counterparty's Legal Entity
	// Identifier when their wallet holds a ClaimTopicInstitutionalRole claim,
	// satisfying MiFIR RTS 22 field 7/16 (counterparty LEI). Empty when the
	// counterparty has no institutional role claim (e.g. a retail investor).
	BuyerLEI  string `json:"buyer_lei,omitempty"`
	SellerLEI string `json:"seller_lei,omitempty"`
}

// ReportingService is the interface for regulatory reporting back-ends.
// The DefaultReportingService stores reports on-chain; a live implementation
// would additionally submit reports to the relevant NCA/ARM via SFTP/API.
type ReportingService interface {
	// GenerateReport creates a RegulatoryReport for the given trade and asset,
	// and must be called once per trade that has a reporting obligation.
	GenerateReport(
		reportType ReportType,
		trade Trade,
		asset *Asset,
		blockIndex int,
	) (*RegulatoryReport, error)
}

// DefaultReportingService is the built-in reporting service that stores
// RegulatoryReports in the blockchain's in-memory report list.
// In production, subclass or wrap this to also submit to the NCA/ARM.
type DefaultReportingService struct{}

// GenerateReport implements ReportingService.
func (svc *DefaultReportingService) GenerateReport(
	reportType ReportType,
	trade Trade,
	asset *Asset,
	blockIndex int,
) (*RegulatoryReport, error) {
	if asset == nil {
		return nil, fmt.Errorf("asset must not be nil")
	}

	isin := ""
	dti := ""
	instrumentType := string(asset.AssetType)
	if asset.Metadata.ISIN != "" {
		isin = asset.Metadata.ISIN
	}
	if asset.Metadata.DTI != "" {
		dti = asset.Metadata.DTI
	}

	id := fmt.Sprintf("%s-%s-%d", string(reportType), trade.ID, time.Now().UnixNano())

	return &RegulatoryReport{
		ID:             id,
		ReportType:     reportType,
		TradeID:        trade.ID,
		AssetID:        asset.ID,
		ISIN:           isin,
		DTI:            dti,
		BuyerID:        trade.BuyerID,
		SellerID:       trade.SellerID,
		Quantity:       trade.Quantity,
		Price:          trade.Price,
		Currency:       asset.Currency,
		TradeDate:      trade.ExecutedAt,
		ReportedAt:     time.Now().Unix(),
		BlockIndex:     blockIndex,
		Venue:          "GreenHouse-MTF",
		InstrumentType: instrumentType,
	}, nil
}

// MiFIRReportableAssetTypes is the set of asset types that trigger MiFIR
// transaction reporting obligations under RTS 22.
var MiFIRReportableAssetTypes = map[AssetType]bool{
	AssetTypeEquity:      true,
	AssetTypeDebt:        true,
	AssetTypeWarrant:     true,
	AssetTypeConvertible: true,
}

// AIFMDReportableAssetTypes is the set of asset types that trigger AIFMD
// Annex IV reporting obligations.
var AIFMDReportableAssetTypes = map[AssetType]bool{
	AssetTypeFundUnit: true,
}

// GenerateMiFIRReport is a convenience function that generates a MiFIR report
// for a trade and appends it to bc.RegulatoryReports.
// It is called from SealBlock for every trade in a block's OrderTransactions.
// It uses bc.ReportingService (falling back to DefaultReportingService when nil)
// so that the NCAReportingService is invoked in production without callers needing
// to be aware of which implementation is active.
func GenerateMiFIRReport(
	bc *Blockchain,
	trade Trade,
	blockIndex int,
) {
	asset, ok := bc.Assets[trade.AssetID]
	if !ok {
		return
	}
	if !MiFIRReportableAssetTypes[asset.AssetType] {
		return
	}

	svc := bc.ReportingService
	if svc == nil {
		svc = &DefaultReportingService{}
	}
	report, err := svc.GenerateReport(ReportTypeMiFIR, trade, asset, blockIndex)
	if err != nil {
		return
	}
	report.BuyerLEI = lookupCounterpartyLEI(bc, trade.BuyerID)
	report.SellerLEI = lookupCounterpartyLEI(bc, trade.SellerID)
	bc.RegulatoryReports = append(bc.RegulatoryReports, report)

	bc.emitEvent(EventRegulatoryReport, map[string]any{
		"report_id":   report.ID,
		"report_type": string(report.ReportType),
		"trade_id":    report.TradeID,
		"asset_id":    report.AssetID,
		"block_index": blockIndex,
	})
}

// GenerateAIFMDReport generates an AIFMD Annex IV report for a fund-unit trade.
// It uses bc.ReportingService (falling back to DefaultReportingService when nil).
func GenerateAIFMDReport(
	bc *Blockchain,
	trade Trade,
	blockIndex int,
) {
	asset, ok := bc.Assets[trade.AssetID]
	if !ok {
		return
	}
	if !AIFMDReportableAssetTypes[asset.AssetType] {
		return
	}

	svc := bc.ReportingService
	if svc == nil {
		svc = &DefaultReportingService{}
	}
	report, err := svc.GenerateReport(ReportTypeAIFMD, trade, asset, blockIndex)
	if err != nil {
		return
	}
	report.BuyerLEI = lookupCounterpartyLEI(bc, trade.BuyerID)
	report.SellerLEI = lookupCounterpartyLEI(bc, trade.SellerID)
	bc.RegulatoryReports = append(bc.RegulatoryReports, report)

	bc.emitEvent(EventRegulatoryReport, map[string]any{
		"report_id":   report.ID,
		"report_type": string(report.ReportType),
		"trade_id":    report.TradeID,
		"asset_id":    report.AssetID,
		"block_index": blockIndex,
	})
}

// lookupCounterpartyLEI returns the LEI carried by any valid
// ClaimTopicInstitutionalRole claim held by walletKey, or "" if none exists
// (e.g. a retail investor with no institutional role). When a wallet holds
// role claims for more than one entity, the first match is used.
func lookupCounterpartyLEI(bc *Blockchain, walletKey string) string {
	for _, c := range EffectiveClaims(bc, walletKey) {
		if lei, _, err := ParseEntityRoleClaim(c); err == nil {
			return lei
		}
	}
	return ""
}

// MarshalRegulatoryReport returns the report as canonical JSON for archive submission.
func (r *RegulatoryReport) MarshalJSON() ([]byte, error) {
	type Alias RegulatoryReport
	return json.Marshal((*Alias)(r))
}
