package gonetwork

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ExemptionBasis is the regulatory foundation for a prospectus exemption.
type ExemptionBasis string

const (
	// ExemptionProspectusArt1_4 allows placements to fewer than 150 non-professional
	// investors per EU member state without a full prospectus (EU 2017/1129 Art 1(4)).
	ExemptionProspectusArt1_4 ExemptionBasis = "prospectus_art1_4"
	// ExemptionQIBOnly restricts participation to Qualified Institutional Buyers / ELTIFs.
	ExemptionQIBOnly ExemptionBasis = "qib_only"
	// ExemptionPilotRegime uses the EU DLT Pilot Regime sandbox (EU 2022/858).
	ExemptionPilotRegime ExemptionBasis = "dlt_pilot"
)

// ProspectusExemption tracks the regulatory basis for a placement and enforces
// per-jurisdiction retail investor caps in real time.
// RetailHoldersByJurisdiction is rebuilt by UpdateRetailCounts at the end of
// each block so it always reflects the current on-chain state.
type ProspectusExemption struct {
	AssetID                     string
	Basis                       ExemptionBasis
	MaxRetailPerJurisdiction    int            // typically 149 (i.e. < 150)
	MaxTicketSizeEUR            float64        // 0 = no limit
	JurisdictionCoverage        []string       // ISO codes; empty = any EU jurisdiction
	RetailHoldersByJurisdiction map[string]int // jurisdictionCode → current count

	// TwelveMonthEURValue is the 12-month rolling total raised under this exemption
	// in EUR-equivalent. Used to enforce Prospectus Regulation value thresholds
	// (Art 1(3): €1M simplified; Art 3(2): €8M threshold above which full prospectus
	// is typically required under national implementing rules).
	TwelveMonthEURValue float64 `json:"twelve_month_eur_value"`
	// OfferingValueByTradeID records the EUR value of each settled trade so that
	// cancellations can decrement the rolling total accurately.
	OfferingValueByTradeID map[string]float64 `json:"offering_value_by_trade_id"`
}

// SuitabilityAssessment is the on-chain MiFID II Article 25 record for a wallet/asset pair.
// For complex instruments (warrants, convertibles) a positive assessment is mandatory
// before a transfer is permitted.
type SuitabilityAssessment struct {
	WalletPublicKey         string
	AssetID                 string
	InstrumentClass         AssetType
	AssessedAt              int64
	HasSufficientKnowledge  bool
	HasSufficientExperience bool
	CanAbsorbLoss           bool
	Suitable                bool   // final determination — all three flags must be true
	RegistrySignature       []byte // signed by IdentityRegistry
}

// JurisdictionRule encodes country-specific transfer constraints layered on top of
// the global AccreditedOnly / MaxHolders rules already present in TransferRestrictions.
type JurisdictionRule struct {
	CountryCode         string
	MaxRetailHolders    int         // 0 = unlimited
	RequiresSuitability bool        // true for MiFID II complex instruments in this jurisdiction
	BlockedAssetTypes   []AssetType // asset types that may not be distributed in this country
	MinTicketSizeEUR    float64     // 0 = no minimum
	MaxTicketSizeEUR    float64     // 0 = no limit

	// G-11: UK Financial Promotion Order fields
	// FPOExemptionType is the Financial Promotion Order 2005 article under which
	// this promotion is exempt from FCA authorisation (e.g. "fpo_art19" for
	// certified high-net-worth individuals, "fpo_art50" for sophisticated investors).
	// An empty string means no FPO exemption is claimed.
	FPOExemptionType string `json:"fpo_exemption_type,omitempty"`
	// RequiresRiskWarning indicates that a prescribed risk warning must be displayed
	// to retail investors before they can invest (required for all UK retail offerings).
	RequiresRiskWarning bool `json:"requires_risk_warning,omitempty"`
}

// SuitabilityKey returns the canonical map key for a suitability assessment.
// Format: "<walletPublicKey>:<assetID>"
func SuitabilityKey(walletKey, assetID string) string {
	return walletKey + ":" + assetID
}

// ---------------------------------------------------------------------------
// ProspectusExemption
// ---------------------------------------------------------------------------

// NewProspectusExemption creates a ProspectusExemption for the given asset.
// maxRetailPerJurisdiction is the maximum number of retail investors allowed
// per EU member state under the chosen exemption basis (typically 149).
// jurisdictions is the set of target EU member-state ISO codes; empty means any.
func NewProspectusExemption(
	assetID string,
	basis ExemptionBasis,
	maxRetailPerJurisdiction int,
	jurisdictions []string,
) *ProspectusExemption {
	return &ProspectusExemption{
		AssetID:                     assetID,
		Basis:                       basis,
		MaxRetailPerJurisdiction:    maxRetailPerJurisdiction,
		JurisdictionCoverage:        jurisdictions,
		RetailHoldersByJurisdiction: make(map[string]int),
	}
}

// CheckProspectusLimits returns an error if adding receiverCredential would
// breach the per-jurisdiction retail investor cap. Professional, eligible
// counterparty, and accredited investors do not count toward the cap.
//
// The exemption's RetailHoldersByJurisdiction map must be up to date before calling
// this function (call UpdateRetailCounts after each block).
func CheckProspectusLimits(
	receiverCredential *CredentialAttestation,
	exemption *ProspectusExemption,
) error {
	if exemption == nil {
		return nil
	}
	if receiverCredential == nil {
		// No credential — treat as retail, unknown jurisdiction
		return fmt.Errorf("receiver has no credential; cannot verify prospectus eligibility")
	}
	// Professional / eligible-CP / accredited investors do not count toward retail cap
	if receiverCredential.InvestorClass != InvestorClassRetail {
		return nil
	}

	jur := receiverCredential.Jurisdiction
	current := exemption.RetailHoldersByJurisdiction[jur]
	if exemption.MaxRetailPerJurisdiction > 0 && current >= exemption.MaxRetailPerJurisdiction {
		return fmt.Errorf(
			"prospectus exemption cap reached: %d/%d retail investors in jurisdiction %s",
			current, exemption.MaxRetailPerJurisdiction, jur,
		)
	}
	return nil
}

// UpdateRetailCounts rebuilds RetailHoldersByJurisdiction from the current holdings
// and credentials maps. It should be called at the end of finalizeBlock so the counts
// are always consistent with the on-chain state.
func UpdateRetailCounts(
	exemption *ProspectusExemption,
	holdings map[string]*AssetHolding,
	credentials map[string]*CredentialAttestation,
) {
	counts := make(map[string]int)
	for _, holding := range holdings {
		if holding.AssetID != exemption.AssetID {
			continue
		}
		if holding.Balance <= 0 {
			continue
		}
		cred, ok := credentials[holding.HolderID]
		if !ok {
			continue
		}
		if cred.InvestorClass == InvestorClassRetail {
			counts[cred.Jurisdiction]++
		}
	}
	exemption.RetailHoldersByJurisdiction = counts
}

// ---------------------------------------------------------------------------
// Suitability
// ---------------------------------------------------------------------------

// complexInstruments is the set of asset types that require MiFID II suitability
// assessment before a transfer is permitted.
var complexInstruments = map[AssetType]bool{
	AssetTypeWarrant:     true,
	AssetTypeConvertible: true,
}

// CheckSuitability returns an error if the instrument is complex (warrant or
// convertible) and either no assessment exists for this wallet/asset pair or the
// assessment is negative. Standard equities, debt, and fund units pass through
// without a check.
func CheckSuitability(
	walletKey string,
	asset *Asset,
	assessments map[string]*SuitabilityAssessment,
) error {
	if !complexInstruments[asset.AssetType] {
		return nil
	}
	key := SuitabilityKey(walletKey, asset.ID)
	assessment, ok := assessments[key]
	if !ok {
		return fmt.Errorf(
			"MiFID II suitability assessment required for %s instrument (asset %s): none found for wallet %s",
			asset.AssetType, asset.ID, walletKey,
		)
	}
	if !assessment.Suitable {
		return fmt.Errorf(
			"MiFID II suitability assessment for wallet %s on asset %s is negative",
			walletKey, asset.ID,
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// JurisdictionRule
// ---------------------------------------------------------------------------

// ApplyJurisdictionRule checks a JurisdictionRule against a proposed transfer.
// senderCredential and receiverCredential may be nil (treated as uncredentialled retail).
// ticketValueEUR is the EUR-equivalent deal size (Amount × PricePerUnit × FX rate).
func ApplyJurisdictionRule(
	rule *JurisdictionRule,
	senderCredential *CredentialAttestation,
	receiverCredential *CredentialAttestation,
	asset *Asset,
	ticketValueEUR float64,
) error {
	if rule == nil {
		return nil
	}

	// Check blocked asset types for this jurisdiction
	for _, blocked := range rule.BlockedAssetTypes {
		if asset.AssetType == blocked {
			return fmt.Errorf(
				"asset type %s is blocked for distribution in jurisdiction %s",
				asset.AssetType, rule.CountryCode,
			)
		}
	}

	// Min ticket size
	if rule.MinTicketSizeEUR > 0 && ticketValueEUR < rule.MinTicketSizeEUR {
		return fmt.Errorf(
			"ticket size EUR %.2f is below minimum EUR %.2f for jurisdiction %s",
			ticketValueEUR, rule.MinTicketSizeEUR, rule.CountryCode,
		)
	}

	// Max ticket size
	if rule.MaxTicketSizeEUR > 0 && ticketValueEUR > rule.MaxTicketSizeEUR {
		return fmt.Errorf(
			"ticket size EUR %.2f exceeds maximum EUR %.2f for jurisdiction %s",
			ticketValueEUR, rule.MaxTicketSizeEUR, rule.CountryCode,
		)
	}

	// Retail-holder cap for jurisdiction
	if rule.MaxRetailHolders > 0 {
		receiverClass := InvestorClassRetail
		if receiverCredential != nil {
			receiverClass = receiverCredential.InvestorClass
		}
		if receiverClass == InvestorClassRetail {
			// The caller is responsible for tracking the live count;
			// we surface the rule — actual count enforcement is in CheckProspectusLimits.
			_ = senderCredential // available for future rule extensions
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// ProspectusExemption — EUR rolling value helpers
// ---------------------------------------------------------------------------

// ProspectusThreshold1MEUR is the lower value threshold under Art 1(3) of the
// Prospectus Regulation. Offerings below this amount are always exempt.
const ProspectusThreshold1MEUR = 1_000_000.0

// ProspectusThreshold8MEUR is the upper value threshold: above this, a full EU
// prospectus is typically required unless the qualified-investor-only exemption applies.
const ProspectusThreshold8MEUR = 8_000_000.0

// RecordSettlement adds the EUR value of a settled trade to the exemption's 12-month
// rolling total. Call this from finalizeBlock after DVP settlement completes.
func (pe *ProspectusExemption) RecordSettlement(tradeID string, eurValue float64) {
	if pe.OfferingValueByTradeID == nil {
		pe.OfferingValueByTradeID = make(map[string]float64)
	}
	if _, exists := pe.OfferingValueByTradeID[tradeID]; !exists {
		pe.OfferingValueByTradeID[tradeID] = eurValue
		pe.TwelveMonthEURValue += eurValue
	}
}

// CheckProspectusValueThreshold returns an error if a new trade of eurValue would
// push the exemption over the 8M EUR value ceiling that triggers a full prospectus
// obligation (unless the exemption basis is QIB-only, which has no value cap).
func CheckProspectusValueThreshold(pe *ProspectusExemption, eurValue float64) error {
	if pe == nil || pe.Basis == ExemptionQIBOnly {
		return nil
	}
	if pe.TwelveMonthEURValue+eurValue > ProspectusThreshold8MEUR {
		return fmt.Errorf(
			"offering would exceed €8M 12-month value threshold (current: €%.2f, new: €%.2f): full prospectus required",
			pe.TwelveMonthEURValue, eurValue,
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MAR Article 18 — Insider Lists
// ---------------------------------------------------------------------------

// InsiderRecord represents one entry on a MAR Article 18 insider list.
// An insider is any person who has access to inside information relating to an admitted
// instrument. The platform operator must maintain these lists and produce them to the
// NCA on demand (MAR Art 18(1)).
type InsiderRecord struct {
	ID            string `json:"id"`
	AssetID       string `json:"asset_id"`
	FullName      string `json:"full_name"` // full legal name
	Role          string `json:"role"`      // e.g. "Director", "Adviser", "Employee"
	Organisation  string `json:"organisation,omitempty"`
	AddedAt       int64  `json:"added_at"`        // Unix timestamp
	RemovedAt     int64  `json:"removed_at"`      // 0 = still active
	AddedByWallet string `json:"added_by_wallet"` // compliance officer wallet key
	// Reason describes why this person has access to inside information.
	Reason string `json:"reason"`
}

// InsiderList is the per-instrument MAR Article 18 insider list.
// A list is created automatically when a new asset is admitted to trading.
type InsiderList struct {
	AssetID string           `json:"asset_id"`
	Records []*InsiderRecord `json:"records"`
}

// Add appends a new insider record to the list.
func (il *InsiderList) Add(r *InsiderRecord) {
	r.AssetID = il.AssetID
	il.Records = append(il.Records, r)
}

// Remove marks the record with the given ID as removed (soft delete).
// Returns false if no matching active record was found.
func (il *InsiderList) Remove(recordID string, removedAt int64) bool {
	for _, r := range il.Records {
		if r.ID == recordID && r.RemovedAt == 0 {
			r.RemovedAt = removedAt
			return true
		}
	}
	return false
}

// Active returns only currently active (not removed) insider records.
func (il *InsiderList) Active() []*InsiderRecord {
	var out []*InsiderRecord
	for _, r := range il.Records {
		if r.RemovedAt == 0 {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// MAR Article 16 — Suspicious Transaction and Order Reports (STOR)
// ---------------------------------------------------------------------------

// STORCategory classifies the type of market abuse suspected.
// Reference: MAR Article 16; ESMA guidelines on delayed disclosure.
type STORCategory string

const (
	// STORInsiderDealing — suspected trading on inside information (MAR Art 8).
	STORInsiderDealing STORCategory = "insider_dealing"
	// STORMarketManipulation — suspected price distortion or false impression of supply/demand.
	STORMarketManipulation STORCategory = "market_manipulation"
	// STORSpoofing — large orders placed with intent to cancel before execution.
	STORSpoofing STORCategory = "spoofing"
	// STORLayering — stacking multiple orders to create false order book depth.
	STORLayering STORCategory = "layering"
	// STORWashTrading — buyer and seller are economically the same party.
	STORWashTrading STORCategory = "wash_trading"
	// STORFrontRunning — suspected execution ahead of a known large client order.
	STORFrontRunning STORCategory = "front_running"
)

// STORResolution is the outcome of compliance officer review.
type STORResolution string

const (
	STORResolutionPendingReview STORResolution = "pending_review"
	STORResolutionFiledWithNCA  STORResolution = "filed_with_nca"
	STORResolutionDismissed     STORResolution = "dismissed"
	STORResolutionEscalated     STORResolution = "escalated"
)

// STORDraft is a Suspicious Transaction and Order Report pending compliance review.
// Auto-created by pattern detection rules in the order/trade pipeline; filed with
// the NCA by a compliance officer via POST /v1/compliance/stor/{id}/resolve.
//
// Reference: MAR Article 16(1) — obligation applies to market operators; report must
// be filed with the NCA "without delay" once suspicion arises.
type STORDraft struct {
	ID          string         `json:"id"`
	Category    STORCategory   `json:"category"`
	AssetID     string         `json:"asset_id"`
	OrderID     string         `json:"order_id,omitempty"` // the triggering order
	TradeID     string         `json:"trade_id,omitempty"` // the triggering trade, if any
	WalletKey   string         `json:"wallet_key"`         // suspected participant
	Description string         `json:"description"`        // auto-generated + editable
	DetectedAt  int64          `json:"detected_at"`        // Unix timestamp
	Resolution  STORResolution `json:"resolution"`
	ResolvedAt  int64          `json:"resolved_at,omitempty"`
	ResolvedBy  string         `json:"resolved_by,omitempty"` // compliance officer wallet key
	// NCARef is the reference number returned by the NCA upon filing.
	// Populated by the compliance officer when setting Resolution = STORResolutionFiledWithNCA.
	NCARef string `json:"nca_ref,omitempty"`
}

// NewSTORDraft constructs a new STOR draft with a generated ID and DetectedAt timestamp.
func NewSTORDraft(category STORCategory, assetID, orderID, tradeID, walletKey, description string) *STORDraft {
	return &STORDraft{
		ID:          generateID("STOR"),
		Category:    category,
		AssetID:     assetID,
		OrderID:     orderID,
		TradeID:     tradeID,
		WalletKey:   walletKey,
		Description: description,
		DetectedAt:  time.Now().Unix(),
		Resolution:  STORResolutionPendingReview,
	}
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// generateID returns a random prefixed identifier.
// Format: "<prefix>-<16 hex chars>" e.g. "STOR-a3f7b2c19d4e5f6a".
func generateID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// ---------------------------------------------------------------------------
// MarshalJSON helpers (for compliance reports, audit logs)
// ---------------------------------------------------------------------------

// MarshalProspectusExemption returns the exemption as canonical JSON for audit trails.
func (pe *ProspectusExemption) MarshalJSON() ([]byte, error) {
	type Alias ProspectusExemption
	return json.Marshal((*Alias)(pe))
}
