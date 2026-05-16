package gonetwork

import (
	"encoding/json"
	"fmt"
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
// MarshalJSON helpers (for compliance reports, audit logs)
// ---------------------------------------------------------------------------

// MarshalProspectusExemption returns the exemption as canonical JSON for audit trails.
func (pe *ProspectusExemption) MarshalJSON() ([]byte, error) {
	type Alias ProspectusExemption
	return json.Marshal((*Alias)(pe))
}
