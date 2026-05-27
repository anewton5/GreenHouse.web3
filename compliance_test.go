package gonetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const compAssetID = "comp-asset-001"

// newCred builds a CredentialAttestation with the given class and jurisdiction.
func newCred(walletKey string, class InvestorClass, jurisdiction string) *CredentialAttestation {
	return &CredentialAttestation{
		WalletPublicKey: walletKey,
		InvestorClass:   class,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    jurisdiction,
	}
}

// exemptionWith returns a ProspectusExemption pre-loaded with the given retail counts.
func exemptionWith(assetID, jurisdiction string, maxRetail, currentCount int) *ProspectusExemption {
	pe := NewProspectusExemption(assetID, ExemptionProspectusArt1_4, maxRetail, []string{jurisdiction})
	pe.RetailHoldersByJurisdiction[jurisdiction] = currentCount
	return pe
}

// newComplexAsset creates a warrant asset (requires suitability).
func newWarrantAsset(t *testing.T) *Asset {
	t.Helper()
	k := newKey(t)
	a, err := NewAsset(k, AssetTypeWarrant, 1_000, "EUR",
		AssetMetadata{CompanyName: "Acme Warrants", Jurisdiction: "LU"},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return a
}

// newEquityAsset creates a plain equity asset (no suitability required).
func newEquityAsset(t *testing.T) *Asset {
	t.Helper()
	k := newKey(t)
	a, err := NewAsset(k, AssetTypeEquity, 10_000, "GBP",
		AssetMetadata{CompanyName: "Acme Ltd", Jurisdiction: "GB"},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return a
}

func positiveSuitability(walletKey, assetID string, assetType AssetType) *SuitabilityAssessment {
	return &SuitabilityAssessment{
		WalletPublicKey:         walletKey,
		AssetID:                 assetID,
		InstrumentClass:         assetType,
		HasSufficientKnowledge:  true,
		HasSufficientExperience: true,
		CanAbsorbLoss:           true,
		Suitable:                true,
	}
}

func negativeSuitability(walletKey, assetID string, assetType AssetType) *SuitabilityAssessment {
	return &SuitabilityAssessment{
		WalletPublicKey:         walletKey,
		AssetID:                 assetID,
		InstrumentClass:         assetType,
		HasSufficientKnowledge:  false,
		HasSufficientExperience: false,
		CanAbsorbLoss:           false,
		Suitable:                false,
	}
}

// ---------------------------------------------------------------------------
// Prospectus limit tests
// ---------------------------------------------------------------------------

// TestProspectusLimit_UnderCap: 148 existing retail holders → 149th transfer allowed.
func TestProspectusLimit_UnderCap(t *testing.T) {
	pe := exemptionWith(compAssetID, "GB", 149, 148)
	cred := newCred("wallet-gb-149", InvestorClassRetail, "GB")
	err := CheckProspectusLimits(cred, pe)
	assert.NoError(t, err, "148 existing retail holders: 149th should be allowed")
}

// TestProspectusLimit_AtCap: 149 existing retail holders → 150th transfer blocked.
func TestProspectusLimit_AtCap(t *testing.T) {
	pe := exemptionWith(compAssetID, "GB", 149, 149)
	cred := newCred("wallet-gb-150", InvestorClassRetail, "GB")
	err := CheckProspectusLimits(cred, pe)
	assert.Error(t, err, "cap reached: 150th retail investor must be blocked")
}

// TestProspectusLimit_ProfessionalExcluded: professional investor does not count toward cap.
func TestProspectusLimit_ProfessionalExcluded(t *testing.T) {
	pe := exemptionWith(compAssetID, "GB", 149, 149) // GB cap already full
	cred := newCred("wallet-prof", InvestorClassProfessional, "GB")
	err := CheckProspectusLimits(cred, pe)
	assert.NoError(t, err, "professional investor must bypass retail cap")
}

// TestProspectusLimit_PerJurisdiction: GB at cap does not block a DE transfer.
func TestProspectusLimit_PerJurisdiction(t *testing.T) {
	pe := exemptionWith(compAssetID, "GB", 149, 149) // GB full
	// DE has 0 retail holders — should still be allowed
	cred := newCred("wallet-de-1", InvestorClassRetail, "DE")
	err := CheckProspectusLimits(cred, pe)
	assert.NoError(t, err, "GB cap must not block a new DE retail investor")
}

// ---------------------------------------------------------------------------
// Suitability tests
// ---------------------------------------------------------------------------

// TestSuitability_Pass: positive assessment → transfer allowed.
func TestSuitability_Pass(t *testing.T) {
	asset := newWarrantAsset(t)
	walletKey := "wallet-suitability-pass"
	assessments := map[string]*SuitabilityAssessment{
		SuitabilityKey(walletKey, asset.ID): positiveSuitability(walletKey, asset.ID, AssetTypeWarrant),
	}
	err := CheckSuitability(walletKey, asset, assessments)
	assert.NoError(t, err)
}

// TestSuitability_Fail: negative assessment → complex instrument blocked.
func TestSuitability_Fail(t *testing.T) {
	asset := newWarrantAsset(t)
	walletKey := "wallet-suitability-fail"
	assessments := map[string]*SuitabilityAssessment{
		SuitabilityKey(walletKey, asset.ID): negativeSuitability(walletKey, asset.ID, AssetTypeWarrant),
	}
	err := CheckSuitability(walletKey, asset, assessments)
	assert.Error(t, err, "negative suitability must block the transfer")
}

// TestSuitability_Missing: no assessment → complex instrument blocked.
func TestSuitability_Missing(t *testing.T) {
	asset := newWarrantAsset(t)
	walletKey := "wallet-no-assessment"
	assessments := map[string]*SuitabilityAssessment{} // empty
	err := CheckSuitability(walletKey, asset, assessments)
	assert.Error(t, err, "missing assessment must block the complex instrument transfer")
}

// TestSuitability_NotRequired: standard equity → suitability not checked.
func TestSuitability_NotRequired(t *testing.T) {
	asset := newEquityAsset(t)
	walletKey := "wallet-equity-holder"
	assessments := map[string]*SuitabilityAssessment{} // empty — fine for equity
	err := CheckSuitability(walletKey, asset, assessments)
	assert.NoError(t, err, "standard equity must not require suitability assessment")
}

// ---------------------------------------------------------------------------
// JurisdictionRule tests
// ---------------------------------------------------------------------------

// TestJurisdictionRule_MinTicket: transfer below MinTicketSizeEUR blocked.
func TestJurisdictionRule_MinTicket(t *testing.T) {
	asset := newEquityAsset(t)
	rule := &JurisdictionRule{
		CountryCode:      "DE",
		MinTicketSizeEUR: 100_000,
	}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 50_000, 0)
	assert.Error(t, err, "ticket below minimum must be blocked")
}

// TestJurisdictionRule_BlockedAssetType: warrant blocked in given jurisdiction.
func TestJurisdictionRule_BlockedAssetType(t *testing.T) {
	asset := newWarrantAsset(t)
	rule := &JurisdictionRule{
		CountryCode:       "FR",
		BlockedAssetTypes: []AssetType{AssetTypeWarrant},
	}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 200_000, 0)
	assert.Error(t, err, "blocked asset type must be rejected for the jurisdiction")
}

// TestJurisdictionRule_Allowed: transfer that satisfies all rules passes.
func TestJurisdictionRule_Allowed(t *testing.T) {
	asset := newEquityAsset(t)
	rule := &JurisdictionRule{
		CountryCode:      "NL",
		MinTicketSizeEUR: 50_000,
		MaxTicketSizeEUR: 1_000_000,
	}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 200_000, 0)
	assert.NoError(t, err, "valid transfer must pass all jurisdiction rules")
}

// ---------------------------------------------------------------------------
// UpdateRetailCounts tests
// ---------------------------------------------------------------------------

// TestUpdateRetailCounts_Accurate: counts match actual retail holders by jurisdiction.
func TestUpdateRetailCounts_Accurate(t *testing.T) {
	gbRetail1 := "wallet-gb-r1"
	gbRetail2 := "wallet-gb-r2"
	deRetail1 := "wallet-de-r1"
	gbProf := "wallet-gb-prof"

	holdings := map[string]*AssetHolding{
		HoldingKey(gbRetail1, compAssetID): {HolderID: gbRetail1, AssetID: compAssetID, Balance: 100},
		HoldingKey(gbRetail2, compAssetID): {HolderID: gbRetail2, AssetID: compAssetID, Balance: 200},
		HoldingKey(deRetail1, compAssetID): {HolderID: deRetail1, AssetID: compAssetID, Balance: 50},
		HoldingKey(gbProf, compAssetID):    {HolderID: gbProf, AssetID: compAssetID, Balance: 500},
		// Different asset — must not be counted
		HoldingKey(gbRetail1, "other-asset"): {HolderID: gbRetail1, AssetID: "other-asset", Balance: 10},
	}

	credentials := map[string]*CredentialAttestation{
		gbRetail1: newCred(gbRetail1, InvestorClassRetail, "GB"),
		gbRetail2: newCred(gbRetail2, InvestorClassRetail, "GB"),
		deRetail1: newCred(deRetail1, InvestorClassRetail, "DE"),
		gbProf:    newCred(gbProf, InvestorClassProfessional, "GB"),
	}

	pe := NewProspectusExemption(compAssetID, ExemptionProspectusArt1_4, 149, []string{"GB", "DE"})
	UpdateRetailCounts(pe, holdings, credentials)

	assert.Equal(t, 2, pe.RetailHoldersByJurisdiction["GB"], "2 retail holders in GB")
	assert.Equal(t, 1, pe.RetailHoldersByJurisdiction["DE"], "1 retail holder in DE")
	assert.Equal(t, 0, pe.RetailHoldersByJurisdiction["FR"], "0 retail holders in FR")
}

// TestUpdateRetailCounts_ZeroBalance: holder with zero balance not counted.
func TestUpdateRetailCounts_ZeroBalance(t *testing.T) {
	walletKey := "wallet-zero"
	holdings := map[string]*AssetHolding{
		HoldingKey(walletKey, compAssetID): {HolderID: walletKey, AssetID: compAssetID, Balance: 0},
	}
	credentials := map[string]*CredentialAttestation{
		walletKey: newCred(walletKey, InvestorClassRetail, "GB"),
	}
	pe := NewProspectusExemption(compAssetID, ExemptionProspectusArt1_4, 149, []string{"GB"})
	UpdateRetailCounts(pe, holdings, credentials)

	assert.Equal(t, 0, pe.RetailHoldersByJurisdiction["GB"], "zero-balance holder must not be counted")
}
