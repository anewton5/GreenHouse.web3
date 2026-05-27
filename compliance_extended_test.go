package gonetwork

// ---------------------------------------------------------------------------
// compliance_extended_test.go
//
// Covers:
//   ProspectusExemption.RecordSettlement  — idempotency, rolling total
//   CheckProspectusValueThreshold         — QIB bypass, over-threshold error
//   CheckProspectusLimits                 — nil exemption, no credential, cap
//   UpdateRetailCounts                    — builds correct per-jurisdiction map
//   InsiderList.Add / Active / Remove     — lifecycle, soft-delete, unknown ID
//   NewSTORDraft                          — fields set correctly, unique IDs
//   generateID                            — prefix format, uniqueness
//   NewProspectusExemption                — initial state
//   CheckSuitability                      — complex instruments, missing / negative
//   ApplyJurisdictionRule                 — blocked type, ticket size bounds
// ---------------------------------------------------------------------------

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ProspectusExemption.RecordSettlement
// ---------------------------------------------------------------------------

func TestRecordSettlement_AccumulatesValue(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.RecordSettlement("trade-1", 100_000)
	pe.RecordSettlement("trade-2", 200_000)
	assert.InDelta(t, 300_000.0, pe.TwelveMonthEURValue, 0.01)
}

func TestRecordSettlement_Idempotent(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.RecordSettlement("trade-1", 100_000)
	pe.RecordSettlement("trade-1", 100_000) // duplicate — must not double-count
	assert.InDelta(t, 100_000.0, pe.TwelveMonthEURValue, 0.01)
}

func TestRecordSettlement_NilMap_InitialisesMap(t *testing.T) {
	pe := &ProspectusExemption{OfferingValueByTradeID: nil}
	pe.RecordSettlement("trade-1", 50_000)
	require.NotNil(t, pe.OfferingValueByTradeID)
	assert.InDelta(t, 50_000.0, pe.TwelveMonthEURValue, 0.01)
}

// ---------------------------------------------------------------------------
// CheckProspectusValueThreshold
// ---------------------------------------------------------------------------

func TestCheckProspectusValueThreshold_BelowLimit_OK(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.TwelveMonthEURValue = 1_000_000
	err := CheckProspectusValueThreshold(pe, 500_000)
	assert.NoError(t, err)
}

func TestCheckProspectusValueThreshold_AtLimit_OK(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.TwelveMonthEURValue = 7_000_000
	// Exactly at 8M — not over
	err := CheckProspectusValueThreshold(pe, 1_000_000)
	assert.NoError(t, err)
}

func TestCheckProspectusValueThreshold_OverLimit_Error(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.TwelveMonthEURValue = 7_500_000
	err := CheckProspectusValueThreshold(pe, 1_000_000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "€8M")
}

func TestCheckProspectusValueThreshold_NilExemption_NoError(t *testing.T) {
	err := CheckProspectusValueThreshold(nil, 1_000_000)
	assert.NoError(t, err)
}

func TestCheckProspectusValueThreshold_QIBOnly_NoError(t *testing.T) {
	// QIB-only exemptions have no value cap
	pe := NewProspectusExemption("asset-1", ExemptionQIBOnly, 0, nil)
	pe.TwelveMonthEURValue = 100_000_000
	err := CheckProspectusValueThreshold(pe, 50_000_000)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// CheckProspectusLimits
// ---------------------------------------------------------------------------

func TestCheckProspectusLimits_NilExemption_NoError(t *testing.T) {
	cred := &CredentialAttestation{InvestorClass: InvestorClassRetail, Jurisdiction: "DE"}
	err := CheckProspectusLimits(cred, nil)
	assert.NoError(t, err)
}

func TestCheckProspectusLimits_NilCredential_Error(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	err := CheckProspectusLimits(nil, pe)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential")
}

func TestCheckProspectusLimits_ProfessionalInvestor_OK(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	// Force cap breach condition for retail
	pe.RetailHoldersByJurisdiction["DE"] = 149
	cred := &CredentialAttestation{InvestorClass: InvestorClassProfessional, Jurisdiction: "DE"}
	err := CheckProspectusLimits(cred, pe)
	assert.NoError(t, err, "professional investors don't count against retail cap")
}

func TestCheckProspectusLimits_RetailBelowCap_OK(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.RetailHoldersByJurisdiction["FR"] = 100
	cred := &CredentialAttestation{InvestorClass: InvestorClassRetail, Jurisdiction: "FR"}
	err := CheckProspectusLimits(cred, pe)
	assert.NoError(t, err)
}

func TestCheckProspectusLimits_RetailAtCap_Error(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)
	pe.RetailHoldersByJurisdiction["FR"] = 149
	cred := &CredentialAttestation{InvestorClass: InvestorClassRetail, Jurisdiction: "FR"}
	err := CheckProspectusLimits(cred, pe)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "149/149")
}

// ---------------------------------------------------------------------------
// UpdateRetailCounts
// ---------------------------------------------------------------------------

func TestUpdateRetailCounts_BuildsCorrectMap(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)

	holdings := map[string]*AssetHolding{
		"h1": {HolderID: "wallet-a", AssetID: "asset-1", Balance: 100},
		"h2": {HolderID: "wallet-b", AssetID: "asset-1", Balance: 50},
		"h3": {HolderID: "wallet-c", AssetID: "asset-1", Balance: 200},
		"h4": {HolderID: "wallet-d", AssetID: "other-asset", Balance: 10},
	}

	credentials := map[string]*CredentialAttestation{
		"wallet-a": {InvestorClass: InvestorClassRetail, Jurisdiction: "DE"},
		"wallet-b": {InvestorClass: InvestorClassRetail, Jurisdiction: "FR"},
		"wallet-c": {InvestorClass: InvestorClassProfessional, Jurisdiction: "DE"}, // not counted
		"wallet-d": {InvestorClass: InvestorClassRetail, Jurisdiction: "DE"},       // wrong asset
	}

	UpdateRetailCounts(pe, holdings, credentials)

	assert.Equal(t, 1, pe.RetailHoldersByJurisdiction["DE"])
	assert.Equal(t, 1, pe.RetailHoldersByJurisdiction["FR"])
}

func TestUpdateRetailCounts_ZeroBalanceExcluded(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)

	holdings := map[string]*AssetHolding{
		"h1": {HolderID: "wallet-a", AssetID: "asset-1", Balance: 0},
	}
	credentials := map[string]*CredentialAttestation{
		"wallet-a": {InvestorClass: InvestorClassRetail, Jurisdiction: "IT"},
	}

	UpdateRetailCounts(pe, holdings, credentials)
	assert.Equal(t, 0, pe.RetailHoldersByJurisdiction["IT"])
}

func TestUpdateRetailCounts_UnknownCredential_Excluded(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionProspectusArt1_4, 149, nil)

	holdings := map[string]*AssetHolding{
		"h1": {HolderID: "wallet-unknown", AssetID: "asset-1", Balance: 100},
	}
	credentials := map[string]*CredentialAttestation{}

	UpdateRetailCounts(pe, holdings, credentials)
	assert.Empty(t, pe.RetailHoldersByJurisdiction)
}

// ---------------------------------------------------------------------------
// InsiderList
// ---------------------------------------------------------------------------

func TestInsiderList_Add_Active(t *testing.T) {
	il := &InsiderList{AssetID: "asset-1"}
	r := &InsiderRecord{ID: "ins-001", FullName: "Jane Doe", Role: "Director"}
	il.Add(r)

	active := il.Active()
	require.Len(t, active, 1)
	assert.Equal(t, "Jane Doe", active[0].FullName)
	assert.Equal(t, "asset-1", active[0].AssetID, "Add must stamp AssetID")
}

func TestInsiderList_Remove_ExistingRecord(t *testing.T) {
	il := &InsiderList{AssetID: "asset-2"}
	il.Add(&InsiderRecord{ID: "ins-001", FullName: "John Smith"})

	now := time.Now().Unix()
	ok := il.Remove("ins-001", now)
	assert.True(t, ok)
	assert.Empty(t, il.Active())
}

func TestInsiderList_Remove_UnknownID_ReturnsFalse(t *testing.T) {
	il := &InsiderList{AssetID: "asset-3"}
	ok := il.Remove("ghost-id", time.Now().Unix())
	assert.False(t, ok)
}

func TestInsiderList_Remove_AlreadyRemoved_ReturnsFalse(t *testing.T) {
	il := &InsiderList{AssetID: "asset-4"}
	il.Add(&InsiderRecord{ID: "ins-001", FullName: "Test Person"})
	now := time.Now().Unix()
	il.Remove("ins-001", now)

	// Second remove returns false — already stamped
	ok := il.Remove("ins-001", now+1)
	assert.False(t, ok)
}

func TestInsiderList_Active_ExcludesRemoved(t *testing.T) {
	il := &InsiderList{AssetID: "asset-5"}
	il.Add(&InsiderRecord{ID: "ins-001", FullName: "Active Person"})
	il.Add(&InsiderRecord{ID: "ins-002", FullName: "Removed Person"})
	il.Remove("ins-002", time.Now().Unix())

	active := il.Active()
	require.Len(t, active, 1)
	assert.Equal(t, "Active Person", active[0].FullName)
}

func TestInsiderList_MultipleActiveThenRemoveAll(t *testing.T) {
	il := &InsiderList{AssetID: "asset-6"}
	for i := 0; i < 5; i++ {
		il.Add(&InsiderRecord{ID: strings.Repeat("x", i+1), FullName: "Person"})
	}
	assert.Len(t, il.Active(), 5)

	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		il.Remove(strings.Repeat("x", i+1), now)
	}
	assert.Empty(t, il.Active())
}

// ---------------------------------------------------------------------------
// NewSTORDraft
// ---------------------------------------------------------------------------

func TestNewSTORDraft_FieldsSetCorrectly(t *testing.T) {
	d := NewSTORDraft(
		STORInsiderDealing,
		"asset-001",
		"order-001",
		"trade-001",
		"wallet-abc",
		"Suspected insider dealing detected",
	)

	require.NotNil(t, d)
	assert.Equal(t, STORInsiderDealing, d.Category)
	assert.Equal(t, "asset-001", d.AssetID)
	assert.Equal(t, "order-001", d.OrderID)
	assert.Equal(t, "trade-001", d.TradeID)
	assert.Equal(t, "wallet-abc", d.WalletKey)
	assert.Equal(t, STORResolutionPendingReview, d.Resolution)
	assert.Greater(t, d.DetectedAt, int64(0))
	assert.NotEmpty(t, d.ID)
	assert.True(t, strings.HasPrefix(d.ID, "STOR-"), "ID should have STOR- prefix")
}

func TestNewSTORDraft_UniqueIDs(t *testing.T) {
	d1 := NewSTORDraft(STORMarketManipulation, "a", "", "", "w", "desc")
	d2 := NewSTORDraft(STORMarketManipulation, "a", "", "", "w", "desc")
	assert.NotEqual(t, d1.ID, d2.ID, "each draft must get a unique ID")
}

// ---------------------------------------------------------------------------
// generateID
// ---------------------------------------------------------------------------

func TestGenerateID_PrefixAndLength(t *testing.T) {
	id := generateID("TEST")
	assert.True(t, strings.HasPrefix(id, "TEST-"))
	// "TEST-" (5) + 16 hex chars = 21 chars minimum
	assert.GreaterOrEqual(t, len(id), 21)
}

func TestGenerateID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID("ID")
		assert.False(t, seen[id], "generateID must return unique IDs")
		seen[id] = true
	}
}

// ---------------------------------------------------------------------------
// NewProspectusExemption
// ---------------------------------------------------------------------------

func TestNewProspectusExemption_InitialState(t *testing.T) {
	pe := NewProspectusExemption("asset-1", ExemptionPilotRegime, 149, []string{"DE", "FR"})
	assert.Equal(t, "asset-1", pe.AssetID)
	assert.Equal(t, ExemptionPilotRegime, pe.Basis)
	assert.Equal(t, 149, pe.MaxRetailPerJurisdiction)
	assert.Equal(t, []string{"DE", "FR"}, pe.JurisdictionCoverage)
	assert.NotNil(t, pe.RetailHoldersByJurisdiction)
	assert.InDelta(t, 0.0, pe.TwelveMonthEURValue, 0.01)
}

// ---------------------------------------------------------------------------
// CheckSuitability
// ---------------------------------------------------------------------------

func TestCheckSuitability_NonComplexAsset_OK(t *testing.T) {
	asset := &Asset{ID: "bond-001", AssetType: AssetTypeDebt}
	err := CheckSuitability("wallet-key", asset, nil)
	assert.NoError(t, err, "non-complex assets skip suitability check")
}

func TestCheckSuitability_ComplexAsset_NoAssessment_Error(t *testing.T) {
	asset := &Asset{ID: "warrant-001", AssetType: AssetTypeWarrant}
	err := CheckSuitability("wallet-key", asset, map[string]*SuitabilityAssessment{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suitability assessment required")
}

func TestCheckSuitability_ComplexAsset_NegativeAssessment_Error(t *testing.T) {
	asset := &Asset{ID: "conv-001", AssetType: AssetTypeConvertible}
	assessments := map[string]*SuitabilityAssessment{
		SuitabilityKey("wallet-key", "conv-001"): {Suitable: false},
	}
	err := CheckSuitability("wallet-key", asset, assessments)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestCheckSuitability_ComplexAsset_PositiveAssessment_OK(t *testing.T) {
	asset := &Asset{ID: "warrant-002", AssetType: AssetTypeWarrant}
	assessments := map[string]*SuitabilityAssessment{
		SuitabilityKey("wallet-key", "warrant-002"): {Suitable: true},
	}
	err := CheckSuitability("wallet-key", asset, assessments)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ApplyJurisdictionRule
// ---------------------------------------------------------------------------

func TestApplyJurisdictionRule_NilRule_NoError(t *testing.T) {
	asset := &Asset{ID: "asset-1", AssetType: AssetTypeEquity}
	err := ApplyJurisdictionRule(nil, nil, nil, asset, 1000, 0)
	assert.NoError(t, err)
}

func TestApplyJurisdictionRule_BlockedAssetType_Error(t *testing.T) {
	rule := &JurisdictionRule{
		CountryCode:       "US",
		BlockedAssetTypes: []AssetType{AssetTypeEquity},
	}
	asset := &Asset{ID: "equity-001", AssetType: AssetTypeEquity}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 1000, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestApplyJurisdictionRule_BelowMinTicket_Error(t *testing.T) {
	rule := &JurisdictionRule{CountryCode: "DE", MinTicketSizeEUR: 10_000}
	asset := &Asset{ID: "bond-001", AssetType: AssetTypeDebt}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 5_000, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestApplyJurisdictionRule_AboveMaxTicket_Error(t *testing.T) {
	rule := &JurisdictionRule{CountryCode: "FR", MaxTicketSizeEUR: 100_000}
	asset := &Asset{ID: "bond-001", AssetType: AssetTypeDebt}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 200_000, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestApplyJurisdictionRule_ValidTicketSize_NoError(t *testing.T) {
	rule := &JurisdictionRule{
		CountryCode:      "IT",
		MinTicketSizeEUR: 1_000,
		MaxTicketSizeEUR: 100_000,
	}
	asset := &Asset{ID: "bond-001", AssetType: AssetTypeDebt}
	err := ApplyJurisdictionRule(rule, nil, nil, asset, 50_000, 0)
	assert.NoError(t, err)
}
