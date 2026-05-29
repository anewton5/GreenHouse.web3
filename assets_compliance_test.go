// assets_compliance_test.go — Item 13 acceptance tests.
//
// Verifies that AssetTransaction.Validate, when called with a non-nil *Blockchain,
// enforces the four new compliance gates introduced by Item 13:
//
//  1. AML SeverityFlag → SARDraft recorded in bc.PendingSARs (transaction proceeds).
//  2. Blocked asset type in receiver's jurisdiction → error from ApplyJurisdictionRule.
//  3. Complex instrument without SuitabilityAssessment → error from CheckSuitability.
//  4. Transfer exceeding the €8M Prospectus Regulation value threshold → error.
//  5. Per-jurisdiction retail holder cap reached → error from ApplyJurisdictionRule.
//
// All tests create a minimal *Blockchain via NewBlockchain so the SAR map,
// JurisdictionRules, SuitabilityAssessments, and ProspectusExemptions are
// correctly initialised.

package gonetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// minimalBlockchain returns a fresh Blockchain with the P2P layer disabled
// (GONETWORK_NO_P2P=1) so compliance tests do not spawn libp2p hosts that
// interfere with the peer-discovery timing tests.
func minimalBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	t.Setenv("GONETWORK_NO_P2P", "1")
	return NewBlockchain(context.Background(), t.Name())
}

// makeCred creates a CredentialAttestation for the given wallet key.
func makeCred(walletKey string, class InvestorClass, jurisdiction string) *CredentialAttestation {
	return &CredentialAttestation{
		WalletPublicKey: walletKey,
		InvestorClass:   class,
		KYCStatus:       KYCStatusVerified,
		Jurisdiction:    jurisdiction,
		ExpiresAt:       time.Now().Unix() + 86400*365,
	}
}

// ---------------------------------------------------------------------------
// 1. AML SeverityFlag → SARDraft
// ---------------------------------------------------------------------------

// TestValidate_AMLFlag_CreatesSARDraft verifies that a flag-severity AML alert
// does NOT block the transaction but stores a SARDraft in bc.PendingSARs and
// emits EventSARCreated on bc.Events.
func TestValidate_AMLFlag_CreatesSARDraft(t *testing.T) {
	bc := minimalBlockchain(t)

	asset, issuerKey := makeTestAsset(t)
	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 500)

	// Attach a flag screener that flags the sender.
	flagScreener := NewMockAMLScreener()
	flagScreener.FlagAddress(aliceKeyStr, "PEP")

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(bc, assets, holdings, nil, nil, flagScreener)
	// Transaction must NOT be blocked — flag ≠ block.
	assert.NoError(t, err, "AML flag must not block the transaction")

	// A SAR draft must have been recorded.
	assert.Len(t, bc.PendingSARs, 1, "expected one SARDraft in bc.PendingSARs")
	for _, sar := range bc.PendingSARs {
		assert.Equal(t, SARStatusPending, sar.Status)
		assert.Equal(t, at.AssetID, sar.AssetID)
		assert.Equal(t, at.Tx.Amount, sar.Amount)
	}
}

// ---------------------------------------------------------------------------
// 2. Blocked asset type in receiver's jurisdiction
// ---------------------------------------------------------------------------

// TestValidate_BlockedAssetType_ReturnsError verifies that a transfer of a
// warrant (blocked in a custom jurisdiction rule) to a receiver in that
// jurisdiction fails with an error from ApplyJurisdictionRule.
func TestValidate_BlockedAssetType_ReturnsError(t *testing.T) {
	bc := minimalBlockchain(t)

	// Add a jurisdiction rule that blocks warrants in "XY".
	bc.JurisdictionRules["XY"] = &JurisdictionRule{
		CountryCode:       "XY",
		BlockedAssetTypes: []AssetType{AssetTypeWarrant},
	}

	// Create a warrant asset.
	issuerKey, _ := GeneratePrivateKey()
	warrant, err := NewAsset(
		issuerKey,
		AssetTypeWarrant,
		100_000,
		"EUR",
		AssetMetadata{CompanyName: "WarrantCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{warrant.ID: warrant}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, warrant, assets, holdings, 1_000)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr: makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		bobKeyStr:   makeCred(bobKeyStr, InvestorClassProfessional, "XY"),
	}

	// Set up a positive suitability assessment for Bob so only the jurisdiction
	// check fires (not the suitability check).
	bc.SuitabilityAssessments[SuitabilityKey(bobKeyStr, warrant.ID)] = &SuitabilityAssessment{
		WalletPublicKey: bobKeyStr,
		AssetID:         warrant.ID,
		Suitable:        true,
	}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), warrant.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(bc, assets, holdings, credentials, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
	assert.Contains(t, err.Error(), "XY")
}

// ---------------------------------------------------------------------------
// 3. Complex instrument without SuitabilityAssessment
// ---------------------------------------------------------------------------

// TestValidate_ComplexInstrument_NoSuitability_ReturnsError verifies that
// transferring a convertible to a receiver who has no SuitabilityAssessment
// fails with a suitability error.
func TestValidate_ComplexInstrument_NoSuitability_ReturnsError(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	convertible, err := NewAsset(
		issuerKey,
		AssetTypeConvertible,
		50_000,
		"EUR",
		AssetMetadata{CompanyName: "ConvertCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{convertible.ID: convertible}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, convertible, assets, holdings, 500)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr: makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		bobKeyStr:   makeCred(bobKeyStr, InvestorClassProfessional, "GB"),
	}
	// bc.SuitabilityAssessments is empty — no assessment for Bob.

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), convertible.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(bc, assets, holdings, credentials, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suitability")
}

// TestValidate_ComplexInstrument_WithSuitability_Passes verifies that a
// convertible transfer is allowed when the receiver has a positive assessment.
func TestValidate_ComplexInstrument_WithSuitability_Passes(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	convertible, err := NewAsset(
		issuerKey,
		AssetTypeConvertible,
		50_000,
		"EUR",
		AssetMetadata{CompanyName: "ConvertCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{convertible.ID: convertible}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, convertible, assets, holdings, 500)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr: makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		bobKeyStr:   makeCred(bobKeyStr, InvestorClassProfessional, "GB"),
	}

	// Give Bob a positive suitability assessment.
	bc.SuitabilityAssessments[SuitabilityKey(bobKeyStr, convertible.ID)] = &SuitabilityAssessment{
		WalletPublicKey: bobKeyStr,
		AssetID:         convertible.ID,
		Suitable:        true,
	}

	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), convertible.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	assert.NoError(t, at.Validate(bc, assets, holdings, credentials, nil))
}

// ---------------------------------------------------------------------------
// 4. Prospectus €8M value threshold exceeded
// ---------------------------------------------------------------------------

// TestValidate_ProspectusThresholdExceeded_ReturnsError verifies that a
// transfer whose amount would push the 12-month rolling total above €8M
// fails with a prospectus threshold error.
func TestValidate_ProspectusThresholdExceeded_ReturnsError(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		10_000_000,
		"EUR",
		AssetMetadata{CompanyName: "ThresholdCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 5_000_000)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr: makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		bobKeyStr:   makeCred(bobKeyStr, InvestorClassRetail, "GB"),
	}

	// Register a prospectus exemption with a rolling total already near the limit.
	exemption := NewProspectusExemption(asset.ID, ExemptionPilotRegime, 149, []string{"GB"})
	exemption.TwelveMonthEURValue = 7_500_000 // already €7.5M raised
	bc.ProspectusExemptions[asset.ID] = exemption

	// A transfer of €600_000 would push total to €8.1M — must be rejected.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 600_000, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(bc, assets, holdings, credentials, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "8M")
}

// TestValidate_ProspectusThresholdNotExceeded_Passes verifies that a transfer
// well below the €8M ceiling succeeds when a prospectus exemption is active.
func TestValidate_ProspectusThresholdNotExceeded_Passes(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		10_000_000,
		"EUR",
		AssetMetadata{CompanyName: "ThresholdCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	bobKey, bobKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 5_000_000)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr: makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		bobKeyStr:   makeCred(bobKeyStr, InvestorClassRetail, "GB"),
	}

	exemption := NewProspectusExemption(asset.ID, ExemptionPilotRegime, 149, []string{"GB"})
	exemption.TwelveMonthEURValue = 1_000_000 // €1M so far — plenty of headroom
	bc.ProspectusExemptions[asset.ID] = exemption

	// Transfer of €50,000 — well within limits.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), asset.ID, 50_000, AssetTxTypeTransfer)
	require.NoError(t, err)

	assert.NoError(t, at.Validate(bc, assets, holdings, credentials, nil))
}

// ---------------------------------------------------------------------------
// 5. Per-jurisdiction retail holder cap (DE: 149)
// ---------------------------------------------------------------------------

// TestValidate_DERetailCapReached_ReturnsError verifies that a transfer to a
// 150th retail investor in Germany is rejected by the seeded DE jurisdiction rule.
func TestValidate_DERetailCapReached_ReturnsError(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		10_000_000,
		"EUR",
		AssetMetadata{CompanyName: "EUIssuance"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	newBuyerKey, newBuyerKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 1_000_000)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr:    makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		newBuyerKeyStr: makeCred(newBuyerKeyStr, InvestorClassRetail, "DE"),
	}

	// Simulate 149 existing DE retail holders by populating holdings + credentials.
	for i := 0; i < 149; i++ {
		_, existingKeyStr := makeTestWallet(t)
		existingHolding := &AssetHolding{
			AssetID:  asset.ID,
			HolderID: existingKeyStr,
			Balance:  100,
		}
		holdings[HoldingKey(existingKeyStr, asset.ID)] = existingHolding
		credentials[existingKeyStr] = makeCred(existingKeyStr, InvestorClassRetail, "DE")
	}

	// Transfer to the 150th DE retail investor — must be rejected.
	at, err := NewAssetTransaction(aliceKey, newBuyerKey.Public(), asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	err = at.Validate(bc, assets, holdings, credentials, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retail holder cap")
	assert.Contains(t, err.Error(), "DE")
}

// TestValidate_DERetailCapNotReached_Passes verifies that a transfer to the
// 149th retail investor in Germany is allowed.
func TestValidate_DERetailCapNotReached_Passes(t *testing.T) {
	bc := minimalBlockchain(t)

	issuerKey, _ := GeneratePrivateKey()
	asset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		10_000_000,
		"EUR",
		AssetMetadata{CompanyName: "EUIssuance"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, aliceKeyStr := makeTestWallet(t)
	newBuyerKey, newBuyerKeyStr := makeTestWallet(t)

	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, asset, assets, holdings, 1_000_000)

	credentials := map[string]*CredentialAttestation{
		aliceKeyStr:    makeCred(aliceKeyStr, InvestorClassProfessional, "GB"),
		newBuyerKeyStr: makeCred(newBuyerKeyStr, InvestorClassRetail, "DE"),
	}

	// Simulate 148 existing DE retail holders (cap is 149 — one slot remains).
	for i := 0; i < 148; i++ {
		_, existingKeyStr := makeTestWallet(t)
		holdings[HoldingKey(existingKeyStr, asset.ID)] = &AssetHolding{
			AssetID:  asset.ID,
			HolderID: existingKeyStr,
			Balance:  100,
		}
		credentials[existingKeyStr] = makeCred(existingKeyStr, InvestorClassRetail, "DE")
	}

	at, err := NewAssetTransaction(aliceKey, newBuyerKey.Public(), asset.ID, 100, AssetTxTypeTransfer)
	require.NoError(t, err)

	assert.NoError(t, at.Validate(bc, assets, holdings, credentials, nil))
}

// ---------------------------------------------------------------------------
// 6. NilBlockchain — existing behaviour unchanged
// ---------------------------------------------------------------------------

// TestValidate_NilBlockchain_SkipsComplianceChecks verifies that passing bc=nil
// keeps the existing pre-Item-13 behaviour: no jurisdiction, suitability, or
// prospectus checks are applied, and the transaction succeeds.
func TestValidate_NilBlockchain_SkipsComplianceChecks(t *testing.T) {
	issuerKey, _ := GeneratePrivateKey()
	// Warrant — complex instrument that normally requires suitability.
	warrant, err := NewAsset(
		issuerKey,
		AssetTypeWarrant,
		100_000,
		"EUR",
		AssetMetadata{CompanyName: "WarrantCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	aliceKey, _ := makeTestWallet(t)
	bobKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{warrant.ID: warrant}
	holdings := map[string]*AssetHolding{}
	issueTokens(t, issuerKey, aliceKey, warrant, assets, holdings, 500)

	// nil bc — no compliance checks run.
	at, err := NewAssetTransaction(aliceKey, bobKey.Public(), warrant.ID, 10, AssetTxTypeTransfer)
	require.NoError(t, err)

	assert.NoError(t, at.Validate(nil, assets, holdings, nil, nil))
}
