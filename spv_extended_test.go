package gonetwork

// ---------------------------------------------------------------------------
// spv_extended_test.go
//
// Full lifecycle tests for the SPV module (private placement vehicle layer):
//   NewSPVWrapper          — construction, validation, signature
//   VerifySignature        — valid, tampered
//   SPVDeterministicID     — deterministic output
//   UpdateNAV              — generates signed NAV-update SPVTransaction
//   NewSPVTransaction      — dividend, capital call, winding-up, NAV update
//   SPVTransaction.VerifySignature — valid, tampered
//   ApplySPVTransaction    — dividend → PaymentInstructions, capital call
//   ProcessCapitalCall     — per-holder records + PaymentInstructions
//   MarkCapitalCallDefault — locks holding for 10 years
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSPVAdmin(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

func newTestSPV(t *testing.T, admin *PrivateKey) *SPVWrapper {
	t.Helper()
	spv, err := NewSPVWrapper(
		admin,
		"Acme Series B SPV",
		SPVJurisdictionLuxembourg,
		"acme-ltd",
		"Series B Preferred",
		"abc123def456",
	)
	require.NoError(t, err)
	return spv
}

// ---------------------------------------------------------------------------
// NewSPVWrapper — constructor
// ---------------------------------------------------------------------------

func TestNewSPVWrapper_ValidIreland(t *testing.T) {
	admin := newSPVAdmin(t)
	spv, err := NewSPVWrapper(admin, "Fund I", SPVJurisdictionIreland, "startup-ltd", "Series A", "docHash1")
	require.NoError(t, err)
	require.NotNil(t, spv)
	assert.NotEmpty(t, spv.ID)
	assert.Equal(t, "Fund I", spv.Name)
	assert.Equal(t, SPVJurisdictionIreland, spv.Jurisdiction)
	assert.Equal(t, "startup-ltd", spv.UnderlyingCompanyID)
	assert.NotEmpty(t, spv.Signature)
}

func TestNewSPVWrapper_EmptyName_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	_, err := NewSPVWrapper(admin, "", SPVJurisdictionLuxembourg, "co", "class", "hash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestNewSPVWrapper_EmptyCompany_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	_, err := NewSPVWrapper(admin, "Fund", SPVJurisdictionLuxembourg, "", "class", "hash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "underlyingCompanyID")
}

func TestNewSPVWrapper_EmptyShareClass_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	_, err := NewSPVWrapper(admin, "Fund", SPVJurisdictionLuxembourg, "co", "", "hash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "underlyingShareClass")
}

func TestNewSPVWrapper_EmptyLegalDocHash_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	_, err := NewSPVWrapper(admin, "Fund", SPVJurisdictionLuxembourg, "co", "class", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legalDocHash")
}

// ---------------------------------------------------------------------------
// SPVDeterministicID
// ---------------------------------------------------------------------------

func TestSPVDeterministicID_Deterministic(t *testing.T) {
	admin := newSPVAdmin(t)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())

	id1 := SPVDeterministicID(adminPub, "Fund I", "LU", "startup-ltd")
	id2 := SPVDeterministicID(adminPub, "Fund I", "LU", "startup-ltd")
	assert.Equal(t, id1, id2, "same inputs must produce same ID")
}

func TestSPVDeterministicID_DifferentNameProducesDifferentID(t *testing.T) {
	admin := newSPVAdmin(t)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())

	id1 := SPVDeterministicID(adminPub, "Fund I", "LU", "startup-ltd")
	id2 := SPVDeterministicID(adminPub, "Fund II", "LU", "startup-ltd")
	assert.NotEqual(t, id1, id2)
}

func TestSPVDeterministicID_MatchesNewSPVWrapperID(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())

	computedID := SPVDeterministicID(adminPub, spv.Name, string(spv.Jurisdiction), spv.UnderlyingCompanyID)
	assert.Equal(t, spv.ID, computedID)
}

// ---------------------------------------------------------------------------
// SPVWrapper.VerifySignature
// ---------------------------------------------------------------------------

func TestSPVWrapperVerifySignature_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	assert.True(t, spv.VerifySignature(admin.Public()))
}

func TestSPVWrapperVerifySignature_WrongKey_False(t *testing.T) {
	admin := newSPVAdmin(t)
	other := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	assert.False(t, spv.VerifySignature(other.Public()))
}

func TestSPVWrapperVerifySignature_TamperedName_False(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	spv.Name = "Tampered Name"
	assert.False(t, spv.VerifySignature(admin.Public()))
}

// ---------------------------------------------------------------------------
// UpdateNAV
// ---------------------------------------------------------------------------

func TestUpdateNAV_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)

	tx, err := spv.UpdateNAV(125.50, admin)
	require.NoError(t, err)
	require.NotNil(t, tx)
	assert.Equal(t, SPVTxTypeNAVUpdate, tx.Type)
	assert.Equal(t, 125.50, spv.NAV)
	assert.NotEmpty(t, tx.Signature)
	assert.True(t, tx.VerifySignature(admin.Public()))
}

func TestUpdateNAV_NegativeNAV_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	_, err := spv.UpdateNAV(-1.0, admin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-negative")
}

func TestUpdateNAV_ZeroNAV_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	_, err := spv.UpdateNAV(0, admin)
	require.NoError(t, err)
	assert.Equal(t, 0.0, spv.NAV)
}

// ---------------------------------------------------------------------------
// NewSPVTransaction — dividend, capital call, NAV update, winding-up
// ---------------------------------------------------------------------------

func TestNewSPVTransaction_Dividend_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, err := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 2.50, "EUR", time.Now().Unix())
	require.NoError(t, err)
	assert.Equal(t, SPVTxTypeDividendDistribution, tx.Type)
	assert.Equal(t, 2.50, tx.AmountPerUnit)
	assert.Equal(t, "EUR", tx.Currency)
	assert.True(t, tx.VerifySignature(admin.Public()))
}

func TestNewSPVTransaction_CapitalCall_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, err := NewSPVTransaction(admin, spv.ID, SPVTxTypeCapitalCall, 5.0, "GBP", time.Now().Unix())
	require.NoError(t, err)
	assert.Equal(t, SPVTxTypeCapitalCall, tx.Type)
}

func TestNewSPVTransaction_NAVUpdate_NoCurrencyRequired(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, err := NewSPVTransaction(admin, spv.ID, SPVTxTypeNAVUpdate, 0, "", time.Now().Unix())
	require.NoError(t, err)
	assert.Equal(t, SPVTxTypeNAVUpdate, tx.Type)
}

func TestNewSPVTransaction_NoCurrencyForDividend_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	_, err := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 1.0, "", time.Now().Unix())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "currency")
}

func TestNewSPVTransaction_EmptySPVID_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	_, err := NewSPVTransaction(admin, "", SPVTxTypeDividendDistribution, 1.0, "EUR", time.Now().Unix())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spvID")
}

func TestNewSPVTransaction_NegativeAmountForCapitalCall_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	_, err := NewSPVTransaction(admin, spv.ID, SPVTxTypeCapitalCall, -1.0, "EUR", time.Now().Unix())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "amountPerUnit")
}

// ---------------------------------------------------------------------------
// SPVTransaction.VerifySignature
// ---------------------------------------------------------------------------

func TestSPVTransactionVerifySignature_Valid(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 1.0, "EUR", time.Now().Unix())
	assert.True(t, tx.VerifySignature(admin.Public()))
}

func TestSPVTransactionVerifySignature_WrongKey_False(t *testing.T) {
	admin := newSPVAdmin(t)
	other := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 1.0, "EUR", time.Now().Unix())
	assert.False(t, tx.VerifySignature(other.Public()))
}

func TestSPVTransactionVerifySignature_TamperedAmount_False(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	tx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 1.0, "EUR", time.Now().Unix())
	tx.AmountPerUnit = 999.9
	assert.False(t, tx.VerifySignature(admin.Public()))
}

// ---------------------------------------------------------------------------
// ApplySPVTransaction — dividend
// ---------------------------------------------------------------------------

func TestApplySPVTransaction_Dividend_GeneratesInstructions(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())
	spv.SPVAdminKey = adminPub

	asset := &Asset{ID: "spv-note", AssetType: AssetTypeParticipationNote}

	investor1Key := newSPVAdmin(t)
	investor2Key := newSPVAdmin(t)
	inv1 := base64.StdEncoding.EncodeToString(investor1Key.Public().Bytes())
	inv2 := base64.StdEncoding.EncodeToString(investor2Key.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(inv1, "spv-note"): {AssetID: "spv-note", HolderID: inv1, Balance: 100},
		HoldingKey(inv2, "spv-note"): {AssetID: "spv-note", HolderID: inv2, Balance: 50},
	}

	spvTx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 2.0, "EUR", time.Now().Unix())
	instructions, err := ApplySPVTransaction(spvTx, spv, asset, holdings, nil)
	require.NoError(t, err)
	require.Len(t, instructions, 2)

	// Verify amounts: investor1 = 100 × 2.0 = 200; investor2 = 50 × 2.0 = 100
	totalAmount := 0.0
	for _, instr := range instructions {
		assert.Equal(t, "EUR", instr.Currency)
		assert.Equal(t, adminPub, instr.PayerWalletID)
		totalAmount += instr.TotalAmount
	}
	assert.InDelta(t, 300.0, totalAmount, 0.001)
}

func TestApplySPVTransaction_CapitalCall_SwappedPayerPayee(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())
	spv.SPVAdminKey = adminPub

	asset := &Asset{ID: "spv-note", AssetType: AssetTypeParticipationNote}
	investor := newSPVAdmin(t)
	invPub := base64.StdEncoding.EncodeToString(investor.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(invPub, "spv-note"): {AssetID: "spv-note", HolderID: invPub, Balance: 200},
	}

	spvTx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeCapitalCall, 5.0, "EUR", time.Now().Unix())
	instructions, err := ApplySPVTransaction(spvTx, spv, asset, holdings, nil)
	require.NoError(t, err)
	require.Len(t, instructions, 1)

	// For capital call: investor pays SPV admin
	assert.Equal(t, invPub, instructions[0].PayerWalletID)
	assert.Equal(t, adminPub, instructions[0].PayeeWalletID)
	assert.InDelta(t, 1000.0, instructions[0].TotalAmount, 0.001) // 200 × 5.0
}

func TestApplySPVTransaction_NAVUpdate_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	asset := &Asset{ID: "spv-note"}
	spvTx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeNAVUpdate, 0, "", time.Now().Unix())
	_, err := ApplySPVTransaction(spvTx, spv, asset, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dividend")
}

func TestApplySPVTransaction_NilAsset_Error(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	spvTx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 1.0, "EUR", time.Now().Unix())
	_, err := ApplySPVTransaction(spvTx, spv, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "asset")
}

func TestApplySPVTransaction_ZeroBalance_Excluded(t *testing.T) {
	admin := newSPVAdmin(t)
	spv := newTestSPV(t, admin)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())
	spv.SPVAdminKey = adminPub

	asset := &Asset{ID: "spv-note"}
	investor := newSPVAdmin(t)
	invPub := base64.StdEncoding.EncodeToString(investor.Public().Bytes())
	holdings := map[string]*AssetHolding{
		HoldingKey(invPub, "spv-note"): {AssetID: "spv-note", HolderID: invPub, Balance: 0},
	}

	spvTx, _ := NewSPVTransaction(admin, spv.ID, SPVTxTypeDividendDistribution, 2.0, "EUR", time.Now().Unix())
	instructions, err := ApplySPVTransaction(spvTx, spv, asset, holdings, nil)
	require.NoError(t, err)
	assert.Empty(t, instructions)
}

// ---------------------------------------------------------------------------
// ProcessCapitalCall
// ---------------------------------------------------------------------------

func TestProcessCapitalCall_CreatesRecordsAndInstructions(t *testing.T) {
	admin := newSPVAdmin(t)
	adminPub := base64.StdEncoding.EncodeToString(admin.Public().Bytes())

	investor1 := newSPVAdmin(t)
	investor2 := newSPVAdmin(t)
	inv1Pub := base64.StdEncoding.EncodeToString(investor1.Public().Bytes())
	inv2Pub := base64.StdEncoding.EncodeToString(investor2.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(inv1Pub, "spv-note"): {AssetID: "spv-note", HolderID: inv1Pub, Balance: 100},
		HoldingKey(inv2Pub, "spv-note"): {AssetID: "spv-note", HolderID: inv2Pub, Balance: 50},
	}

	pending := make(map[string]*PaymentInstruction)
	records, err := ProcessCapitalCall("spv-id-001", "spv-note", 10.0, "EUR", 14, holdings, pending, adminPub)
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Len(t, pending, 2)

	// Verify amounts and deadlines
	for _, record := range records {
		assert.Equal(t, CapitalCallStatusPending, record.Status)
		assert.Greater(t, record.AmountDue, 0.0)
		assert.NotEmpty(t, record.PaymentRef)
	}
}

func TestProcessCapitalCall_EmptySPVID_Error(t *testing.T) {
	_, err := ProcessCapitalCall("", "spv-note", 10.0, "EUR", 14, nil, nil, "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spvID")
}

func TestProcessCapitalCall_EmptyAssetID_Error(t *testing.T) {
	_, err := ProcessCapitalCall("spv1", "", 10.0, "EUR", 14, nil, nil, "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assetID")
}

func TestProcessCapitalCall_ZeroAmountPerUnit_Error(t *testing.T) {
	_, err := ProcessCapitalCall("spv1", "asset1", 0, "EUR", 14, nil, nil, "admin")
	require.Error(t, err)
}

func TestProcessCapitalCall_EmptyCurrency_Error(t *testing.T) {
	_, err := ProcessCapitalCall("spv1", "asset1", 5.0, "", 14, nil, nil, "admin")
	require.Error(t, err)
}

func TestProcessCapitalCall_DefaultDeadline_14Days(t *testing.T) {
	investor := newSPVAdmin(t)
	invPub := base64.StdEncoding.EncodeToString(investor.Public().Bytes())
	holdings := map[string]*AssetHolding{
		HoldingKey(invPub, "note"): {AssetID: "note", HolderID: invPub, Balance: 100},
	}
	records, err := ProcessCapitalCall("spv1", "note", 5.0, "EUR", 0, holdings, nil, "admin")
	require.NoError(t, err)
	require.Len(t, records, 1)
	expectedDeadline := time.Now().Unix() + 14*86400
	assert.InDelta(t, expectedDeadline, records[0].DeadlineAt, 5)
}

// ---------------------------------------------------------------------------
// MarkCapitalCallDefault
// ---------------------------------------------------------------------------

func TestMarkCapitalCallDefault_SetsLockup(t *testing.T) {
	investor := newSPVAdmin(t)
	invPub := base64.StdEncoding.EncodeToString(investor.Public().Bytes())
	holdings := map[string]*AssetHolding{
		HoldingKey(invPub, "spv-note"): {AssetID: "spv-note", HolderID: invPub, Balance: 100},
	}

	require.NoError(t, MarkCapitalCallDefault(invPub, "spv-note", holdings))
	h := holdings[HoldingKey(invPub, "spv-note")]
	// 10-year lockup
	tenYears := time.Now().Unix() + int64(10*365*24*3600)
	assert.InDelta(t, tenYears, h.LockedUntil, 10)
}

func TestMarkCapitalCallDefault_MissingHolding_Error(t *testing.T) {
	err := MarkCapitalCallDefault("unknown-key", "spv-note", map[string]*AssetHolding{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no holding")
}
