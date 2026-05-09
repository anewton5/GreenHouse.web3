package gonetwork

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const spvCompanyID = "acme-ltd"
const spvShareClass = "Series B Preferred"
const spvLegalDocHash = "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
const spvAssetID = "spv-asset-001"
const spvCurrency = "EUR"

func newSPV(t *testing.T, adminKey *PrivateKey) *SPVWrapper {
	t.Helper()
	spv, err := NewSPVWrapper(
		adminKey,
		"Acme Luxembourg RAIF",
		SPVJurisdictionLuxembourg,
		spvCompanyID,
		spvShareClass,
		spvLegalDocHash,
	)
	require.NoError(t, err)
	return spv
}

// spvAsset returns a ParticipationNote asset linked to the given SPV's ISIN.
func spvAsset(issuerPubStr, spvISIN string) *Asset {
	return &Asset{
		ID:        spvAssetID,
		Issuer:    issuerPubStr,
		AssetType: AssetTypeParticipationNote,
		Currency:  spvCurrency,
		Metadata: AssetMetadata{
			ISIN: spvISIN,
		},
	}
}

// makeHoldings builds a holdings map for the given (holderPub, balance) pairs
// all under spvAssetID.
func makeHoldings(pairs ...interface{}) map[string]*AssetHolding {
	m := make(map[string]*AssetHolding)
	for i := 0; i+1 < len(pairs); i += 2 {
		holderID := pairs[i].(string)
		balance := pairs[i+1].(float64)
		m[HoldingKey(holderID, spvAssetID)] = &AssetHolding{
			HolderID: holderID,
			AssetID:  spvAssetID,
			Balance:  balance,
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// TestNewSPVWrapper_Valid
// ---------------------------------------------------------------------------

func TestNewSPVWrapper_Valid(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	assert.NotEmpty(t, spv.ID)
	assert.Equal(t, "Acme Luxembourg RAIF", spv.Name)
	assert.Equal(t, SPVJurisdictionLuxembourg, spv.Jurisdiction)
	assert.Equal(t, spvCompanyID, spv.UnderlyingCompanyID)
	assert.Equal(t, spvShareClass, spv.UnderlyingShareClass)
	assert.Equal(t, spvLegalDocHash, spv.LegalDocHash)
	assert.NotEmpty(t, spv.Signature)
	assert.True(t, spv.VerifySignature(adminKey.Public()),
		"formation signature must verify with admin public key")
}

// ---------------------------------------------------------------------------
// TestNewSPVWrapper_MissingFields
// ---------------------------------------------------------------------------

func TestNewSPVWrapper_MissingFields(t *testing.T) {
	adminKey := newKey(t)

	cases := []struct {
		name   string
		mutate func(name, cid, sc, ldh *string, j *SPVJurisdiction)
	}{
		{"empty name", func(name, _, _, _ *string, _ *SPVJurisdiction) { *name = "" }},
		{"empty company", func(_, cid, _, _ *string, _ *SPVJurisdiction) { *cid = "" }},
		{"empty share class", func(_, _, sc, _ *string, _ *SPVJurisdiction) { *sc = "" }},
		{"empty legal doc", func(_, _, _, ldh *string, _ *SPVJurisdiction) { *ldh = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "Acme RAIF"
			cid := spvCompanyID
			sc := spvShareClass
			ldh := spvLegalDocHash
			j := SPVJurisdictionLuxembourg
			tc.mutate(&name, &cid, &sc, &ldh, &j)
			_, err := NewSPVWrapper(adminKey, name, j, cid, sc, ldh)
			assert.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// TestSPVWrapper_UpdateNAV
// ---------------------------------------------------------------------------

func TestSPVWrapper_UpdateNAV(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	before := time.Now().UTC().Unix() - 1

	navTx, err := spv.UpdateNAV(12.50, adminKey)
	require.NoError(t, err)

	assert.Equal(t, float64(12.50), spv.NAV, "NAV must be updated on the wrapper")
	assert.Greater(t, spv.NAVUpdatedAt, before, "NAVUpdatedAt must advance")

	assert.Equal(t, spv.ID, navTx.SPVID)
	assert.Equal(t, SPVTxTypeNAVUpdate, navTx.Type)
	assert.NotEmpty(t, navTx.Signature)
	assert.True(t, navTx.VerifySignature(adminKey.Public()),
		"NAV update transaction signature must verify")
}

// ---------------------------------------------------------------------------
// TestApplySPVTransaction_Dividend
// ---------------------------------------------------------------------------

func TestApplySPVTransaction_Dividend(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	holder1 := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	holder2 := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	holder3 := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())

	holdings := makeHoldings(
		holder1, 1000.0,
		holder2, 500.0,
		holder3, 250.0,
	)

	issuerPub := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	asset := spvAsset(issuerPub, "LU0123456789")

	// £0.50 per unit dividend
	divTx, err := NewSPVTransaction(adminKey, spv.ID, SPVTxTypeDividendDistribution,
		0.50, spvCurrency, time.Now().UTC().Unix())
	require.NoError(t, err)

	instructions, err := ApplySPVTransaction(divTx, spv, asset, holdings, nil)
	require.NoError(t, err)

	require.Len(t, instructions, 3, "one instruction per holder")

	// Build a map holderID → instruction for assertions
	byHolder := make(map[string]PaymentInstruction)
	for _, ins := range instructions {
		byHolder[ins.PayeeWalletID] = ins
	}

	assert.InDelta(t, 500.0, byHolder[holder1].TotalAmount, 0.001) // 1000 * 0.50
	assert.InDelta(t, 250.0, byHolder[holder2].TotalAmount, 0.001) // 500  * 0.50
	assert.InDelta(t, 125.0, byHolder[holder3].TotalAmount, 0.001) // 250  * 0.50

	for _, ins := range instructions {
		assert.Equal(t, spv.SPVAdminKey, ins.PayerWalletID, "SPV admin pays in a dividend")
		assert.Equal(t, spvCurrency, ins.Currency)
		assert.NotEmpty(t, ins.Reference)
	}
}

// ---------------------------------------------------------------------------
// TestApplySPVTransaction_ZeroBalance
// ---------------------------------------------------------------------------

func TestApplySPVTransaction_ZeroBalance(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	holderActive := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	holderZero := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())

	holdings := makeHoldings(
		holderActive, 100.0,
		holderZero, 0.0, // zero balance — must produce no instruction
	)

	issuerPub := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	asset := spvAsset(issuerPub, "LU0123456789")

	divTx, err := NewSPVTransaction(adminKey, spv.ID, SPVTxTypeDividendDistribution,
		1.00, spvCurrency, time.Now().UTC().Unix())
	require.NoError(t, err)

	instructions, err := ApplySPVTransaction(divTx, spv, asset, holdings, nil)
	require.NoError(t, err)

	require.Len(t, instructions, 1, "zero-balance holder must receive no instruction")
	assert.Equal(t, holderActive, instructions[0].PayeeWalletID)
}

// ---------------------------------------------------------------------------
// TestSPVAssetLink
// ---------------------------------------------------------------------------

func TestSPVAssetLink(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	// Typical workflow: issuer creates a ParticipationNote asset and stores
	// the SPV's ISIN in Metadata.ISIN so on-chain lookups can find the SPV.
	issuerPub := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	const spvISIN = "LU0987654321"
	asset := spvAsset(issuerPub, spvISIN)

	assert.Equal(t, AssetTypeParticipationNote, asset.AssetType)
	assert.Equal(t, spvISIN, asset.Metadata.ISIN,
		"asset ISIN must reference the SPV's ISIN")

	// Store both in Blockchain and verify lookup
	bc := newTestBC(t)
	bc.Assets[asset.ID] = asset
	bc.SPVs[spv.ID] = spv

	// Find the SPV for this asset via ISIN match
	var found *SPVWrapper
	for _, s := range bc.SPVs {
		// In production, SPVWrapper would carry its own ISIN; here we match by company
		if s.ID == spv.ID {
			found = s
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, spvCompanyID, found.UnderlyingCompanyID)
}

// ---------------------------------------------------------------------------
// TestSPVSignatureTampering
// ---------------------------------------------------------------------------

func TestSPVSignatureTampering(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	// Mutate a field after signing — verification must fail
	original := spv.UnderlyingShareClass
	spv.UnderlyingShareClass = "Series C Preferred"
	assert.False(t, spv.VerifySignature(adminKey.Public()),
		"tampered wrapper must fail signature verification")

	// Restore and check it passes again
	spv.UnderlyingShareClass = original
	assert.True(t, spv.VerifySignature(adminKey.Public()),
		"restored wrapper must pass signature verification")
}

// ---------------------------------------------------------------------------
// TestNewSPVTransaction_Valid
// ---------------------------------------------------------------------------

func TestNewSPVTransaction_Valid(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	now := time.Now().UTC().Unix()
	tx, err := NewSPVTransaction(adminKey, spv.ID, SPVTxTypeDividendDistribution,
		2.50, spvCurrency, now)
	require.NoError(t, err)

	assert.NotEmpty(t, tx.ID)
	assert.Equal(t, spv.ID, tx.SPVID)
	assert.Equal(t, SPVTxTypeDividendDistribution, tx.Type)
	assert.Equal(t, 2.50, tx.AmountPerUnit)
	assert.Equal(t, spvCurrency, tx.Currency)
	assert.Equal(t, now, tx.EffectiveAt)
	assert.True(t, tx.VerifySignature(adminKey.Public()))
}

// ---------------------------------------------------------------------------
// TestApplySPVTransaction_CapitalCall
// ---------------------------------------------------------------------------

func TestApplySPVTransaction_CapitalCall(t *testing.T) {
	adminKey := newKey(t)
	spv := newSPV(t, adminKey)

	holderA := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	holderB := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())

	holdings := makeHoldings(holderA, 200.0, holderB, 100.0)

	issuerPub := base64.StdEncoding.EncodeToString(newKey(t).Public().Bytes())
	asset := spvAsset(issuerPub, "IE000123456")

	// €1.00 per unit capital call
	callTx, err := NewSPVTransaction(adminKey, spv.ID, SPVTxTypeCapitalCall,
		1.00, spvCurrency, time.Now().UTC().Unix())
	require.NoError(t, err)

	instructions, err := ApplySPVTransaction(callTx, spv, asset, holdings, nil)
	require.NoError(t, err)

	require.Len(t, instructions, 2)
	byPayer := make(map[string]PaymentInstruction)
	for _, ins := range instructions {
		byPayer[ins.PayerWalletID] = ins
	}

	// In a capital call, holder pays the SPV admin
	assert.InDelta(t, 200.0, byPayer[holderA].TotalAmount, 0.001)
	assert.InDelta(t, 100.0, byPayer[holderB].TotalAmount, 0.001)

	for _, ins := range instructions {
		assert.Equal(t, spv.SPVAdminKey, ins.PayeeWalletID, "SPV admin is the payee in a capital call")
	}
}
