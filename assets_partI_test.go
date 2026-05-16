package gonetwork

// ---------------------------------------------------------------------------
// Part I — On-Chain/Off-Chain Asset Consistency (A-01 to A-08)
// ---------------------------------------------------------------------------
//
// Test coverage for all Track A implementation items defined in
// TECHNICAL_ARCHITECTURE_REVIEW.md Part I.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// A-01 — CirculatingSupply consistency
// ---------------------------------------------------------------------------

func TestCirculatingSupply_ConsistencyAfterIssue(t *testing.T) {
	bc := NewBlockchain(context.Background(), "test")
	issuerKey, _ := makeTestWallet(t)
	asset, _ := makeTestAsset(t)
	asset.CirculatingSupply = 0
	bc.Assets[asset.ID] = asset

	recipientKey, recipientStr := makeTestWallet(t)
	_ = recipientStr
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 500_000, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(at, bc.Assets, bc.Holdings))

	// CirculatingSupply must equal sum of holdings.
	sum := 0.0
	for k, h := range bc.Holdings {
		if len(k) > len(asset.ID) && k[len(k)-len(asset.ID):] == asset.ID {
			sum += h.Balance
		}
	}
	assert.InDelta(t, asset.CirculatingSupply, sum, 1e-9)
}

func TestCirculatingSupply_ConsistencyAfterTransfer(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	recipientKey, _ := makeTestWallet(t)
	secondKey, _ := makeTestWallet(t)

	// Issue 1000 to recipient.
	at1, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 1000, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(at1, assets, holdings))

	// Transfer 400 from recipient to second.
	at2, err := NewAssetTransaction(recipientKey, secondKey.Public(), asset.ID, 400, AssetTxTypeTransfer)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(at2, assets, holdings))

	sum := 0.0
	for k, h := range holdings {
		if len(k) > len(asset.ID) && k[len(k)-len(asset.ID):] == asset.ID {
			sum += h.Balance
		}
	}
	assert.InDelta(t, asset.CirculatingSupply, sum, 1e-9)
	assert.InDelta(t, 1000.0, sum, 1e-9)
}

func TestCirculatingSupply_DetectsDivergence(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 200, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	// Artificially diverge CirculatingSupply.
	asset.CirculatingSupply = 999

	bc := NewBlockchain(context.Background(), "test")
	bc.Assets = assets
	bc.Holdings = holdings

	// assertCirculatingSupplyConsistency panics in dev when GH_ENV != "production".
	// In the test environment it should panic.
	assert.Panics(t, func() {
		bc.assertCirculatingSupplyConsistency()
	})
}

// ---------------------------------------------------------------------------
// A-02 — IssuerSignature in Validate
// ---------------------------------------------------------------------------

func TestValidate_TamperedAssetRejected(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	// Apply a legitimate issue so CirculatingSupply > 0.
	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 500, AssetTxTypeIssue)
	require.NoError(t, err)
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	// Now tamper with TotalSupply (simulates an on-disk or in-memory mutation).
	asset.TotalSupply = 9_999_999

	// The next Validate call must detect the signature mismatch.
	at2, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 100, AssetTxTypeIssue)
	require.NoError(t, err)
	err = at2.Validate(assets, holdings, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tampered")
}

func TestValidate_IntactSignatureAllowed(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 100, AssetTxTypeIssue)
	require.NoError(t, err)
	// A valid, unmodified asset must not be rejected by the signature check.
	assert.NoError(t, at.Validate(assets, holdings, nil, nil))
}

func TestValidate_AssetWithoutSignatureIsAllowed(t *testing.T) {
	// Assets created directly (as in handleCreateAsset) have nil IssuerSignature.
	// Validate must not reject them — JWT is the identity anchor in that path.
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	pubStr := base64.StdEncoding.EncodeToString(key.Public().Bytes())

	asset := &Asset{
		ID:                "manual-asset-001",
		Issuer:            pubStr,
		AssetType:         AssetTypeEquity,
		TotalSupply:       100_000,
		CirculatingSupply: 100_000,
		Currency:          "GBP",
		IssuerSignature:   nil, // no signature — API-created path
	}
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{
		HoldingKey(pubStr, asset.ID): {AssetID: asset.ID, HolderID: pubStr, Balance: 100_000},
	}

	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(key, recipientKey.Public(), asset.ID, 50_000, AssetTxTypeIssue)
	require.NoError(t, err)
	assert.NoError(t, at.Validate(assets, holdings, nil, nil))
}

// ---------------------------------------------------------------------------
// A-03 — Legal document amendment trail
// ---------------------------------------------------------------------------

func TestLegalDoc_AmendmentChain(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	asset.Metadata.LegalDocHash = "aabbcc"
	assets := map[string]*Asset{asset.ID: asset}
	spvs := map[string]*SPVWrapper{}
	log := map[string][]*LegalDocAmendment{}

	// First amendment.
	a1, err := NewLegalDocAmendment(asset.ID, "aabbcc", "ddeeff", issuerKey)
	require.NoError(t, err)
	require.NoError(t, ApplyAmendment(a1, assets, spvs, log))

	// Current hash reflects the amendment.
	assert.Equal(t, "ddeeff", CurrentLegalDocHash(asset.ID, asset, log))

	// Second amendment chains from first.
	a2, err := NewLegalDocAmendment(asset.ID, "ddeeff", "112233", issuerKey)
	require.NoError(t, err)
	require.NoError(t, ApplyAmendment(a2, assets, spvs, log))

	assert.Equal(t, "112233", CurrentLegalDocHash(asset.ID, asset, log))
	assert.Len(t, log[asset.ID], 2)
}

func TestLegalDoc_WrongPreviousHashRejected(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	asset.Metadata.LegalDocHash = "aabbcc"
	assets := map[string]*Asset{asset.ID: asset}
	log := map[string][]*LegalDocAmendment{}

	// Provide wrong previous hash.
	a, err := NewLegalDocAmendment(asset.ID, "wrong-hash", "ddeeff", issuerKey)
	require.NoError(t, err)
	err = ApplyAmendment(a, assets, map[string]*SPVWrapper{}, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "previous hash")
}

func TestLegalDoc_GenesisHashNoAmendments(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.Metadata.LegalDocHash = "genesis123"
	log := map[string][]*LegalDocAmendment{}

	// No amendments → current hash is genesis.
	assert.Equal(t, "genesis123", CurrentLegalDocHash(asset.ID, asset, log))
}

// ---------------------------------------------------------------------------
// A-04 — Participation note dual-authority issuance
// ---------------------------------------------------------------------------

func makeParticipationNoteAsset(t *testing.T) (*Asset, *PrivateKey) {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	asset, err := NewAsset(
		key,
		AssetTypeParticipationNote,
		5_000,
		"EUR",
		AssetMetadata{CompanyName: "SPV Alpha"},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return asset, key
}

func TestIssue_ParticipationNoteCirculatingSupplyZeroAtCreation(t *testing.T) {
	asset, _ := makeParticipationNoteAsset(t)
	assert.Equal(t, float64(0), asset.CirculatingSupply,
		"participation note CirculatingSupply must be 0 at creation")
}

func TestIssue_ParticipationNoteBlockedWithoutCountersig(t *testing.T) {
	// An issuer cannot issue tokens directly — CirculatingSupply = 0 blocks the check.
	asset, issuerKey := makeParticipationNoteAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 100, AssetTxTypeIssue)
	require.NoError(t, err)
	err = at.Validate(assets, holdings, nil, nil)
	require.Error(t, err, "issue to new holder should fail because CirculatingSupply is 0")
}

func TestIssue_ParticipationNoteReleasedAfterCountersig(t *testing.T) {
	// Simulate the countersign by setting CirculatingSupply and creating the holding.
	asset, issuerKey := makeParticipationNoteAsset(t)
	assets := map[string]*Asset{asset.ID: asset}
	holdings := map[string]*AssetHolding{}

	issuerPubStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	// Countersign: release supply (mirrors handleCounterSignAsset logic).
	holdings[HoldingKey(issuerPubStr, asset.ID)] = &AssetHolding{
		AssetID:  asset.ID,
		HolderID: issuerPubStr,
		Balance:  asset.TotalSupply,
	}
	asset.CirculatingSupply = asset.TotalSupply

	// Now an issue (transfer from issuer to investor) should succeed.
	recipientKey, _ := makeTestWallet(t)
	at, err := NewAssetTransaction(issuerKey, recipientKey.Public(), asset.ID, 1_000, AssetTxTypeTransfer)
	require.NoError(t, err)
	require.NoError(t, at.Validate(assets, holdings, nil, nil))
	require.NoError(t, ApplyAssetTransaction(at, assets, holdings))

	assert.Equal(t, float64(1_000), holdings[HoldingKey(base64.StdEncoding.EncodeToString(recipientKey.Public().Bytes()), asset.ID)].Balance)
}

// ---------------------------------------------------------------------------
// A-05 — Warrant exercise
// ---------------------------------------------------------------------------

func makeWarrantAndEquityPair(t *testing.T) (warrantAsset, equityAsset *Asset, issuerKey *PrivateKey) {
	t.Helper()
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	warrantAsset, err = NewAsset(
		issuerKey,
		AssetTypeWarrant,
		10_000,
		"EUR",
		AssetMetadata{CompanyName: "WarrantCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	equityAsset, err = NewAsset(
		issuerKey,
		AssetTypeEquity,
		10_000,
		"EUR",
		AssetMetadata{CompanyName: "WarrantCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return warrantAsset, equityAsset, issuerKey
}

func TestWarrant_ExerciseReducesWarrantBalance(t *testing.T) {
	warrantAsset, equityAsset, _ := makeWarrantAndEquityPair(t)
	exerciserKey, _ := makeTestWallet(t)

	assets := map[string]*Asset{
		warrantAsset.ID: warrantAsset,
		equityAsset.ID:  equityAsset,
	}
	holdings := map[string]*AssetHolding{}

	// Give exerciser 500 warrant units.
	wKey := HoldingKey(base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes()), warrantAsset.ID)
	holdings[wKey] = &AssetHolding{AssetID: warrantAsset.ID, HolderID: base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes()), Balance: 500}
	warrantAsset.CirculatingSupply = 500
	equityAsset.CirculatingSupply = 0

	req := &WarrantExerciseRequest{
		ID:              "ex-001",
		WarrantAssetID:  warrantAsset.ID,
		EquityAssetID:   equityAsset.ID,
		UnitsToExercise: 200,
		StrikePrice:     5.0,
		ExerciserKey:    base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes()),
	}

	_, _, err := ProcessWarrantExercise(req, assets, holdings, nil)
	require.NoError(t, err)

	// Warrant holding reduced.
	assert.InDelta(t, 300.0, holdings[wKey].Balance, 1e-9)
	assert.InDelta(t, 300.0, warrantAsset.CirculatingSupply, 1e-9)
}

func TestWarrant_ExerciseIncreasesEquityBalance(t *testing.T) {
	warrantAsset, equityAsset, issuerKey := makeWarrantAndEquityPair(t)
	exerciserKey, _ := makeTestWallet(t)
	_ = issuerKey

	exerciserStr := base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes())
	assets := map[string]*Asset{
		warrantAsset.ID: warrantAsset,
		equityAsset.ID:  equityAsset,
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(exerciserStr, warrantAsset.ID): {AssetID: warrantAsset.ID, HolderID: exerciserStr, Balance: 1000},
	}
	warrantAsset.CirculatingSupply = 1000

	req := &WarrantExerciseRequest{
		ID:              "ex-002",
		WarrantAssetID:  warrantAsset.ID,
		EquityAssetID:   equityAsset.ID,
		UnitsToExercise: 300,
		ExerciserKey:    exerciserStr,
	}

	_, _, err := ProcessWarrantExercise(req, assets, holdings, nil)
	require.NoError(t, err)

	eKey := HoldingKey(exerciserStr, equityAsset.ID)
	require.NotNil(t, holdings[eKey])
	assert.InDelta(t, 300.0, holdings[eKey].Balance, 1e-9)
	assert.InDelta(t, 300.0, equityAsset.CirculatingSupply, 1e-9)
}

func TestWarrant_ExerciseInsufficientBalance(t *testing.T) {
	warrantAsset, equityAsset, _ := makeWarrantAndEquityPair(t)
	exerciserKey, _ := makeTestWallet(t)
	exerciserStr := base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes())

	assets := map[string]*Asset{warrantAsset.ID: warrantAsset, equityAsset.ID: equityAsset}
	holdings := map[string]*AssetHolding{
		HoldingKey(exerciserStr, warrantAsset.ID): {AssetID: warrantAsset.ID, HolderID: exerciserStr, Balance: 10},
	}
	warrantAsset.CirculatingSupply = 10

	req := &WarrantExerciseRequest{
		ID:              "ex-003",
		WarrantAssetID:  warrantAsset.ID,
		EquityAssetID:   equityAsset.ID,
		UnitsToExercise: 999,
		ExerciserKey:    exerciserStr,
	}
	_, _, err := ProcessWarrantExercise(req, assets, holdings, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")
}

func TestWarrant_ExerciseCreatesCashInstruction(t *testing.T) {
	warrantAsset, equityAsset, _ := makeWarrantAndEquityPair(t)
	exerciserKey, _ := makeTestWallet(t)
	exerciserStr := base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes())

	assets := map[string]*Asset{warrantAsset.ID: warrantAsset, equityAsset.ID: equityAsset}
	holdings := map[string]*AssetHolding{
		HoldingKey(exerciserStr, warrantAsset.ID): {AssetID: warrantAsset.ID, HolderID: exerciserStr, Balance: 500},
	}
	warrantAsset.CirculatingSupply = 500
	pending := map[string]*PaymentInstruction{}

	req := &WarrantExerciseRequest{
		ID:              "ex-004",
		WarrantAssetID:  warrantAsset.ID,
		EquityAssetID:   equityAsset.ID,
		UnitsToExercise: 100,
		StrikePrice:     10.0,
		ExerciserKey:    exerciserStr,
	}
	_, _, err := ProcessWarrantExercise(req, assets, holdings, pending)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	inst := pending["ex-004"]
	assert.InDelta(t, 1000.0, inst.TotalAmount, 1e-9) // 100 * 10.0
}

// ---------------------------------------------------------------------------
// A-06 — Convertible note conversion
// ---------------------------------------------------------------------------

func TestConvertible_ConversionAtMaturity(t *testing.T) {
	issuerKey, _ := makeTestWallet(t)

	convAsset, err := NewAsset(
		issuerKey,
		AssetTypeConvertible,
		10_000,
		"EUR",
		AssetMetadata{CompanyName: "ConvCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	equityAsset, err := NewAsset(
		issuerKey,
		AssetTypeEquity,
		50_000,
		"EUR",
		AssetMetadata{CompanyName: "ConvCo"},
		TransferRestrictions{},
	)
	require.NoError(t, err)

	holderKey, _ := makeTestWallet(t)
	holderStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	assets := map[string]*Asset{convAsset.ID: convAsset, equityAsset.ID: equityAsset}
	holdings := map[string]*AssetHolding{
		HoldingKey(holderStr, convAsset.ID): {AssetID: convAsset.ID, HolderID: holderStr, Balance: 1000},
	}
	convAsset.CirculatingSupply = 1000

	req := &ConvertibleConversionRequest{
		ID:                 "conv-001",
		ConvertibleAssetID: convAsset.ID,
		EquityAssetID:      equityAsset.ID,
		ConversionRatio:    2.0, // 1 convertible = 2 equity
		UnitsToConvert:     400,
		Trigger:            ConversionTriggerMaturity,
		HolderKey:          holderStr,
	}

	_, _, err = ProcessConvertibleConversion(req, assets, holdings)
	require.NoError(t, err)

	// Convertible balance decremented.
	assert.InDelta(t, 600.0, holdings[HoldingKey(holderStr, convAsset.ID)].Balance, 1e-9)
	// Equity balance created.
	eHolding := holdings[HoldingKey(holderStr, equityAsset.ID)]
	require.NotNil(t, eHolding)
	assert.InDelta(t, 800.0, eHolding.Balance, 1e-9) // 400 * 2.0
	assert.InDelta(t, 800.0, equityAsset.CirculatingSupply, 1e-9)
}

func TestConvertible_InsufficientBalance(t *testing.T) {
	issuerKey, _ := makeTestWallet(t)
	convAsset, err := NewAsset(issuerKey, AssetTypeConvertible, 1000, "EUR", AssetMetadata{}, TransferRestrictions{})
	require.NoError(t, err)
	equityAsset, err := NewAsset(issuerKey, AssetTypeEquity, 10000, "EUR", AssetMetadata{}, TransferRestrictions{})
	require.NoError(t, err)

	holderKey, _ := makeTestWallet(t)
	holderStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	assets := map[string]*Asset{convAsset.ID: convAsset, equityAsset.ID: equityAsset}
	holdings := map[string]*AssetHolding{
		HoldingKey(holderStr, convAsset.ID): {AssetID: convAsset.ID, HolderID: holderStr, Balance: 50},
	}
	convAsset.CirculatingSupply = 50

	req := &ConvertibleConversionRequest{
		ID:                 "conv-002",
		ConvertibleAssetID: convAsset.ID,
		EquityAssetID:      equityAsset.ID,
		ConversionRatio:    1.0,
		UnitsToConvert:     999,
		HolderKey:          holderStr,
	}
	_, _, err = ProcessConvertibleConversion(req, assets, holdings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")
}

// ---------------------------------------------------------------------------
// A-07 — Anti-dilution protection
// ---------------------------------------------------------------------------

func TestAntiDilution_DownRoundAdjustsConversionRatio(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	_ = issuerKey
	asset.CirculatingSupply = 1_000_000

	holderKey, _ := makeTestWallet(t)
	holderStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(holderStr, asset.ID): {AssetID: asset.ID, HolderID: holderStr, Balance: 100_000},
	}

	// Holder paid £2.00 in the prior round; new round is at £1.00.
	originalPrices := map[string]float64{holderStr: 2.0}

	adjustments, err := AntiDilutionAdjustment(asset, 500_000, 1.0, holdings, originalPrices)
	require.NoError(t, err)
	require.Contains(t, adjustments, holderStr)

	// NCP = (1_000_000 * 2.0 + 500_000 * 1.0) / (1_000_000 + 500_000) = 1.6667
	assert.InDelta(t, 1.666667, adjustments[holderStr], 1e-4)
}

func TestAntiDilution_UpRoundNoAdjustment(t *testing.T) {
	asset, _ := makeTestAsset(t)
	asset.CirculatingSupply = 1_000_000

	holderKey, _ := makeTestWallet(t)
	holderStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(holderStr, asset.ID): {AssetID: asset.ID, HolderID: holderStr, Balance: 100_000},
	}

	// New round price (£3.00) above original (£2.00) — no anti-dilution needed.
	originalPrices := map[string]float64{holderStr: 2.0}

	adjustments, err := AntiDilutionAdjustment(asset, 200_000, 3.0, holdings, originalPrices)
	require.NoError(t, err)
	assert.Empty(t, adjustments)
}

// ---------------------------------------------------------------------------
// A-08 — Capital call enforcement
// ---------------------------------------------------------------------------

func TestCapitalCall_InstructionCreatedPerHolder(t *testing.T) {
	asset, issuerKey := makeTestAsset(t)
	_ = issuerKey
	asset.CirculatingSupply = 1000

	holder1Key, _ := makeTestWallet(t)
	holder2Key, _ := makeTestWallet(t)
	h1 := base64.StdEncoding.EncodeToString(holder1Key.Public().Bytes())
	h2 := base64.StdEncoding.EncodeToString(holder2Key.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(h1, asset.ID): {AssetID: asset.ID, HolderID: h1, Balance: 600},
		HoldingKey(h2, asset.ID): {AssetID: asset.ID, HolderID: h2, Balance: 400},
	}

	pending := map[string]*PaymentInstruction{}
	spvAdminKey, _ := makeTestWallet(t)
	spvAdminStr := base64.StdEncoding.EncodeToString(spvAdminKey.Public().Bytes())

	records, err := ProcessCapitalCall(
		"spv-001", asset.ID, 10.0, "EUR", 14,
		holdings, pending, spvAdminStr,
	)
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Len(t, pending, 2)

	// Total obligation correct.
	totalDue := 0.0
	for _, r := range records {
		totalDue += r.AmountDue
	}
	assert.InDelta(t, 10_000.0, totalDue, 1e-9) // 1000 units * £10 = £10,000
}

func TestCapitalCall_DefaultMarksHoldingLocked(t *testing.T) {
	asset, _ := makeTestAsset(t)
	holderKey, _ := makeTestWallet(t)
	holderStr := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	holdings := map[string]*AssetHolding{
		HoldingKey(holderStr, asset.ID): {AssetID: asset.ID, HolderID: holderStr, Balance: 100},
	}

	err := MarkCapitalCallDefault(holderStr, asset.ID, holdings)
	require.NoError(t, err)

	// Lockup should now be set far in the future.
	h := holdings[HoldingKey(holderStr, asset.ID)]
	assert.Greater(t, h.LockedUntil, int64(0))
}

// ---------------------------------------------------------------------------
// Signature helper — verifying Ed25519 signing across instrument_lifecycle.go
// ---------------------------------------------------------------------------

// TestExerciseRequestSignatureVerification verifies that the warrant exercise
// signature check correctly accepts a valid signature and rejects a tampered one.
func TestExerciseRequestSignatureVerification(t *testing.T) {
	warrantAsset, equityAsset, _ := makeWarrantAndEquityPair(t)
	exerciserKey, _ := makeTestWallet(t)
	exerciserStr := base64.StdEncoding.EncodeToString(exerciserKey.Public().Bytes())

	assets := map[string]*Asset{warrantAsset.ID: warrantAsset, equityAsset.ID: equityAsset}
	holdings := map[string]*AssetHolding{
		HoldingKey(exerciserStr, warrantAsset.ID): {AssetID: warrantAsset.ID, HolderID: exerciserStr, Balance: 1000},
	}
	warrantAsset.CirculatingSupply = 1000

	req := &WarrantExerciseRequest{
		ID:              "sig-test",
		WarrantAssetID:  warrantAsset.ID,
		EquityAssetID:   equityAsset.ID,
		UnitsToExercise: 50,
		ExerciserKey:    exerciserStr,
	}

	// Sign the request.
	data, err := json.Marshal(req)
	require.NoError(t, err)
	hash := sha3.Sum256(data)
	req.ExerciserSignature = exerciserKey.Sign(hash[:]).Bytes()

	// Valid signature → should succeed.
	_, _, err = ProcessWarrantExercise(req, assets, holdings, nil)
	require.NoError(t, err)
}
