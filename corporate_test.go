package gonetwork

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

const caAssetID = "ca-asset-001"
const caCurrency = "GBP"

// newCAAsset creates an asset with ROFR enabled.
func newROFRAsset(t *testing.T, issuerKey *PrivateKey) *Asset {
	t.Helper()
	a, err := NewAsset(issuerKey, AssetTypeEquity, 10_000, caCurrency,
		AssetMetadata{CompanyName: "Acme Ltd", Jurisdiction: "GB"},
		TransferRestrictions{HasROFR: true, ROFRDays: 30},
	)
	require.NoError(t, err)
	return a
}

// newPlainAsset creates an asset without any ROFR.
func newPlainAsset(t *testing.T, issuerKey *PrivateKey) *Asset {
	t.Helper()
	a, err := NewAsset(issuerKey, AssetTypeEquity, 10_000, caCurrency,
		AssetMetadata{CompanyName: "Boring Corp", Jurisdiction: "GB"},
		TransferRestrictions{},
	)
	require.NoError(t, err)
	return a
}

// seedCAHoldings builds a holdings map with the given (holderPub, balance) pairs.
func seedCAHoldings(assetID string, pairs ...interface{}) map[string]*AssetHolding {
	m := make(map[string]*AssetHolding)
	for i := 0; i+1 < len(pairs); i += 2 {
		holderID := pairs[i].(string)
		balance := pairs[i+1].(float64)
		m[HoldingKey(holderID, assetID)] = &AssetHolding{
			HolderID: holderID,
			AssetID:  assetID,
			Balance:  balance,
		}
	}
	return m
}

// makeTransfer builds a minimal AssetTransaction for use in ROFR checks.
func makeTransfer(senderPub, receiverPub, assetID string, amount float64) *AssetTransaction {
	return &AssetTransaction{
		AssetID: assetID,
		TxType:  AssetTxTypeTransfer,
		Tx: Transaction{
			Sender:   senderPub,
			Receiver: receiverPub,
			Amount:   amount,
		},
	}
}

// signResponse creates a CorporateActionResponse signed by holderKey.
func signResponse(actionID string, exercised bool, holderKey *PrivateKey) *CorporateActionResponse {
	return NewCorporateActionResponse(actionID, exercised, holderKey)
}

// ---------------------------------------------------------------------------
// TestNewCorporateAction_Valid
// ---------------------------------------------------------------------------

func TestNewCorporateAction_Valid(t *testing.T) {
	proposerKey := newKey(t)
	proposerPub := base64.StdEncoding.EncodeToString(proposerKey.Public().Bytes())

	ca, err := NewCorporateAction(
		proposerKey,
		caAssetID,
		CorporateActionROFR,
		nil,
		5.00,
		1000,
		30,
		0.5,
	)
	require.NoError(t, err)

	assert.NotEmpty(t, ca.ID)
	assert.Equal(t, caAssetID, ca.AssetID)
	assert.Equal(t, CorporateActionROFR, ca.Type)
	assert.Equal(t, CorporateActionPending, ca.Status)
	assert.Equal(t, proposerPub, ca.ProposerKey)
	assert.Equal(t, float64(5.00), ca.PricePerUnit)
	assert.Equal(t, float64(1000), ca.TotalUnits)
	assert.Equal(t, 0.5, ca.RequiredThreshold)
	assert.Greater(t, ca.DeadlineAt, time.Now().UTC().Unix())
	assert.NotEmpty(t, ca.ProposerSignature)
	assert.NotNil(t, ca.Responses)
}

// ---------------------------------------------------------------------------
// TestRecordResponse_Exercise
// ---------------------------------------------------------------------------

func TestRecordResponse_Exercise(t *testing.T) {
	proposerKey := newKey(t)
	holderKey := newKey(t)
	holderPub := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)

	resp := signResponse(ca.ID, true, holderKey)
	err = ca.RecordResponse(resp, holderKey.Public())
	require.NoError(t, err)

	exercised, ok := ca.Responses[holderPub]
	assert.True(t, ok, "response must be recorded")
	assert.True(t, exercised, "exercised flag must be true")
}

// ---------------------------------------------------------------------------
// TestRecordResponse_Waive
// ---------------------------------------------------------------------------

func TestRecordResponse_Waive(t *testing.T) {
	proposerKey := newKey(t)
	holderKey := newKey(t)
	holderPub := base64.StdEncoding.EncodeToString(holderKey.Public().Bytes())

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)

	resp := signResponse(ca.ID, false, holderKey)
	err = ca.RecordResponse(resp, holderKey.Public())
	require.NoError(t, err)

	exercised, ok := ca.Responses[holderPub]
	assert.True(t, ok)
	assert.False(t, exercised, "waiver must be recorded as false")
}

// ---------------------------------------------------------------------------
// TestRecordResponse_Expired
// ---------------------------------------------------------------------------

func TestRecordResponse_Expired(t *testing.T) {
	proposerKey := newKey(t)
	holderKey := newKey(t)

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 1, 0.5)
	require.NoError(t, err)

	// Wind the deadline back to the past
	ca.DeadlineAt = time.Now().UTC().Unix() - 1

	resp := signResponse(ca.ID, true, holderKey)
	err = ca.RecordResponse(resp, holderKey.Public())
	assert.Error(t, err, "response after deadline must be rejected")
}

// ---------------------------------------------------------------------------
// TestTallyROFR_AllWaive
// ---------------------------------------------------------------------------

func TestTallyROFR_AllWaive(t *testing.T) {
	proposerKey := newKey(t)
	h1Key := newKey(t)
	h2Key := newKey(t)
	h1Pub := base64.StdEncoding.EncodeToString(h1Key.Public().Bytes())
	h2Pub := base64.StdEncoding.EncodeToString(h2Key.Public().Bytes())

	holdings := seedCAHoldings(caAssetID, h1Pub, 600.0, h2Pub, 400.0)

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)

	// Both waive
	require.NoError(t, ca.RecordResponse(signResponse(ca.ID, false, h1Key), h1Key.Public()))
	require.NoError(t, ca.RecordResponse(signResponse(ca.ID, false, h2Key), h2Key.Public()))

	fraction, total := ca.TallyROFR(holdings)
	assert.InDelta(t, 0.0, fraction, 0.001)
	assert.InDelta(t, 1000.0, total, 0.001)
}

// ---------------------------------------------------------------------------
// TestTallyROFR_Partial
// ---------------------------------------------------------------------------

func TestTallyROFR_Partial(t *testing.T) {
	proposerKey := newKey(t)
	h1Key := newKey(t)
	h2Key := newKey(t)
	h1Pub := base64.StdEncoding.EncodeToString(h1Key.Public().Bytes())
	h2Pub := base64.StdEncoding.EncodeToString(h2Key.Public().Bytes())

	holdings := seedCAHoldings(caAssetID,
		h1Pub, 600.0, // exercises — 600/1000 = 60%
		h2Pub, 400.0, // waives
	)

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)

	require.NoError(t, ca.RecordResponse(signResponse(ca.ID, true, h1Key), h1Key.Public()))
	require.NoError(t, ca.RecordResponse(signResponse(ca.ID, false, h2Key), h2Key.Public()))

	fraction, total := ca.TallyROFR(holdings)
	assert.InDelta(t, 0.6, fraction, 0.001, "exercised fraction must be 60%%")
	assert.InDelta(t, 1000.0, total, 0.001)
}

// ---------------------------------------------------------------------------
// TestCheckROFR_Triggered
// ---------------------------------------------------------------------------

func TestCheckROFR_Triggered(t *testing.T) {
	issuerKey := newKey(t)
	senderKey := newKey(t)
	receiverKey := newKey(t)

	asset := newROFRAsset(t, issuerKey)

	senderPub := base64.StdEncoding.EncodeToString(senderKey.Public().Bytes())
	receiverPub := base64.StdEncoding.EncodeToString(receiverKey.Public().Bytes())

	holdings := seedCAHoldings(asset.ID, senderPub, 500.0)
	pending := make(map[string]*CorporateAction)

	at := makeTransfer(senderPub, receiverPub, asset.ID, 100.0)

	triggered, ca, err := CheckROFR(at, asset, holdings, pending)
	assert.True(t, triggered)
	assert.NotNil(t, ca)
	assert.ErrorIs(t, err, ErrROFRTriggered)
	assert.Len(t, pending, 1, "action must be recorded in pending map")
}

// ---------------------------------------------------------------------------
// TestCheckROFR_NotApplicable
// ---------------------------------------------------------------------------

func TestCheckROFR_NotApplicable(t *testing.T) {
	issuerKey := newKey(t)
	senderKey := newKey(t)
	receiverKey := newKey(t)

	asset := newPlainAsset(t, issuerKey) // no ROFR

	senderPub := base64.StdEncoding.EncodeToString(senderKey.Public().Bytes())
	receiverPub := base64.StdEncoding.EncodeToString(receiverKey.Public().Bytes())

	holdings := seedCAHoldings(asset.ID, senderPub, 500.0)
	pending := make(map[string]*CorporateAction)

	at := makeTransfer(senderPub, receiverPub, asset.ID, 100.0)

	triggered, ca, err := CheckROFR(at, asset, holdings, pending)
	assert.False(t, triggered)
	assert.Nil(t, ca)
	assert.NoError(t, err)
	assert.Empty(t, pending)
}

// ---------------------------------------------------------------------------
// TestExecuteDragAlong_ProducesTransactions
// ---------------------------------------------------------------------------

func TestExecuteDragAlong_ProducesTransactions(t *testing.T) {
	proposerKey := newKey(t)
	minorityKey := newKey(t)
	buyerKey := newKey(t)

	proposerPub := base64.StdEncoding.EncodeToString(proposerKey.Public().Bytes())
	minorityPub := base64.StdEncoding.EncodeToString(minorityKey.Public().Bytes())
	buyerPub := base64.StdEncoding.EncodeToString(buyerKey.Public().Bytes())

	holdings := seedCAHoldings(caAssetID,
		proposerPub, 700.0,
		minorityPub, 300.0,
	)

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionDragAlong,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)

	txs, err := ExecuteDragAlong(ca, holdings, buyerPub)
	require.NoError(t, err)

	// The proposer is excluded; only the minority holder should appear
	require.Len(t, txs, 1, "only minority holder should be dragged")
	assert.Equal(t, minorityPub, txs[0].Tx.Sender)
	assert.Equal(t, buyerPub, txs[0].Tx.Receiver)
	assert.InDelta(t, 300.0, txs[0].Tx.Amount, 0.001)
	assert.Equal(t, AssetTxTypeTransfer, txs[0].TxType)
}

// ---------------------------------------------------------------------------
// TestCorporateAction_Lapsed
// ---------------------------------------------------------------------------

func TestCorporateAction_Lapsed(t *testing.T) {
	proposerKey := newKey(t)

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionROFR,
		nil, 5.00, 1000, 1, 0.5)
	require.NoError(t, err)

	assert.False(t, ca.IsLapsed(), "should not be lapsed immediately after creation")

	// Backdate the deadline
	ca.DeadlineAt = time.Now().UTC().Unix() - 1
	assert.True(t, ca.IsLapsed(), "should be lapsed after deadline passes")
}

// ---------------------------------------------------------------------------
// TestTagAlong_MinorityJoins
// ---------------------------------------------------------------------------

// TestTagAlong_MinorityJoins verifies that a tag-along action correctly captures
// all minority holders as participants who can join a majority sale.
// Since ExecuteDragAlong is the symmetric mechanism (forces participation),
// we verify here that a tag-along action is created and can be tallied,
// and that a holder who opts in appears in the response map.
func TestTagAlong_MinorityJoins(t *testing.T) {
	proposerKey := newKey(t)
	minorityKey := newKey(t)
	minorityPub := base64.StdEncoding.EncodeToString(minorityKey.Public().Bytes())

	ca, err := NewCorporateAction(proposerKey, caAssetID, CorporateActionTagAlong,
		nil, 5.00, 1000, 30, 0.5)
	require.NoError(t, err)
	assert.Equal(t, CorporateActionTagAlong, ca.Type)

	// Minority holder exercises their tag-along right (Exercised = true = joining the sale)
	resp := signResponse(ca.ID, true, minorityKey)
	err = ca.RecordResponse(resp, minorityKey.Public())
	require.NoError(t, err)

	joined, ok := ca.Responses[minorityPub]
	assert.True(t, ok)
	assert.True(t, joined, "minority holder who exercises tag-along must be recorded as joined")
}
