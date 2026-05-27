package gonetwork

// ---------------------------------------------------------------------------
// corporate_extended_test.go
//
// Full lifecycle tests for all private-placement corporate governance actions:
//   NewCorporateAction   — construction + validation
//   RecordResponse       — valid response, wrong key, lapsed action
//   TallyROFR            — fraction computation across holder map
//   NewCorporateActionResponse — signed response construction
//   CheckROFR            — triggered / not-triggered paths
//   ExecuteDragAlong     — generates minority-holder transfer txs
//   CorporateActionDividend / TagAlong actions
// ---------------------------------------------------------------------------

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

// makeCorpKey generates a keyed test identity with a readable label.
func makeCorpKey(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

// makeROFRAsset creates an equity asset with ROFR enabled.
func makeROFRAsset() *Asset {
	return &Asset{
		ID:        "acme-equity",
		AssetType: AssetTypeEquity,
		Currency:  "GBP",
		Restrictions: TransferRestrictions{
			HasROFR:  true,
			ROFRDays: 14,
		},
	}
}

// makeCAHoldings returns a small holder map for asset "acme-equity".
func makeCAHoldings(holders map[string]float64) map[string]*AssetHolding {
	m := make(map[string]*AssetHolding)
	for holderID, balance := range holders {
		key := HoldingKey(holderID, "acme-equity")
		m[key] = &AssetHolding{
			AssetID:  "acme-equity",
			HolderID: holderID,
			Balance:  balance,
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// NewCorporateAction
// ---------------------------------------------------------------------------

func TestNewCorporateAction_EmptyAssetID_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	_, err := NewCorporateAction(proposer, "", CorporateActionROFR, nil, 0, 0, 1, 0.5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assetID")
}

func TestNewCorporateAction_ZeroDeadlineDays_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	_, err := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 0, 0, 0, 0.5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deadlineDays")
}

func TestNewCorporateAction_InvalidThreshold_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	_, err := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 0, 0, 1, 0.0)
	require.Error(t, err)

	_, err2 := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 0, 0, 1, 1.5)
	require.Error(t, err2)
}

func TestNewCorporateAction_DragAlong_Type(t *testing.T) {
	proposer := makeCorpKey(t)
	ca, err := NewCorporateAction(proposer, "acme-equity", CorporateActionDragAlong, nil, 15.0, 10000, 30, 0.75)
	require.NoError(t, err)
	assert.Equal(t, CorporateActionDragAlong, ca.Type)
	assert.Equal(t, float64(10000), ca.TotalUnits)
	assert.Equal(t, float64(15.0), ca.PricePerUnit)
}

// ---------------------------------------------------------------------------
// IsLapsed
// ---------------------------------------------------------------------------

func TestCorporateAction_IsLapsed_Future(t *testing.T) {
	ca := &CorporateAction{DeadlineAt: time.Now().Add(24 * time.Hour).Unix()}
	assert.False(t, ca.IsLapsed())
}

func TestCorporateAction_IsLapsed_Past(t *testing.T) {
	ca := &CorporateAction{DeadlineAt: time.Now().Add(-1 * time.Hour).Unix()}
	assert.True(t, ca.IsLapsed())
}

// ---------------------------------------------------------------------------
// RecordResponse
// ---------------------------------------------------------------------------

func TestRecordResponse_Valid_Exercised(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)

	resp := NewCorporateActionResponse(ca.ID, true, holder)
	err := ca.RecordResponse(resp, holder.Public())
	require.NoError(t, err)

	holderPub := base64.StdEncoding.EncodeToString(holder.Public().Bytes())
	exercised, ok := ca.Responses[holderPub]
	require.True(t, ok)
	assert.True(t, exercised)
}

func TestRecordResponse_Valid_Waived(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)

	resp := NewCorporateActionResponse(ca.ID, false, holder)
	require.NoError(t, ca.RecordResponse(resp, holder.Public()))

	holderPub := base64.StdEncoding.EncodeToString(holder.Public().Bytes())
	exercised, ok := ca.Responses[holderPub]
	require.True(t, ok)
	assert.False(t, exercised)
}

func TestRecordResponse_WrongKey_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	holder1 := makeCorpKey(t)
	holder2 := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)

	// Response says holder1's key but we supply holder2's public key
	resp := NewCorporateActionResponse(ca.ID, true, holder1)
	err := ca.RecordResponse(resp, holder2.Public())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HolderKey")
}

func TestRecordResponse_Lapsed_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)
	ca.DeadlineAt = time.Now().Add(-1 * time.Hour).Unix() // force lapsed

	resp := NewCorporateActionResponse(ca.ID, true, holder)
	err := ca.RecordResponse(resp, holder.Public())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lapsed")
}

func TestRecordResponse_NonPendingStatus_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)
	ca.Status = CorporateActionApproved

	resp := NewCorporateActionResponse(ca.ID, true, holder)
	err := ca.RecordResponse(resp, holder.Public())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not pending")
}

func TestRecordResponse_TamperedSignature_Error(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 500, 14, 0.5)

	resp := NewCorporateActionResponse(ca.ID, true, holder)
	resp.Exercised = false // tamper after signing
	err := ca.RecordResponse(resp, holder.Public())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
}

// ---------------------------------------------------------------------------
// TallyROFR
// ---------------------------------------------------------------------------

func TestTallyROFR_AllExercised(t *testing.T) {
	proposer := makeCorpKey(t)
	holder1 := makeCorpKey(t)
	holder2 := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 0, 14, 0.5)

	pub1 := base64.StdEncoding.EncodeToString(holder1.Public().Bytes())
	pub2 := base64.StdEncoding.EncodeToString(holder2.Public().Bytes())
	ca.Responses[pub1] = true
	ca.Responses[pub2] = true

	holdings := makeCAHoldings(map[string]float64{pub1: 600, pub2: 400})
	fraction, total := ca.TallyROFR(holdings)
	assert.InDelta(t, 1.0, fraction, 0.001)
	assert.InDelta(t, 1000.0, total, 0.001)
}

func TestTallyROFR_HalfExercised(t *testing.T) {
	proposer := makeCorpKey(t)
	holder1 := makeCorpKey(t)
	holder2 := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 0, 14, 0.5)

	pub1 := base64.StdEncoding.EncodeToString(holder1.Public().Bytes())
	pub2 := base64.StdEncoding.EncodeToString(holder2.Public().Bytes())
	ca.Responses[pub1] = true  // exercised
	ca.Responses[pub2] = false // waived

	holdings := makeCAHoldings(map[string]float64{pub1: 500, pub2: 500})
	fraction, total := ca.TallyROFR(holdings)
	assert.InDelta(t, 0.5, fraction, 0.001)
	assert.InDelta(t, 1000.0, total, 0.001)
}

func TestTallyROFR_EmptyHoldings_ReturnsZero(t *testing.T) {
	proposer := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 0, 14, 0.5)
	fraction, total := ca.TallyROFR(map[string]*AssetHolding{})
	assert.Equal(t, 0.0, fraction)
	assert.Equal(t, 0.0, total)
}

func TestTallyROFR_OtherAsset_Excluded(t *testing.T) {
	proposer := makeCorpKey(t)
	holder := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 10, 0, 14, 0.5)
	pub := base64.StdEncoding.EncodeToString(holder.Public().Bytes())
	ca.Responses[pub] = true

	// Holdings are for a different asset — should not count
	holdings := map[string]*AssetHolding{
		HoldingKey(pub, "other-asset"): {
			AssetID:  "other-asset",
			HolderID: pub,
			Balance:  1000,
		},
	}
	fraction, total := ca.TallyROFR(holdings)
	assert.Equal(t, 0.0, fraction)
	assert.Equal(t, 0.0, total)
}

// ---------------------------------------------------------------------------
// CheckROFR
// ---------------------------------------------------------------------------

func TestCheckROFR_NoRestriction_NotTriggered(t *testing.T) {
	asset := &Asset{ID: "acme-equity", AssetType: AssetTypeEquity, Restrictions: TransferRestrictions{HasROFR: false}}
	at := &AssetTransaction{AssetID: "acme-equity", TxType: AssetTxTypeTransfer, Tx: Transaction{Sender: "pub1", Amount: 100}}
	triggered, _, err := CheckROFR(at, asset, nil, nil)
	require.NoError(t, err)
	assert.False(t, triggered)
}

func TestCheckROFR_WithRestriction_Triggered(t *testing.T) {
	asset := makeROFRAsset()
	at := &AssetTransaction{
		AssetID: "acme-equity",
		TxType:  AssetTxTypeTransfer,
		Tx:      Transaction{Sender: "pub1", Receiver: "pub2", Amount: 200},
	}
	pending := make(map[string]*CorporateAction)
	triggered, ca, err := CheckROFR(at, asset, nil, pending)

	require.ErrorIs(t, err, ErrROFRTriggered)
	assert.True(t, triggered)
	require.NotNil(t, ca)
	assert.Equal(t, CorporateActionROFR, ca.Type)
	assert.Equal(t, CorporateActionPending, ca.Status)
	assert.Len(t, pending, 1)
}

func TestCheckROFR_DefaultROFRDays_30(t *testing.T) {
	asset := &Asset{
		ID:        "acme-equity",
		AssetType: AssetTypeEquity,
		Restrictions: TransferRestrictions{
			HasROFR:  true,
			ROFRDays: 0, // should default to 30
		},
	}
	at := &AssetTransaction{
		AssetID: "acme-equity",
		Tx:      Transaction{Sender: "p1", Amount: 50},
	}
	pending := make(map[string]*CorporateAction)
	_, ca, _ := CheckROFR(at, asset, nil, pending)

	now := time.Now().UTC().Unix()
	expectedDeadline := now + 30*86400
	// Allow ±5 seconds for test execution timing
	assert.InDelta(t, expectedDeadline, ca.DeadlineAt, 5)
}

// ---------------------------------------------------------------------------
// ExecuteDragAlong
// ---------------------------------------------------------------------------

func TestExecuteDragAlong_GeneratesMinorityTxs(t *testing.T) {
	proposer := makeCorpKey(t)
	minority1 := makeCorpKey(t)
	minority2 := makeCorpKey(t)
	buyer := makeCorpKey(t)

	proposerPub := base64.StdEncoding.EncodeToString(proposer.Public().Bytes())
	minority1Pub := base64.StdEncoding.EncodeToString(minority1.Public().Bytes())
	minority2Pub := base64.StdEncoding.EncodeToString(minority2.Public().Bytes())
	buyerPub := base64.StdEncoding.EncodeToString(buyer.Public().Bytes())

	ca := &CorporateAction{
		ID:          "drag-001",
		AssetID:     "acme-equity",
		Type:        CorporateActionDragAlong,
		Status:      CorporateActionApproved,
		ProposerKey: proposerPub,
		Responses:   make(map[string]bool),
	}

	holdings := map[string]*AssetHolding{
		HoldingKey(proposerPub, "acme-equity"):  {AssetID: "acme-equity", HolderID: proposerPub, Balance: 6000},
		HoldingKey(minority1Pub, "acme-equity"): {AssetID: "acme-equity", HolderID: minority1Pub, Balance: 2500},
		HoldingKey(minority2Pub, "acme-equity"): {AssetID: "acme-equity", HolderID: minority2Pub, Balance: 1500},
	}

	txs, err := ExecuteDragAlong(ca, holdings, buyerPub)
	require.NoError(t, err)
	// Proposer is skipped; minority1 and minority2 are included
	require.Len(t, txs, 2)

	for _, tx := range txs {
		assert.Equal(t, "acme-equity", tx.AssetID)
		assert.Equal(t, AssetTxTypeTransfer, tx.TxType)
		assert.Equal(t, buyerPub, tx.Tx.Receiver)
		assert.Greater(t, tx.Tx.Amount, 0.0)
	}
}

func TestExecuteDragAlong_WrongType_Error(t *testing.T) {
	ca := &CorporateAction{
		ID:        "rofr-001",
		AssetID:   "acme-equity",
		Type:      CorporateActionROFR, // wrong type
		Responses: make(map[string]bool),
	}
	_, err := ExecuteDragAlong(ca, nil, "buyer-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drag_along")
}

func TestExecuteDragAlong_ZeroBalance_Excluded(t *testing.T) {
	proposer := makeCorpKey(t)
	proposerPub := base64.StdEncoding.EncodeToString(proposer.Public().Bytes())
	holder := makeCorpKey(t)
	holderPub := base64.StdEncoding.EncodeToString(holder.Public().Bytes())
	buyer := makeCorpKey(t)
	buyerPub := base64.StdEncoding.EncodeToString(buyer.Public().Bytes())

	ca := &CorporateAction{
		ID:          "drag-002",
		AssetID:     "acme-equity",
		Type:        CorporateActionDragAlong,
		ProposerKey: proposerPub,
		Responses:   make(map[string]bool),
	}
	holdings := map[string]*AssetHolding{
		HoldingKey(holderPub, "acme-equity"): {AssetID: "acme-equity", HolderID: holderPub, Balance: 0},
	}
	txs, err := ExecuteDragAlong(ca, holdings, buyerPub)
	require.NoError(t, err)
	assert.Empty(t, txs)
}

// ---------------------------------------------------------------------------
// NewCorporateActionResponse — signed response
// ---------------------------------------------------------------------------

func TestNewCorporateActionResponse_SignatureIsValid(t *testing.T) {
	holder := makeCorpKey(t)
	holderPub := base64.StdEncoding.EncodeToString(holder.Public().Bytes())
	proposer := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 0, 0, 7, 0.5)

	resp := NewCorporateActionResponse(ca.ID, true, holder)
	assert.Equal(t, ca.ID, resp.ActionID)
	assert.Equal(t, holderPub, resp.HolderKey)
	assert.True(t, resp.Exercised)
	assert.NotEmpty(t, resp.Signature)

	// Should verify successfully when recorded on the action
	require.NoError(t, ca.RecordResponse(resp, holder.Public()))
}

func TestNewCorporateActionResponse_Waived(t *testing.T) {
	holder := makeCorpKey(t)
	proposer := makeCorpKey(t)
	ca, _ := NewCorporateAction(proposer, "acme-equity", CorporateActionROFR, nil, 0, 0, 7, 0.5)

	resp := NewCorporateActionResponse(ca.ID, false, holder)
	assert.False(t, resp.Exercised)
	require.NoError(t, ca.RecordResponse(resp, holder.Public()))
}
