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

const lwAssetID = "lw-asset-001"
const lwCurrency = "GBP"

// newTestBC returns a minimal Blockchain suitable for liquidity window tests.
// No P2P node is started — only the maps and mock services needed by Tick are initialised.
func newTestBC(t *testing.T) *Blockchain {
	t.Helper()
	oracle, err := NewMockOracleService()
	require.NoError(t, err)
	reg, err := NewMockIdentityRegistry()
	require.NoError(t, err)
	return &Blockchain{
		Blocks:                   []Block{{Transactions: []Transaction{}, PrevHash: "0000000000000000", Nonce: 0, Signatures: [][]byte{}}},
		Assets:                   make(map[string]*Asset),
		Holdings:                 make(map[string]*AssetHolding),
		OrderBooks:               make(map[string]*OrderBook),
		Trades:                   []Trade{},
		Credentials:              make(map[string]*CredentialAttestation),
		PendingInstructions:      make(map[string]*PaymentInstruction),
		ConfirmedPayments:        make(map[string]*PaymentConfirmation),
		PendingAssetTransactions: []AssetTransaction{},
		PaymentProvider:          NewMockPaymentProvider(),
		IdentityRegistry:         reg,
		OracleService:            oracle,
		WindowManager:            NewWindowManager(),
		WindowResults:            []WindowResult{},
		SPVs:                     make(map[string]*SPVWrapper),
	}
}

// futureWindow creates a signed LiquidityWindow with valid future timestamps.
func futureWindow(t *testing.T, proposerKey *PrivateKey, assetID string) *LiquidityWindow {
	t.Helper()
	now := time.Now().UTC().Unix()
	w, err := NewLiquidityWindow(proposerKey, assetID, now+3600, now+7200, 0, lwCurrency)
	require.NoError(t, err)
	return w
}

// openWindow returns a window whose OpenAt and CloseAt are in the past and
// whose Status is Open — simulating a window that should now close.
func openWindowReadyToClose(t *testing.T, proposerKey *PrivateKey, assetID string) *LiquidityWindow {
	t.Helper()
	w := futureWindow(t, proposerKey, assetID)
	w.OpenAt = time.Now().UTC().Unix() - 120
	w.CloseAt = time.Now().UTC().Unix() - 1
	w.Status = WindowStatusOpen
	return w
}

// seedBookAndHoldings populates bc with an asset, order book, and holdings for
// bidKey (buyer) and askKey (seller) with the given quantities.
func seedBookAndHoldings(t *testing.T, bc *Blockchain, assetID, currency string, issuerKey, bidKey, askKey *PrivateKey, sellerBalance float64) {
	t.Helper()
	issuerPubStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())
	bidPubStr := base64.StdEncoding.EncodeToString(bidKey.Public().Bytes())
	askPubStr := base64.StdEncoding.EncodeToString(askKey.Public().Bytes())

	asset := &Asset{
		ID:          assetID,
		Issuer:      issuerPubStr,
		TotalSupply: 1_000_000,
		Currency:    currency,
		AssetType:   AssetTypeEquity,
	}
	bc.Assets[assetID] = asset

	// Seller holds sellerBalance units so DVP can complete
	bc.Holdings[HoldingKey(askPubStr, assetID)] = &AssetHolding{
		HolderID: askPubStr,
		AssetID:  assetID,
		Balance:  sellerBalance,
	}
	// Buyer starts with zero balance
	bc.Holdings[HoldingKey(bidPubStr, assetID)] = &AssetHolding{
		HolderID: bidPubStr,
		AssetID:  assetID,
		Balance:  0,
	}
	bc.OrderBooks[assetID] = NewOrderBook(assetID)
}

// addLWOrder places a signed order into bc.OrderBooks[assetID].
func addLWOrder(t *testing.T, bc *Blockchain, assetID string, key *PrivateKey, side OrderSide, price, qty float64) {
	t.Helper()
	o, err := NewOrder(key, assetID, side, price, qty, 0)
	require.NoError(t, err)
	require.NoError(t, bc.OrderBooks[assetID].AddOrder(o, key.Public()))
}

// ---------------------------------------------------------------------------
// TestNewLiquidityWindow_Valid
// ---------------------------------------------------------------------------

func TestNewLiquidityWindow_Valid(t *testing.T) {
	key := newKey(t)
	now := time.Now().UTC().Unix()
	w, err := NewLiquidityWindow(key, lwAssetID, now+3600, now+7200, 500, lwCurrency)
	require.NoError(t, err)

	assert.NotEmpty(t, w.ID)
	assert.Equal(t, lwAssetID, w.AssetID)
	assert.Equal(t, now+3600, w.OpenAt)
	assert.Equal(t, now+7200, w.CloseAt)
	assert.Equal(t, float64(500), w.MaxVolume)
	assert.Equal(t, lwCurrency, w.Currency)
	assert.Equal(t, WindowStatusScheduled, w.Status)
	assert.NotEmpty(t, w.Signature)
	assert.True(t, w.VerifySignature(key.Public()), "signature must verify with proposer public key")
}

// ---------------------------------------------------------------------------
// TestNewLiquidityWindow_InvalidDates
// ---------------------------------------------------------------------------

func TestNewLiquidityWindow_InvalidDates(t *testing.T) {
	key := newKey(t)
	now := time.Now().UTC().Unix()

	// openAt == closeAt
	_, err := NewLiquidityWindow(key, lwAssetID, now+3600, now+3600, 0, lwCurrency)
	assert.Error(t, err)

	// openAt > closeAt
	_, err = NewLiquidityWindow(key, lwAssetID, now+7200, now+3600, 0, lwCurrency)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TestNewLiquidityWindow_PastOpen
// ---------------------------------------------------------------------------

func TestNewLiquidityWindow_PastOpen(t *testing.T) {
	key := newKey(t)
	now := time.Now().UTC().Unix()

	_, err := NewLiquidityWindow(key, lwAssetID, now-1, now+3600, 0, lwCurrency)
	assert.Error(t, err, "openAt in the past must be rejected")

	// openAt == now is also invalid (must be strictly in the future)
	_, err = NewLiquidityWindow(key, lwAssetID, now, now+3600, 0, lwCurrency)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TestWindowManager_ScheduleWindow
// ---------------------------------------------------------------------------

func TestWindowManager_ScheduleWindow(t *testing.T) {
	key := newKey(t)
	wm := NewWindowManager()
	w := futureWindow(t, key, lwAssetID)

	require.NoError(t, wm.ScheduleWindow(w))

	assert.Contains(t, wm.Windows, w.ID)
	require.Len(t, wm.Schedule[lwAssetID], 1)
	assert.Equal(t, w, wm.Schedule[lwAssetID][0])
	assert.True(t, wm.IsManaged(lwAssetID))
}

// ---------------------------------------------------------------------------
// TestWindowManager_NoOverlap
// ---------------------------------------------------------------------------

func TestWindowManager_NoOverlap(t *testing.T) {
	key := newKey(t)
	wm := NewWindowManager()
	now := time.Now().UTC().Unix()

	// First window: +1h → +2h
	w1, err := NewLiquidityWindow(key, lwAssetID, now+3600, now+7200, 0, lwCurrency)
	require.NoError(t, err)
	require.NoError(t, wm.ScheduleWindow(w1))

	// Overlapping window: +1.5h → +3h (starts inside w1)
	w2, err := NewLiquidityWindow(key, lwAssetID, now+5400, now+10800, 0, lwCurrency)
	require.NoError(t, err)
	assert.Error(t, wm.ScheduleWindow(w2), "overlapping window must be rejected")

	// Non-overlapping window: +3h → +4h (starts after w1 closes)
	w3, err := NewLiquidityWindow(key, lwAssetID, now+10800, now+14400, 0, lwCurrency)
	require.NoError(t, err)
	assert.NoError(t, wm.ScheduleWindow(w3), "non-overlapping window must be accepted")
}

// ---------------------------------------------------------------------------
// TestWindowManager_Tick_Opens
// ---------------------------------------------------------------------------

func TestWindowManager_Tick_Opens(t *testing.T) {
	key := newKey(t)
	bc := newTestBC(t)
	w := futureWindow(t, key, lwAssetID)

	// Simulate time passing so ShouldOpen returns true
	w.OpenAt = time.Now().UTC().Unix() - 1

	require.NoError(t, bc.WindowManager.ScheduleWindow(w))

	results := bc.WindowManager.Tick(bc)

	assert.Empty(t, results, "no window closed, so no results expected")
	assert.Equal(t, WindowStatusOpen, w.Status, "window must transition to Open")
}

// ---------------------------------------------------------------------------
// TestWindowManager_Tick_Closes
// ---------------------------------------------------------------------------

func TestWindowManager_Tick_Closes(t *testing.T) {
	key := newKey(t)
	bc := newTestBC(t)
	w := openWindowReadyToClose(t, key, lwAssetID)

	require.NoError(t, bc.WindowManager.ScheduleWindow(w))

	results := bc.WindowManager.Tick(bc)

	require.Len(t, results, 1, "one window closed → one result")
	assert.Equal(t, w.ID, results[0].WindowID)
	assert.Equal(t, lwAssetID, results[0].AssetID)
	assert.NotZero(t, results[0].ClosedAt)
	assert.Equal(t, WindowStatusClosed, w.Status)
}

// ---------------------------------------------------------------------------
// TestMatchingSuppressedOutsideWindow
// ---------------------------------------------------------------------------

func TestMatchingSuppressedOutsideWindow(t *testing.T) {
	issuerKey := newKey(t)
	bidKey := newKey(t)
	askKey := newKey(t)

	bc := newTestBC(t)
	seedBookAndHoldings(t, bc, lwAssetID, lwCurrency, issuerKey, bidKey, askKey, 1000)

	// Schedule a window that has NOT yet opened (future)
	key := newKey(t)
	w := futureWindow(t, key, lwAssetID) // Status=Scheduled, times in future
	require.NoError(t, bc.WindowManager.ScheduleWindow(w))

	// Place matching orders directly in the book
	addLWOrder(t, bc, lwAssetID, bidKey, OrderSideBid, 10.00, 100)
	addLWOrder(t, bc, lwAssetID, askKey, OrderSideAsk, 9.00, 100)

	// CommitBlock triggers finalizeBlock → Tick → window stays Scheduled → no match
	bc.CommitBlock(Block{
		Transactions: []Transaction{},
		PrevHash:     bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
	})

	assert.Empty(t, bc.Trades, "matching must be suppressed while window is Scheduled")
	assert.Equal(t, WindowStatusScheduled, w.Status)
}

// ---------------------------------------------------------------------------
// TestMatchingRunsOnWindowClose
// ---------------------------------------------------------------------------

func TestMatchingRunsOnWindowClose(t *testing.T) {
	issuerKey := newKey(t)
	bidKey := newKey(t)
	askKey := newKey(t)
	askPubStr := base64.StdEncoding.EncodeToString(askKey.Public().Bytes())
	bidPubStr := base64.StdEncoding.EncodeToString(bidKey.Public().Bytes())

	bc := newTestBC(t)
	seedBookAndHoldings(t, bc, lwAssetID, lwCurrency, issuerKey, bidKey, askKey, 500)

	// Create a window that is currently open and ready to close
	key := newKey(t)
	w := openWindowReadyToClose(t, key, lwAssetID)
	require.NoError(t, bc.WindowManager.ScheduleWindow(w))

	// Place matching orders
	addLWOrder(t, bc, lwAssetID, bidKey, OrderSideBid, 10.00, 100)
	addLWOrder(t, bc, lwAssetID, askKey, OrderSideAsk, 9.00, 100)

	// CommitBlock → finalizeBlock → Tick → window closes → MatchOrders fires
	bc.CommitBlock(Block{
		Transactions: []Transaction{},
		PrevHash:     bc.Blocks[len(bc.Blocks)-1].CalculateHash(),
	})

	require.Len(t, bc.Trades, 1, "exactly one trade must be produced on window close")
	assert.Equal(t, WindowStatusClosed, w.Status)
	assert.Equal(t, float64(100), bc.Trades[0].Quantity)

	// DVP: buyer received the units, seller balance decreased
	assert.Equal(t, float64(100), bc.Holdings[HoldingKey(bidPubStr, lwAssetID)].Balance)
	assert.Equal(t, float64(400), bc.Holdings[HoldingKey(askPubStr, lwAssetID)].Balance)

	// Window result was recorded on bc
	require.Len(t, bc.WindowResults, 1)
	assert.Equal(t, w.ID, bc.WindowResults[0].WindowID)
}

// ---------------------------------------------------------------------------
// TestWindowResult_VWAP
// ---------------------------------------------------------------------------

func TestWindowResult_VWAP(t *testing.T) {
	// Two ask orders at different prices matched against two bid orders.
	// VWAP = (qty1*price1 + qty2*price2) / (qty1 + qty2)
	//      = (100*5.00 + 200*6.00) / 300 = 1700/300 ≈ 5.6667

	issuerKey := newKey(t)
	bidKey1 := newKey(t)
	bidKey2 := newKey(t)
	askKey1 := newKey(t)
	askKey2 := newKey(t)

	bc := newTestBC(t)

	// Seed two sellers (each needs separate balance)
	ask1PubStr := base64.StdEncoding.EncodeToString(askKey1.Public().Bytes())
	ask2PubStr := base64.StdEncoding.EncodeToString(askKey2.Public().Bytes())
	issuerPubStr := base64.StdEncoding.EncodeToString(issuerKey.Public().Bytes())

	asset := &Asset{
		ID:        lwAssetID,
		Issuer:    issuerPubStr,
		Currency:  lwCurrency,
		AssetType: AssetTypeEquity,
	}
	bc.Assets[lwAssetID] = asset
	bc.OrderBooks[lwAssetID] = NewOrderBook(lwAssetID)

	for _, pub := range []string{ask1PubStr, ask2PubStr} {
		bc.Holdings[HoldingKey(pub, lwAssetID)] = &AssetHolding{
			HolderID: pub,
			AssetID:  lwAssetID,
			Balance:  1000,
		}
	}
	for _, key := range []*PrivateKey{bidKey1, bidKey2} {
		pub := base64.StdEncoding.EncodeToString(key.Public().Bytes())
		bc.Holdings[HoldingKey(pub, lwAssetID)] = &AssetHolding{
			HolderID: pub,
			AssetID:  lwAssetID,
			Balance:  0,
		}
	}

	// Place orders: bid1 vs ask1 @ £5, bid2 vs ask2 @ £6
	addLWOrder(t, bc, lwAssetID, bidKey1, OrderSideBid, 10.00, 100) // bid price above both asks
	addLWOrder(t, bc, lwAssetID, askKey1, OrderSideAsk, 5.00, 100)
	addLWOrder(t, bc, lwAssetID, bidKey2, OrderSideBid, 10.00, 200) // same bid price
	addLWOrder(t, bc, lwAssetID, askKey2, OrderSideAsk, 6.00, 200)

	// Register and close a window
	propKey := newKey(t)
	w := openWindowReadyToClose(t, propKey, lwAssetID)
	require.NoError(t, bc.WindowManager.ScheduleWindow(w))

	results := bc.WindowManager.Tick(bc)

	require.Len(t, results, 1)
	r := results[0]
	assert.Equal(t, 2, r.TradeCount)
	assert.Equal(t, float64(300), r.TotalVolume)
	assert.InDelta(t, 1700.0, r.TotalValue, 0.01)
	// VWAP = 1700 / 300 ≈ 5.6667
	assert.InDelta(t, 5.6667, r.ClearingPrice, 0.001)
}

// ---------------------------------------------------------------------------
// TestMultipleAssets_IndependentWindows
// ---------------------------------------------------------------------------

func TestMultipleAssets_IndependentWindows(t *testing.T) {
	const assetA = "asset-alpha"
	const assetB = "asset-beta"

	issuerKey := newKey(t)
	bidKeyA := newKey(t)
	askKeyA := newKey(t)
	bidKeyB := newKey(t)
	askKeyB := newKey(t)

	bc := newTestBC(t)
	seedBookAndHoldings(t, bc, assetA, lwCurrency, issuerKey, bidKeyA, askKeyA, 500)
	seedBookAndHoldings(t, bc, assetB, lwCurrency, issuerKey, bidKeyB, askKeyB, 500)

	propKey := newKey(t)

	// Asset A window: ready to close
	wA := openWindowReadyToClose(t, propKey, assetA)
	require.NoError(t, bc.WindowManager.ScheduleWindow(wA))

	// Asset B window: still scheduled (future), must NOT match
	wB := futureWindow(t, propKey, assetB)
	require.NoError(t, bc.WindowManager.ScheduleWindow(wB))

	// Place matching orders in both books
	addLWOrder(t, bc, assetA, bidKeyA, OrderSideBid, 10.00, 50)
	addLWOrder(t, bc, assetA, askKeyA, OrderSideAsk, 9.00, 50)
	addLWOrder(t, bc, assetB, bidKeyB, OrderSideBid, 10.00, 50)
	addLWOrder(t, bc, assetB, askKeyB, OrderSideAsk, 9.00, 50)

	results := bc.WindowManager.Tick(bc)

	// Only assetA window closed
	require.Len(t, results, 1, "only the closing window produces a result")
	assert.Equal(t, wA.ID, results[0].WindowID)
	assert.Equal(t, assetA, results[0].AssetID)
	assert.Equal(t, WindowStatusClosed, wA.Status)

	// assetB window is still scheduled — no trades for assetB
	assert.Equal(t, WindowStatusScheduled, wB.Status)
	for _, trade := range bc.Trades {
		assert.Equal(t, assetA, trade.AssetID, "all trades must be for assetA only")
	}
}
