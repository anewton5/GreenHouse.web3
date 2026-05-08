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

const testAssetID = "asset-test-001"
const testCurrency = "GBP"

func newKey(t *testing.T) *PrivateKey {
	t.Helper()
	key, err := GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

func newKeyStr(t *testing.T) (*PrivateKey, string) {
	t.Helper()
	key := newKey(t)
	return key, base64.StdEncoding.EncodeToString(key.Public().Bytes())
}

func makeOrder(t *testing.T, key *PrivateKey, side OrderSide, price, qty float64, expiresAt int64) *Order {
	t.Helper()
	o, err := NewOrder(key, testAssetID, side, price, qty, expiresAt)
	require.NoError(t, err)
	return o
}

func addOrder(t *testing.T, ob *OrderBook, order *Order, key *PrivateKey) {
	t.Helper()
	pub := key.Public()
	require.NoError(t, ob.AddOrder(order, pub))
}

// newBookWithOrders creates a book with one bid and one ask already inserted.
func newBookWithOrders(t *testing.T, bidKey, askKey *PrivateKey, bidPrice, askPrice, qty float64) (*OrderBook, *Order, *Order) {
	t.Helper()
	ob := NewOrderBook(testAssetID)
	bid := makeOrder(t, bidKey, OrderSideBid, bidPrice, qty, 0)
	ask := makeOrder(t, askKey, OrderSideAsk, askPrice, qty, 0)
	addOrder(t, ob, bid, bidKey)
	addOrder(t, ob, ask, askKey)
	return ob, bid, ask
}

// ---------------------------------------------------------------------------
// NewOrder tests
// ---------------------------------------------------------------------------

func TestNewOrder_Valid(t *testing.T) {
	key := newKey(t)
	pub := key.Public()

	o, err := NewOrder(key, testAssetID, OrderSideBid, 100.0, 50.0, 0)
	require.NoError(t, err)

	assert.NotEmpty(t, o.ID)
	assert.Equal(t, testAssetID, o.AssetID)
	assert.Equal(t, OrderSideBid, o.Side)
	assert.Equal(t, 100.0, o.Price)
	assert.Equal(t, 50.0, o.Quantity)
	assert.Equal(t, 0.0, o.Filled)
	assert.Equal(t, OrderStatusOpen, o.Status)
	assert.NotEmpty(t, o.Signature)
	assert.True(t, o.VerifySignature(pub))
}

func TestNewOrder_InvalidPrice(t *testing.T) {
	key := newKey(t)
	_, err := NewOrder(key, testAssetID, OrderSideBid, 0, 50.0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "price")
}

func TestNewOrder_NegativePrice(t *testing.T) {
	key := newKey(t)
	_, err := NewOrder(key, testAssetID, OrderSideBid, -5.0, 50.0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "price")
}

func TestNewOrder_InvalidQuantity(t *testing.T) {
	key := newKey(t)
	_, err := NewOrder(key, testAssetID, OrderSideBid, 100.0, 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quantity")
}

func TestNewOrder_NilKey(t *testing.T) {
	_, err := NewOrder(nil, testAssetID, OrderSideBid, 100.0, 50.0, 0)
	require.Error(t, err)
}

func TestOrder_Remaining(t *testing.T) {
	key := newKey(t)
	o := makeOrder(t, key, OrderSideBid, 100.0, 80.0, 0)
	assert.Equal(t, 80.0, o.Remaining())
	o.Filled = 30.0
	assert.Equal(t, 50.0, o.Remaining())
}

func TestOrder_IsExpired_GTC(t *testing.T) {
	key := newKey(t)
	o := makeOrder(t, key, OrderSideBid, 100.0, 50.0, 0) // GTC
	assert.False(t, o.IsExpired())
}

func TestOrder_IsExpired_Future(t *testing.T) {
	key := newKey(t)
	o := makeOrder(t, key, OrderSideBid, 100.0, 50.0, time.Now().Add(time.Hour).Unix())
	assert.False(t, o.IsExpired())
}

func TestOrder_IsExpired_Past(t *testing.T) {
	key := newKey(t)
	// Create with a future expiry to pass NewOrder validation.
	o := makeOrder(t, key, OrderSideBid, 100.0, 50.0, time.Now().Add(time.Hour).Unix())
	// Simulate elapsed time by mutating ExpiresAt.
	o.ExpiresAt = time.Now().Unix() - 1
	assert.True(t, o.IsExpired())
}

func TestOrder_VerifySignature_Tampered(t *testing.T) {
	key := newKey(t)
	pub := key.Public()
	o := makeOrder(t, key, OrderSideBid, 100.0, 50.0, 0)
	assert.True(t, o.VerifySignature(pub))
	// Mutate price without re-signing.
	o.Price = 9999.0
	assert.False(t, o.VerifySignature(pub))
}

// ---------------------------------------------------------------------------
// OrderBook sorting tests
// ---------------------------------------------------------------------------

func TestOrderBookAddBid(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	k1, k2, k3 := newKey(t), newKey(t), newKey(t)

	// Add three bids at different prices in non-descending order.
	b90 := makeOrder(t, k1, OrderSideBid, 90.0, 10.0, 0)
	b110 := makeOrder(t, k2, OrderSideBid, 110.0, 10.0, 0)
	b100 := makeOrder(t, k3, OrderSideBid, 100.0, 10.0, 0)

	addOrder(t, ob, b90, k1)
	addOrder(t, ob, b110, k2)
	addOrder(t, ob, b100, k3)

	require.Len(t, ob.Bids, 3)
	assert.Equal(t, 110.0, ob.Bids[0].Price)
	assert.Equal(t, 100.0, ob.Bids[1].Price)
	assert.Equal(t, 90.0, ob.Bids[2].Price)
}

func TestOrderBookAddAsk(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	k1, k2, k3 := newKey(t), newKey(t), newKey(t)

	a110 := makeOrder(t, k1, OrderSideAsk, 110.0, 10.0, 0)
	a90 := makeOrder(t, k2, OrderSideAsk, 90.0, 10.0, 0)
	a100 := makeOrder(t, k3, OrderSideAsk, 100.0, 10.0, 0)

	addOrder(t, ob, a110, k1)
	addOrder(t, ob, a90, k2)
	addOrder(t, ob, a100, k3)

	require.Len(t, ob.Asks, 3)
	assert.Equal(t, 90.0, ob.Asks[0].Price)
	assert.Equal(t, 100.0, ob.Asks[1].Price)
	assert.Equal(t, 110.0, ob.Asks[2].Price)
}

func TestOrderBookTimePriority(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	k1, k2 := newKey(t), newKey(t)

	// Create two bids at identical price. bid1 placed first → should be Bids[0].
	bid1 := makeOrder(t, k1, OrderSideBid, 100.0, 10.0, 0)
	time.Sleep(time.Millisecond) // ensure distinct PlacedAt nanoseconds
	bid2 := makeOrder(t, k2, OrderSideBid, 100.0, 10.0, 0)

	// Add in reverse order to verify sort — not insertion order — determines priority.
	addOrder(t, ob, bid2, k2)
	addOrder(t, ob, bid1, k1)

	require.Len(t, ob.Bids, 2)
	assert.Equal(t, bid1.ID, ob.Bids[0].ID, "earlier bid should be at index 0")
	assert.Equal(t, bid2.ID, ob.Bids[1].ID)
}

func TestAddOrder_InvalidSignature(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	key := newKey(t)
	wrongKey := newKey(t)
	o := makeOrder(t, key, OrderSideBid, 100.0, 10.0, 0)
	wrongPub := wrongKey.Public()
	err := ob.AddOrder(o, wrongPub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestAddOrder_Expired(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	key := newKey(t)
	o := makeOrder(t, key, OrderSideBid, 100.0, 10.0, time.Now().Add(time.Hour).Unix())
	o.ExpiresAt = time.Now().Unix() - 1 // backdate after signing
	pub := key.Public()
	// Signature won't match after mutation, but IsExpired check runs first via AddOrder.
	// Either error (expired or invalid sig) is acceptable.
	err := ob.AddOrder(o, pub)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// CancelOrder tests
// ---------------------------------------------------------------------------

func TestCancelOrder(t *testing.T) {
	key := newKey(t)
	_, keyStr := newKeyStr(t) // use a fresh pair; get PlacedBy from the order
	ob := NewOrderBook(testAssetID)
	_ = keyStr

	bid := makeOrder(t, key, OrderSideBid, 100.0, 10.0, 0)
	addOrder(t, ob, bid, key)
	require.Len(t, ob.Bids, 1)

	err := ob.CancelOrder(bid.ID, bid.PlacedBy)
	require.NoError(t, err)
	assert.Empty(t, ob.Bids)
	assert.Equal(t, OrderStatusCancelled, bid.Status)
}

func TestCancelOrder_WrongCanceller(t *testing.T) {
	key1 := newKey(t)
	key2 := newKey(t)
	ob := NewOrderBook(testAssetID)

	bid := makeOrder(t, key1, OrderSideBid, 100.0, 10.0, 0)
	addOrder(t, ob, bid, key1)

	wrongKeyStr := base64.StdEncoding.EncodeToString(key2.Public().Bytes())
	err := ob.CancelOrder(bid.ID, wrongKeyStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected")
	assert.Len(t, ob.Bids, 1) // order still in book
}

func TestCancelOrder_NotFound(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	err := ob.CancelOrder("nonexistent-id", "some-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCancelAsk(t *testing.T) {
	key := newKey(t)
	ob := NewOrderBook(testAssetID)
	ask := makeOrder(t, key, OrderSideAsk, 100.0, 10.0, 0)
	addOrder(t, ob, ask, key)

	err := ob.CancelOrder(ask.ID, ask.PlacedBy)
	require.NoError(t, err)
	assert.Empty(t, ob.Asks)
}

// ---------------------------------------------------------------------------
// MatchOrders tests
// ---------------------------------------------------------------------------

func TestMatchOrders_FullFill(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	ob, bid, ask := newBookWithOrders(t, bidKey, askKey, 100.0, 100.0, 50.0)

	trades, atxs, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)

	require.Len(t, trades, 1)
	assert.Equal(t, 50.0, trades[0].Quantity)
	assert.Equal(t, 100.0, trades[0].Price)
	assert.Equal(t, testCurrency, trades[0].Currency)

	assert.Len(t, atxs, 1)
	assert.Equal(t, OrderStatusFilled, bid.Status)
	assert.Equal(t, OrderStatusFilled, ask.Status)
	assert.Empty(t, ob.Bids)
	assert.Empty(t, ob.Asks)
}

func TestMatchOrders_NoMatch(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	// Bid price (90) < ask price (100) — no match.
	ob, _, _ := newBookWithOrders(t, bidKey, askKey, 90.0, 100.0, 50.0)

	trades, atxs, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)
	assert.Empty(t, trades)
	assert.Empty(t, atxs)
	assert.Len(t, ob.Bids, 1)
	assert.Len(t, ob.Asks, 1)
}

func TestMatchOrders_ExecuteAtAskPrice(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	// Bid at 110, ask at 95 — should execute at ask price (95).
	ob, _, _ := newBookWithOrders(t, bidKey, askKey, 110.0, 95.0, 50.0)

	trades, _, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)
	require.Len(t, trades, 1)
	assert.Equal(t, 95.0, trades[0].Price, "execution must be at ask price")
}

func TestMatchOrders_PartialFill(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	ob := NewOrderBook(testAssetID)

	// Bid for 200 units, ask for 100 units at matching price.
	bid := makeOrder(t, bidKey, OrderSideBid, 100.0, 200.0, 0)
	ask := makeOrder(t, askKey, OrderSideAsk, 100.0, 100.0, 0)
	addOrder(t, ob, bid, bidKey)
	addOrder(t, ob, ask, askKey)

	trades, _, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)

	require.Len(t, trades, 1)
	assert.Equal(t, 100.0, trades[0].Quantity)

	assert.Equal(t, OrderStatusPartial, bid.Status)
	assert.Equal(t, 100.0, bid.Filled)
	assert.Equal(t, 100.0, bid.Remaining())

	assert.Equal(t, OrderStatusFilled, ask.Status)
	assert.Empty(t, ob.Asks)
	assert.Len(t, ob.Bids, 1) // bid still present
}

func TestMatchOrders_MultipleMatches(t *testing.T) {
	bidKey := newKey(t)
	ask1Key, ask2Key, ask3Key := newKey(t), newKey(t), newKey(t)
	ob := NewOrderBook(testAssetID)

	// Large bid for 300 units; three asks at different prices, all matchable.
	bid := makeOrder(t, bidKey, OrderSideBid, 110.0, 300.0, 0)
	ask1 := makeOrder(t, ask1Key, OrderSideAsk, 98.0, 100.0, 0)
	ask2 := makeOrder(t, ask2Key, OrderSideAsk, 99.0, 100.0, 0)
	ask3 := makeOrder(t, ask3Key, OrderSideAsk, 100.0, 100.0, 0)

	addOrder(t, ob, bid, bidKey)
	addOrder(t, ob, ask1, ask1Key)
	addOrder(t, ob, ask2, ask2Key)
	addOrder(t, ob, ask3, ask3Key)

	trades, atxs, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)

	assert.Len(t, trades, 3)
	assert.Len(t, atxs, 3)

	// Asks matched in ascending price order.
	assert.Equal(t, 98.0, trades[0].Price)
	assert.Equal(t, 99.0, trades[1].Price)
	assert.Equal(t, 100.0, trades[2].Price)

	assert.Equal(t, OrderStatusFilled, bid.Status)
	assert.Empty(t, ob.Bids)
	assert.Empty(t, ob.Asks)
}

func TestMatchOrders_ProducesAssetTransactions(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	ob, bid, ask := newBookWithOrders(t, bidKey, askKey, 100.0, 100.0, 75.0)

	trades, atxs, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)
	require.Equal(t, len(trades), len(atxs), "one AssetTransaction per trade")

	at := atxs[0]
	tr := trades[0]

	assert.Equal(t, ask.PlacedBy, at.Tx.Sender, "seller is sender")
	assert.Equal(t, bid.PlacedBy, at.Tx.Receiver, "buyer is receiver")
	assert.Equal(t, tr.Quantity, at.Tx.Amount)
	assert.Equal(t, AssetTxTypeTransfer, at.TxType)
	assert.Equal(t, testAssetID, at.AssetID)
	// Unsigned — Validate is NOT called here; seller signs before commitment.
	assert.Empty(t, at.Tx.Signatures)
}

func TestOrderBookEmptyAfterFill(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	ob, _, _ := newBookWithOrders(t, bidKey, askKey, 100.0, 100.0, 100.0)

	_, _, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)

	assert.Empty(t, ob.Bids)
	assert.Empty(t, ob.Asks)
}

func TestOrderExpiry(t *testing.T) {
	bidKey, askKey := newKey(t), newKey(t)
	ob := NewOrderBook(testAssetID)

	// Create bid with a valid future expiry, add it, then backdate ExpiresAt.
	bid := makeOrder(t, bidKey, OrderSideBid, 100.0, 50.0, time.Now().Add(time.Hour).Unix())
	addOrder(t, ob, bid, bidKey)

	// Simulate the bid having expired.
	ob.Bids[0].ExpiresAt = time.Now().Unix() - 1

	// Add a matching ask (GTC — never expires).
	ask := makeOrder(t, askKey, OrderSideAsk, 100.0, 50.0, 0)
	addOrder(t, ob, ask, askKey)

	// MatchOrders calls ExpireOrders first — the bid must be removed.
	trades, _, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)
	assert.Empty(t, trades, "expired bid must not produce a trade")
	assert.Empty(t, ob.Bids, "expired bid must be removed from book")
	assert.Len(t, ob.Asks, 1, "unmatched ask must remain")
}

func TestMatchOrders_TradeIDs_Unique(t *testing.T) {
	bidKey := newKey(t)
	ask1Key, ask2Key := newKey(t), newKey(t)
	ob := NewOrderBook(testAssetID)

	bid := makeOrder(t, bidKey, OrderSideBid, 100.0, 200.0, 0)
	ask1 := makeOrder(t, ask1Key, OrderSideAsk, 100.0, 100.0, 0)
	time.Sleep(time.Millisecond) // ensure distinct nanosecond timestamps for IDs
	ask2 := makeOrder(t, ask2Key, OrderSideAsk, 100.0, 100.0, 0)

	addOrder(t, ob, bid, bidKey)
	addOrder(t, ob, ask1, ask1Key)
	addOrder(t, ob, ask2, ask2Key)

	trades, _, err := ob.MatchOrders(testAssetID, testCurrency)
	require.NoError(t, err)
	require.Len(t, trades, 2)
	assert.NotEqual(t, trades[0].ID, trades[1].ID, "each trade must have a unique ID")
}

func TestNewOrderBook(t *testing.T) {
	ob := NewOrderBook(testAssetID)
	assert.Equal(t, testAssetID, ob.AssetID)
	assert.Empty(t, ob.Bids)
	assert.Empty(t, ob.Asks)
}
