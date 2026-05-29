package gonetwork

// ---------------------------------------------------------------------------
// stor_detection_test.go — MAR Article 16 STOR auto-creation tests (Item 16)
//
// Covers:
//   detectSTORs — Pattern 1: self-transfer  → STORDraft created, reason "self-transfer"
//               — Pattern 2: wash trade     → STORDraft created after 4th trade in 30 days
//               — Pattern 3: price deviation → STORDraft created when price deviates >20% from VWAP
//   EventSTORCreated emitted on bc.Events for each new STOR
//   storCounterpartyKey — order-independent canonical key
//   storAssetVWAP — weighted average over last-N trades
// ---------------------------------------------------------------------------

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mkStorTrade constructs a Trade with the given fields and a generated ID.
func mkStorTrade(assetID, buyerID, sellerID string, price, qty float64) Trade {
	return Trade{
		ID:         generateID("TRD"),
		AssetID:    assetID,
		BuyerID:    buyerID,
		SellerID:   sellerID,
		Price:      price,
		Quantity:   qty,
		Currency:   "EUR",
		ExecutedAt: time.Now().Unix(),
	}
}

// drainEvents reads all immediately-available events from bc.Events and returns them.
func drainEvents(bc *Blockchain) []StreamEvent {
	var evs []StreamEvent
	for {
		select {
		case e := <-bc.Events:
			evs = append(evs, e)
		default:
			return evs
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern 1 — Self-transfer
// ---------------------------------------------------------------------------

func TestDetectSTOR_SelfTransfer_CreatesSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	trade := mkStorTrade("equity-X", "wallet-A", "wallet-A", 100.0, 10)
	bc.detectSTORs(trade)

	require.Len(t, bc.PendingSTORs, 1, "one STOR must be created for a self-transfer")
	for _, stor := range bc.PendingSTORs {
		assert.Contains(t, stor.Description, "self-transfer")
		assert.Equal(t, "equity-X", stor.AssetID)
		assert.Equal(t, STORResolutionPendingReview, stor.Resolution)
	}
}

func TestDetectSTOR_SelfTransfer_EmitsEvent(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	trade := mkStorTrade("equity-X", "wallet-A", "wallet-A", 100.0, 10)
	bc.detectSTORs(trade)

	evs := drainEvents(bc)
	var storEvents []StreamEvent
	for _, e := range evs {
		if e.Type == EventSTORCreated {
			storEvents = append(storEvents, e)
		}
	}
	require.Len(t, storEvents, 1, "exactly one EventSTORCreated must be emitted")
	assert.Contains(t, string(storEvents[0].Payload), "self-transfer")
}

func TestDetectSTOR_DifferentBuyerSeller_NoSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	trade := mkStorTrade("equity-X", "wallet-A", "wallet-B", 100.0, 10)
	bc.detectSTORs(trade)

	assert.Empty(t, bc.PendingSTORs, "no STOR for a normal trade with different buyer and seller")
}

// ---------------------------------------------------------------------------
// Pattern 2 — Wash trade
// ---------------------------------------------------------------------------

func TestDetectSTOR_WashTrade_FourTradesTriggerSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 20)

	// First 3 trades: same A/B pair, same asset — no STOR yet.
	for i := 0; i < 3; i++ {
		bc.detectSTORs(mkStorTrade("equity-W", "alice", "bob", 50.0, 5))
	}
	assert.Empty(t, bc.PendingSTORs, "no STOR after 3 trades in the window")

	// 4th trade crosses the threshold.
	bc.detectSTORs(mkStorTrade("equity-W", "alice", "bob", 50.0, 5))

	var washSTORs []*STORDraft
	for _, s := range bc.PendingSTORs {
		if strings.Contains(s.Description, "wash-trade-pattern") {
			washSTORs = append(washSTORs, s)
		}
	}
	require.Len(t, washSTORs, 1, "one STOR must be created on the 4th trade")
	assert.Equal(t, "equity-W", washSTORs[0].AssetID)
}

func TestDetectSTOR_WashTrade_BidirectionalPairCounted(t *testing.T) {
	// A buys from B, then B buys from A — same counterparty bucket.
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 20)

	bc.detectSTORs(mkStorTrade("equity-W", "alice", "bob", 50.0, 5))
	bc.detectSTORs(mkStorTrade("equity-W", "bob", "alice", 50.0, 5))
	bc.detectSTORs(mkStorTrade("equity-W", "alice", "bob", 50.0, 5))
	bc.detectSTORs(mkStorTrade("equity-W", "bob", "alice", 50.0, 5)) // 4th → STOR

	var washSTORs []*STORDraft
	for _, s := range bc.PendingSTORs {
		if strings.Contains(s.Description, "wash-trade-pattern") {
			washSTORs = append(washSTORs, s)
		}
	}
	require.NotEmpty(t, washSTORs, "bidirectional trades must share the same wash-trade bucket")
}

func TestDetectSTOR_WashTrade_DifferentAssetNotCounted(t *testing.T) {
	// 4 trades between same pair but on different assets — no wash-trade STOR.
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 20)

	for _, assetID := range []string{"asset-1", "asset-2", "asset-3", "asset-4"} {
		bc.detectSTORs(mkStorTrade(assetID, "alice", "bob", 50.0, 5))
	}

	for _, s := range bc.PendingSTORs {
		assert.NotContains(t, s.Description, "wash-trade-pattern",
			"trades on different assets must not trigger wash-trade STOR")
	}
}

// ---------------------------------------------------------------------------
// Pattern 3 — Price deviation
// ---------------------------------------------------------------------------

func TestDetectSTOR_PriceDeviation_CreatesSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	// Seed 5 historical trades at price 100 to establish a reliable VWAP.
	for i := 0; i < 5; i++ {
		bc.Trades = append(bc.Trades, mkStorTrade("equity-P", "buyer", "seller", 100.0, 10))
	}

	// A trade at 130 — 30% above VWAP of 100 — should trigger a STOR.
	devTrade := mkStorTrade("equity-P", "buyer", "seller", 130.0, 10)
	bc.Trades = append(bc.Trades, devTrade)
	bc.detectSTORs(devTrade)

	var deviationSTORs []*STORDraft
	for _, s := range bc.PendingSTORs {
		if strings.Contains(s.Description, "price-deviation") {
			deviationSTORs = append(deviationSTORs, s)
		}
	}
	require.Len(t, deviationSTORs, 1, "one price-deviation STOR must be created")
	assert.Equal(t, "equity-P", deviationSTORs[0].AssetID)
}

func TestDetectSTOR_PriceDeviation_WithinThreshold_NoSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	for i := 0; i < 5; i++ {
		bc.Trades = append(bc.Trades, mkStorTrade("equity-P", "buyer", "seller", 100.0, 10))
	}

	// A trade at 115 — 15% above VWAP — is within the 20% threshold.
	withinTrade := mkStorTrade("equity-P", "buyer", "seller", 115.0, 10)
	bc.Trades = append(bc.Trades, withinTrade)
	bc.detectSTORs(withinTrade)

	for _, s := range bc.PendingSTORs {
		assert.NotContains(t, s.Description, "price-deviation",
			"15%% deviation must not trigger a STOR")
	}
}

func TestDetectSTOR_PriceDeviation_InsufficientHistory_NoSTOR(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 10)

	// Only one historical trade — not enough for a reliable VWAP baseline.
	bc.Trades = append(bc.Trades, mkStorTrade("equity-P", "buyer", "seller", 100.0, 10))

	devTrade := mkStorTrade("equity-P", "buyer", "seller", 999.0, 10)
	bc.Trades = append(bc.Trades, devTrade)
	bc.detectSTORs(devTrade)

	for _, s := range bc.PendingSTORs {
		assert.NotContains(t, s.Description, "price-deviation",
			"single historical trade must not trigger price-deviation STOR")
	}
}

// ---------------------------------------------------------------------------
// EventSTORCreated emitted for all patterns
// ---------------------------------------------------------------------------

func TestDetectSTOR_AllPatterns_EachEmitsEvent(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Events = make(chan StreamEvent, 20)

	// Pattern 1: self-transfer
	bc.detectSTORs(mkStorTrade("equity-A", "same", "same", 100.0, 1))

	// Pattern 2: wash trade — need 4 trades
	for i := 0; i < 4; i++ {
		bc.detectSTORs(mkStorTrade("equity-B", "x", "y", 100.0, 1))
	}

	// Pattern 3: price deviation
	for i := 0; i < 5; i++ {
		bc.Trades = append(bc.Trades, mkStorTrade("equity-C", "a", "b", 100.0, 10))
	}
	devTrade := mkStorTrade("equity-C", "a", "b", 200.0, 10)
	bc.Trades = append(bc.Trades, devTrade)
	bc.detectSTORs(devTrade)

	evs := drainEvents(bc)
	count := 0
	for _, e := range evs {
		if e.Type == EventSTORCreated {
			count++
		}
	}
	assert.GreaterOrEqual(t, count, 3, "at least one EventSTORCreated per pattern")
}

// ---------------------------------------------------------------------------
// storCounterpartyKey
// ---------------------------------------------------------------------------

func TestStorCounterpartyKey_OrderIndependent(t *testing.T) {
	k1 := storCounterpartyKey("alice", "bob")
	k2 := storCounterpartyKey("bob", "alice")
	assert.Equal(t, k1, k2, "counterparty key must be order-independent")
}

func TestStorCounterpartyKey_SamePairDifferentFromDifferentPair(t *testing.T) {
	k1 := storCounterpartyKey("alice", "bob")
	k2 := storCounterpartyKey("alice", "carol")
	assert.NotEqual(t, k1, k2)
}

// ---------------------------------------------------------------------------
// storAssetVWAP
// ---------------------------------------------------------------------------

func TestStorAssetVWAP_EmptyHistory_ReturnsZero(t *testing.T) {
	bc := newTestBlockchain(t)
	vwap, n := bc.storAssetVWAP("equity-Z", "none", 10)
	assert.Equal(t, 0.0, vwap)
	assert.Equal(t, 0, n)
}

func TestStorAssetVWAP_SingleTrade_ReturnsThatPrice(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Trades = append(bc.Trades, mkStorTrade("equity-Z", "a", "b", 50.0, 4))
	vwap, n := bc.storAssetVWAP("equity-Z", "other-id", 10)
	assert.Equal(t, 50.0, vwap)
	assert.Equal(t, 1, n)
}

func TestStorAssetVWAP_WeightsCorrectly(t *testing.T) {
	bc := newTestBlockchain(t)
	// Two trades: price=100 qty=1, price=200 qty=3 → VWAP = (100+600)/4 = 175
	bc.Trades = append(bc.Trades,
		Trade{ID: "t1", AssetID: "equity-Z", Price: 100, Quantity: 1},
		Trade{ID: "t2", AssetID: "equity-Z", Price: 200, Quantity: 3},
	)
	vwap, n := bc.storAssetVWAP("equity-Z", "other", 10)
	assert.InDelta(t, 175.0, vwap, 0.001)
	assert.Equal(t, 2, n)
}

func TestStorAssetVWAP_ExcludesCurrentTrade(t *testing.T) {
	bc := newTestBlockchain(t)
	bc.Trades = append(bc.Trades,
		Trade{ID: "t1", AssetID: "equity-Z", Price: 100, Quantity: 1},
		Trade{ID: "current", AssetID: "equity-Z", Price: 999, Quantity: 100},
	)
	// "current" must be excluded from VWAP — result should be 100
	vwap, n := bc.storAssetVWAP("equity-Z", "current", 10)
	assert.InDelta(t, 100.0, vwap, 0.001)
	assert.Equal(t, 1, n)
}

func TestStorAssetVWAP_RespectsNLimit(t *testing.T) {
	bc := newTestBlockchain(t)
	// 20 trades at price=100, then 1 at price=200 (most recent)
	for i := 0; i < 20; i++ {
		bc.Trades = append(bc.Trades, Trade{ID: generateID("T"), AssetID: "equity-Z", Price: 100, Quantity: 1})
	}
	bc.Trades = append(bc.Trades, Trade{ID: "recent", AssetID: "equity-Z", Price: 200, Quantity: 1})
	// With n=3, only the 3 most recent trades contribute (1x200 + 2x100 = 400/3 ≈ 133.3)
	vwap, n := bc.storAssetVWAP("equity-Z", "other", 3)
	assert.Equal(t, 3, n)
	assert.InDelta(t, 133.33, vwap, 0.1)
}
