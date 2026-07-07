package gonetwork

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVWAP_Windowed(t *testing.T) {
	now := time.Now().Unix()
	trades := []Trade{
		{ID: "old", AssetID: "ASSET-1", Price: 50, Quantity: 2, ExecutedAt: now - int64((3 * time.Hour).Seconds())},
		{ID: "t1", AssetID: "ASSET-1", Price: 100, Quantity: 1, ExecutedAt: now - int64((30 * time.Minute).Seconds())},
		{ID: "t2", AssetID: "ASSET-1", Price: 200, Quantity: 3, ExecutedAt: now - int64((15 * time.Minute).Seconds())},
		{ID: "other", AssetID: "ASSET-2", Price: 500, Quantity: 10, ExecutedAt: now},
	}

	vwap := VWAP(trades, "ASSET-1", time.Hour)
	// (100*1 + 200*3) / 4 = 175
	assert.InDelta(t, 175.0, vwap, 0.001)
}

func TestInventorySnapshot_AggregatesHoldingsOrdersQuotes(t *testing.T) {
	bc := newTestBlockchain(t)
	wallet := "dealer-wallet"

	bc.Holdings[HoldingKey(wallet, "ASSET-1")] = &AssetHolding{HolderID: wallet, AssetID: "ASSET-1", Balance: 10}
	bc.Holdings[HoldingKey(wallet, "ASSET-2")] = &AssetHolding{HolderID: wallet, AssetID: "ASSET-2", Balance: 5}

	ob := NewOrderBook("ASSET-1")
	ob.Bids = append(ob.Bids, &Order{ID: "o1", PlacedBy: wallet, Quantity: 7, Filled: 2, Status: OrderStatusOpen})
	ob.Asks = append(ob.Asks, &Order{ID: "o2", PlacedBy: wallet, Quantity: 3, Filled: 1, Status: OrderStatusPartial})
	ob.Asks = append(ob.Asks, &Order{ID: "o3", PlacedBy: wallet, Quantity: 2, Filled: 0, Status: OrderStatusCancelled})
	bc.OrderBooks["ASSET-1"] = ob

	bc.RFQRequests["r1"] = &RFQRequest{ID: "r1", AssetID: "ASSET-1"}
	bc.RFQQuotes["r1"] = []*RFQQuote{
		{ID: "q1", RequestID: "r1", DealerKey: wallet, Quantity: 4, Status: RFQQuoteStatusActive, ExpiresAt: time.Now().Add(time.Hour).Unix()},
		{ID: "q2", RequestID: "r1", DealerKey: wallet, Quantity: 1, Status: RFQQuoteStatusExpired, ExpiresAt: time.Now().Add(-time.Hour).Unix()},
	}

	report := InventorySnapshot(wallet, bc)
	require.Equal(t, wallet, report.WalletKey)
	assert.InDelta(t, 10.0, report.Holdings["ASSET-1"], 0.001)
	assert.InDelta(t, 5.0, report.Holdings["ASSET-2"], 0.001)
	// open order exposure: (7-2) + (3-1) = 7
	assert.InDelta(t, 7.0, report.OpenOrderExposure["ASSET-1"], 0.001)
	assert.InDelta(t, 4.0, report.OpenQuoteExposure["ASSET-1"], 0.001)
}

func TestCheckMarketMakerPositionLimit_RejectsProjectedUnitCap(t *testing.T) {
	bc := newTestBlockchain(t)
	wallet := "dealer-wallet"
	assetID := "ASSET-1"
	bc.MarketMakerRegistry.ByAsset[assetID] = []*MarketMakerAgreement{{
		ID:               "mm-1",
		AssetID:          assetID,
		DealerKey:        wallet,
		Status:           MarketMakerStatusActive,
		EffectiveFrom:    time.Now().Add(-time.Hour).Unix(),
		MaxPositionUnits: 10,
	}}
	bc.Holdings[HoldingKey(wallet, assetID)] = &AssetHolding{HolderID: wallet, AssetID: assetID, Balance: 9}

	err := CheckMarketMakerPositionLimit(bc, wallet, assetID, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_position_units")
}

func TestCheckMarketMakerPositionLimit_RejectsProjectedValueCap(t *testing.T) {
	bc := newTestBlockchain(t)
	wallet := "dealer-wallet"
	assetID := "ASSET-1"
	bc.MarketMakerRegistry.ByAsset[assetID] = []*MarketMakerAgreement{{
		ID:               "mm-2",
		AssetID:          assetID,
		DealerKey:        wallet,
		Status:           MarketMakerStatusActive,
		EffectiveFrom:    time.Now().Add(-time.Hour).Unix(),
		MaxPositionValue: 100,
	}}
	bc.Holdings[HoldingKey(wallet, assetID)] = &AssetHolding{HolderID: wallet, AssetID: assetID, Balance: 4}
	bc.Trades = append(bc.Trades, Trade{ID: "t-last", AssetID: assetID, Price: 20, Quantity: 1, ExecutedAt: time.Now().Unix()})

	err := CheckMarketMakerPositionLimit(bc, wallet, assetID, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_position_value")
}
