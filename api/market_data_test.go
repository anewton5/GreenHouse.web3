package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gonetwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarketDataVWAPRoute_ReturnsWindowedVWAP(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "market-data-vwap-api-test")
	bc.Assets["ASSET-1"] = &gonetwork.Asset{ID: "ASSET-1", Name: "Alpha", Currency: "EUR"}
	now := time.Now().Unix()
	bc.Trades = append(bc.Trades,
		gonetwork.Trade{ID: "old", AssetID: "ASSET-1", Price: 40, Quantity: 1, ExecutedAt: now - int64((3 * time.Hour).Seconds())},
		gonetwork.Trade{ID: "t1", AssetID: "ASSET-1", Price: 100, Quantity: 1, ExecutedAt: now - int64((20 * time.Minute).Seconds())},
		gonetwork.Trade{ID: "t2", AssetID: "ASSET-1", Price: 200, Quantity: 3, ExecutedAt: now - int64((10 * time.Minute).Seconds())},
	)

	s := NewServer(bc, ":0")
	tok, err := s.issueJWT("viewer-wallet")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/market-data/vwap/ASSET-1?window=1h", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		AssetID    string  `json:"asset_id"`
		Window     string  `json:"window"`
		VWAP       float64 `json:"vwap"`
		TradeCount int     `json:"trade_count"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "ASSET-1", out.AssetID)
	assert.Equal(t, "1h0m0s", out.Window)
	assert.Equal(t, 2, out.TradeCount)
	assert.InDelta(t, 175.0, out.VWAP, 0.001)
}

func TestMarketMakerInventoryRoute_SelfOrAdmin(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	t.Setenv("GREENHOUSE_ADMIN_WALLET_KEYS", "admin-wallet")

	bc := gonetwork.NewBlockchain(context.Background(), "market-data-inventory-api-test")
	wallet := "dealer-wallet"
	bc.Holdings[gonetwork.HoldingKey(wallet, "ASSET-1")] = &gonetwork.AssetHolding{HolderID: wallet, AssetID: "ASSET-1", Balance: 12}
	ob := gonetwork.NewOrderBook("ASSET-1")
	ob.Bids = append(ob.Bids, &gonetwork.Order{ID: "o1", PlacedBy: wallet, Quantity: 5, Filled: 2, Status: gonetwork.OrderStatusOpen})
	bc.OrderBooks["ASSET-1"] = ob
	bc.RFQRequests["r1"] = &gonetwork.RFQRequest{ID: "r1", AssetID: "ASSET-1"}
	bc.RFQQuotes["r1"] = []*gonetwork.RFQQuote{{
		ID:        "q1",
		RequestID: "r1",
		DealerKey: wallet,
		Quantity:  3,
		Status:    gonetwork.RFQQuoteStatusActive,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}}

	s := NewServer(bc, ":0")
	walletTok, err := s.issueJWT(wallet)
	require.NoError(t, err)
	otherTok, err := s.issueJWT("other-wallet")
	require.NoError(t, err)
	adminTok, err := s.issueJWT("admin-wallet")
	require.NoError(t, err)

	selfReq := httptest.NewRequest(http.MethodGet, "/v1/market-makers/"+wallet+"/inventory", nil)
	selfReq.Header.Set("Authorization", "Bearer "+walletTok)
	selfRec := httptest.NewRecorder()
	s.Routes().ServeHTTP(selfRec, selfReq)
	require.Equal(t, http.StatusOK, selfRec.Code)
	var selfOut gonetwork.InventoryReport
	require.NoError(t, json.NewDecoder(selfRec.Body).Decode(&selfOut))
	assert.InDelta(t, 12.0, selfOut.Holdings["ASSET-1"], 0.001)
	assert.InDelta(t, 3.0, selfOut.OpenOrderExposure["ASSET-1"], 0.001)
	assert.InDelta(t, 3.0, selfOut.OpenQuoteExposure["ASSET-1"], 0.001)

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/v1/market-makers/"+wallet+"/inventory", nil)
	forbiddenReq.Header.Set("Authorization", "Bearer "+otherTok)
	forbiddenRec := httptest.NewRecorder()
	s.Routes().ServeHTTP(forbiddenRec, forbiddenReq)
	assert.Equal(t, http.StatusForbidden, forbiddenRec.Code)

	adminReq := httptest.NewRequest(http.MethodGet, "/v1/market-makers/"+wallet+"/inventory", nil)
	adminReq.Header.Set("Authorization", "Bearer "+adminTok)
	adminRec := httptest.NewRecorder()
	s.Routes().ServeHTTP(adminRec, adminReq)
	assert.Equal(t, http.StatusOK, adminRec.Code)
}
