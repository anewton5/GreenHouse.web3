package gonetwork

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRFQTestBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", ConsensusModeHTTP)
	return NewBlockchain(t.Context(), "rfq-test")
}

func seedDesignatedMarketMaker(t *testing.T, bc *Blockchain, assetID string, dealerKey *PrivateKey, lei string) string {
	t.Helper()
	operatorKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	issuerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	claim, err := NewClaim(ClaimTopicInstitutionalRole, "", dealerKeyStr, EntityRoleClaimData(lei, EntityRoleMarketMaker), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[dealerKeyStr] = []*Claim{claim}
	agreement, err := NewMarketMakerAgreement(operatorKey, assetID, dealerKeyStr, lei, 5, 50, 1, 10, 0, 0, time.Now().Unix(), 0)
	require.NoError(t, err)
	require.NoError(t, bc.MarketMakerRegistry.RegisterMarketMaker(agreement))
	return dealerKeyStr
}

func TestRFQRequestAndQuote_SignVerifyTamper(t *testing.T) {
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	req, err := NewRFQRequest(requesterKey, "ASSET-001", OrderSideBid, 10, 12.5, time.Now().Unix()+300)
	require.NoError(t, err)
	assert.True(t, req.VerifySignature(requesterKey.Public()))
	req.Quantity = 11
	assert.False(t, req.VerifySignature(requesterKey.Public()))

	quote, err := NewRFQQuote(dealerKey, "request-1", 12.0, 10, time.Now().Unix()+300)
	require.NoError(t, err)
	assert.True(t, quote.VerifySignature(dealerKey.Public()))
	quote.Price = 13.0
	assert.False(t, quote.VerifySignature(dealerKey.Public()))
}

func TestRFQQuoteRejectedForNonDesignatedDealer(t *testing.T) {
	bc := newRFQTestBlockchain(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	request, err := NewRFQRequest(requesterKey, "ASSET-001", OrderSideBid, 10, 12.5, time.Now().Unix()+300)
	require.NoError(t, err)
	quote, err := NewRFQQuote(dealerKey, request.ID, 12.0, 10, time.Now().Unix()+300)
	require.NoError(t, err)

	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: request.RequesterKey, RequiredSigs: 0}, Action: RFQActionRequest, Request: *request}})
	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: quote.DealerKey, RequiredSigs: 0}, Action: RFQActionQuote, Quote: *quote}})

	assert.Empty(t, bc.RFQQuotes[request.ID])
	require.NotNil(t, bc.RFQRequests[request.ID])
	assert.Equal(t, RFQRequestStatusOpen, bc.RFQRequests[request.ID].Status)
}

func TestRFQAccept_HappyPathAndDoubleAcceptRejected(t *testing.T) {
	bc := newRFQTestBlockchain(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	otherDealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	requesterKeyStr := base64.StdEncoding.EncodeToString(requesterKey.Public().Bytes())
	dealerKeyStr := seedDesignatedMarketMaker(t, bc, "ASSET-001", dealerKey, "549300ACMECORP0020")
	otherDealerKeyStr := seedDesignatedMarketMaker(t, bc, "ASSET-001", otherDealerKey, "549300ACMECORP0021")
	bc.Assets["ASSET-001"] = &Asset{ID: "ASSET-001", Name: "Alpha", Currency: "EUR", AssetType: AssetTypeEquity, CirculatingSupply: 20}
	bc.Holdings[HoldingKey(dealerKeyStr, "ASSET-001")] = &AssetHolding{AssetID: "ASSET-001", HolderID: dealerKeyStr, Balance: 20}
	bc.Holdings[HoldingKey(otherDealerKeyStr, "ASSET-001")] = &AssetHolding{AssetID: "ASSET-001", HolderID: otherDealerKeyStr, Balance: 20}

	request, err := NewRFQRequest(requesterKey, "ASSET-001", OrderSideBid, 10, 12.5, time.Now().Unix()+300)
	require.NoError(t, err)
	quote1, err := NewRFQQuote(dealerKey, request.ID, 12.0, 10, time.Now().Unix()+300)
	require.NoError(t, err)
	quote2, err := NewRFQQuote(otherDealerKey, request.ID, 12.2, 10, time.Now().Unix()+300)
	require.NoError(t, err)

	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: requesterKeyStr, RequiredSigs: 0}, Action: RFQActionRequest, Request: *request}})
	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: dealerKeyStr, RequiredSigs: 0}, Action: RFQActionQuote, Quote: *quote1}})
	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: otherDealerKeyStr, RequiredSigs: 0}, Action: RFQActionQuote, Quote: *quote2}})
	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: requesterKeyStr, RequiredSigs: 0}, Action: RFQActionAccept, Request: *request, AcceptID: quote1.ID}})

	require.Len(t, bc.Trades, 1)
	assert.Equal(t, RFQRequestStatusAccepted, bc.RFQRequests[request.ID].Status)
	assert.Equal(t, RFQQuoteStatusAccepted, bc.RFQQuotes[request.ID][0].Status)
	assert.Equal(t, RFQQuoteStatusRejected, bc.RFQQuotes[request.ID][1].Status)
	assert.InDelta(t, 10.0, bc.Holdings[HoldingKey(requesterKeyStr, "ASSET-001")].Balance, 1e-9)
	assert.InDelta(t, 10.0, bc.Holdings[HoldingKey(dealerKeyStr, "ASSET-001")].Balance, 1e-9)
	assert.Len(t, bc.RegulatoryReports, 1)

	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: requesterKeyStr, RequiredSigs: 0}, Action: RFQActionAccept, Request: *request, AcceptID: quote1.ID}})
	assert.Len(t, bc.Trades, 1)
}

func TestExpireRFQRequestsQuotesAndCancel(t *testing.T) {
	bc := newRFQTestBlockchain(t)
	requesterKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	requesterKeyStr := base64.StdEncoding.EncodeToString(requesterKey.Public().Bytes())
	dealerKeyStr := seedDesignatedMarketMaker(t, bc, "ASSET-001", dealerKey, "549300ACMECORP0022")
	req := &RFQRequest{ID: "req-1", AssetID: "ASSET-001", RequesterKey: requesterKeyStr, Side: OrderSideBid, Quantity: 5, ExpiresAt: time.Now().Unix() - 1, Status: RFQRequestStatusOpen}
	quote := &RFQQuote{ID: "q-1", RequestID: req.ID, DealerKey: dealerKeyStr, Price: 10, Quantity: 5, ExpiresAt: time.Now().Unix() - 1, Status: RFQQuoteStatusActive}
	bc.RFQRequests[req.ID] = req
	bc.RFQQuotes[req.ID] = []*RFQQuote{quote}

	bc.ExpireRFQRequests()
	bc.ExpireRFQQuotes()
	assert.Equal(t, RFQRequestStatusExpired, req.Status)
	assert.Equal(t, RFQQuoteStatusExpired, quote.Status)

	openReq := &RFQRequest{ID: "req-2", AssetID: "ASSET-001", RequesterKey: requesterKeyStr, Side: OrderSideBid, Quantity: 5, ExpiresAt: time.Now().Unix() + 300, Status: RFQRequestStatusOpen}
	activeQuote := &RFQQuote{ID: "q-2", RequestID: openReq.ID, DealerKey: dealerKeyStr, Price: 11, Quantity: 5, ExpiresAt: time.Now().Unix() + 300, Status: RFQQuoteStatusActive}
	bc.RFQRequests[openReq.ID] = openReq
	bc.RFQQuotes[openReq.ID] = []*RFQQuote{activeQuote}
	bc.SealRFQBlock([]RFQTransaction{{Tx: Transaction{Sender: requesterKeyStr, RequiredSigs: 0}, Action: RFQActionCancel, Request: *openReq}})
	assert.Equal(t, RFQRequestStatusCancelled, bc.RFQRequests[openReq.ID].Status)
	assert.Equal(t, RFQQuoteStatusRejected, bc.RFQQuotes[openReq.ID][0].Status)
}

func TestPersistence_SaveAndLoadState_RoundTripRFQState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rfq.db")
	bs, err := OpenBlockStore(path)
	require.NoError(t, err)
	defer bs.Close()

	bc := newRFQTestBlockchain(t)
	bc.RFQRequests["req-1"] = &RFQRequest{ID: "req-1", AssetID: "ASSET-001", RequesterKey: "buyer", Quantity: 5, ExpiresAt: time.Now().Unix() + 300, Status: RFQRequestStatusQuoted}
	bc.RFQQuotes["req-1"] = []*RFQQuote{{ID: "quote-1", RequestID: "req-1", DealerKey: "dealer", Price: 10, Quantity: 5, ExpiresAt: time.Now().Unix() + 300, Status: RFQQuoteStatusActive}}
	require.NoError(t, bs.SaveState(bc, 9))

	bc2 := newRFQTestBlockchain(t)
	lastApplied, err := bs.LoadState(bc2)
	require.NoError(t, err)
	assert.Equal(t, 9, lastApplied)
	require.NotNil(t, bc2.RFQRequests["req-1"])
	assert.Equal(t, RFQRequestStatusQuoted, bc2.RFQRequests["req-1"].Status)
	require.Len(t, bc2.RFQQuotes["req-1"], 1)
	assert.Equal(t, RFQQuoteStatusActive, bc2.RFQQuotes["req-1"][0].Status)
}
