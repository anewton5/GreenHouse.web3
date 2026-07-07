package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gonetwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedApprovedRegistration(server *Server, walletKey string) {
	server.RegRegistry.Upsert(&gonetwork.RegistrationRecord{WalletKey: walletKey, Status: gonetwork.RegistrationStatusApproved})
}

func seedAPIDesignatedMarketMaker(t *testing.T, bc *gonetwork.Blockchain, assetID string, dealerWalletKey, lei string) {
	t.Helper()
	issuerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	operatorKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	claim, err := gonetwork.NewClaim(gonetwork.ClaimTopicInstitutionalRole, "", dealerWalletKey, gonetwork.EntityRoleClaimData(lei, gonetwork.EntityRoleMarketMaker), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[dealerWalletKey] = []*gonetwork.Claim{claim}
	agreement, err := gonetwork.NewMarketMakerAgreement(operatorKey, assetID, dealerWalletKey, lei, 5, 50, 1, 10, 0, 0, time.Now().Unix(), 0)
	require.NoError(t, err)
	require.NoError(t, bc.MarketMakerRegistry.RegisterMarketMaker(agreement))
}

func TestRFQRoutes_CreateAndListRequest(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	bc := gonetwork.NewBlockchain(context.Background(), "rfq-api-create-test")
	bc.Assets["ASSET-1"] = &gonetwork.Asset{ID: "ASSET-1", Name: "Alpha", Currency: "EUR"}
	server := NewServer(bc, ":0")
	requesterKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	requesterWallet := base64.StdEncoding.EncodeToString(requesterKey.Public().Bytes())
	dealerWallet := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	requesterToken, err := server.issueJWT(requesterWallet)
	require.NoError(t, err)
	dealerToken, err := server.issueJWT(dealerWallet)
	require.NoError(t, err)
	seedApprovedRegistration(server, requesterWallet)
	seedApprovedRegistration(server, dealerWallet)
	seedAPIDesignatedMarketMaker(t, bc, "ASSET-1", dealerWallet, "549300ACMECORP0030")

	body := `{"asset_id":"ASSET-1","side":"buy","quantity":5,"limit_price":10,"ttl_seconds":300}`
	req := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+requesterToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	var created gonetwork.RFQRequest
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))

	listReq := httptest.NewRequest(http.MethodGet, "/v1/rfq/requests?assetID=ASSET-1", nil)
	listReq.Header.Set("Authorization", "Bearer "+dealerToken)
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	var listed struct {
		Requests []gonetwork.RFQRequest `json:"requests"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&listed))
	require.Len(t, listed.Requests, 1)
	assert.Equal(t, created.ID, listed.Requests[0].ID)
}

func TestRFQRoutes_QuoteEndpointRoleGateAndListQuotes(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	bc := gonetwork.NewBlockchain(context.Background(), "rfq-api-quote-test")
	bc.Assets["ASSET-1"] = &gonetwork.Asset{ID: "ASSET-1", Name: "Alpha", Currency: "EUR"}
	server := NewServer(bc, ":0")
	requesterKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	requesterWallet := base64.StdEncoding.EncodeToString(requesterKey.Public().Bytes())
	dealerWallet := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	requesterToken, _ := server.issueJWT(requesterWallet)
	dealerToken, _ := server.issueJWT(dealerWallet)
	nonMMToken, _ := server.issueJWT("other-wallet")
	seedApprovedRegistration(server, requesterWallet)
	seedApprovedRegistration(server, dealerWallet)
	seedApprovedRegistration(server, "other-wallet")
	seedAPIDesignatedMarketMaker(t, bc, "ASSET-1", dealerWallet, "549300ACMECORP0031")

	createReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests", strings.NewReader(`{"asset_id":"ASSET-1","side":"buy","quantity":5,"limit_price":10,"ttl_seconds":300}`))
	createReq.Header.Set("Authorization", "Bearer "+requesterToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)
	var created gonetwork.RFQRequest
	require.NoError(t, json.NewDecoder(createRec.Body).Decode(&created))

	forbiddenReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests/"+created.ID+"/quotes", strings.NewReader(`{"price":10,"quantity":5,"ttl_seconds":300}`))
	forbiddenReq.Header.Set("Authorization", "Bearer "+nonMMToken)
	forbiddenReq.Header.Set("Content-Type", "application/json")
	forbiddenRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(forbiddenRec, forbiddenReq)
	assert.Equal(t, http.StatusForbidden, forbiddenRec.Code)

	quoteReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests/"+created.ID+"/quotes", strings.NewReader(`{"price":10,"quantity":5,"ttl_seconds":300}`))
	quoteReq.Header.Set("Authorization", "Bearer "+dealerToken)
	quoteReq.Header.Set("Content-Type", "application/json")
	quoteRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(quoteRec, quoteReq)
	require.Equal(t, http.StatusCreated, quoteRec.Code)

	quoteListForbidden := httptest.NewRequest(http.MethodGet, "/v1/rfq/requests/"+created.ID+"/quotes", nil)
	quoteListForbidden.Header.Set("Authorization", "Bearer "+dealerToken)
	quoteListForbiddenRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(quoteListForbiddenRec, quoteListForbidden)
	assert.Equal(t, http.StatusForbidden, quoteListForbiddenRec.Code)

	quoteListReq := httptest.NewRequest(http.MethodGet, "/v1/rfq/requests/"+created.ID+"/quotes", nil)
	quoteListReq.Header.Set("Authorization", "Bearer "+requesterToken)
	quoteListRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(quoteListRec, quoteListReq)
	require.Equal(t, http.StatusOK, quoteListRec.Code)
	var quotes struct {
		Quotes []gonetwork.RFQQuote `json:"quotes"`
	}
	require.NoError(t, json.NewDecoder(quoteListRec.Body).Decode(&quotes))
	require.Len(t, quotes.Quotes, 1)
}

func TestRFQRoutes_AcceptAndCancel(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	bc := gonetwork.NewBlockchain(context.Background(), "rfq-api-accept-test")
	requesterKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	dealerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	requesterWallet := base64.StdEncoding.EncodeToString(requesterKey.Public().Bytes())
	dealerWallet := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	bc.Assets["ASSET-1"] = &gonetwork.Asset{ID: "ASSET-1", Name: "Alpha", Currency: "EUR", AssetType: gonetwork.AssetTypeEquity, CirculatingSupply: 20}
	bc.Holdings[gonetwork.HoldingKey(dealerWallet, "ASSET-1")] = &gonetwork.AssetHolding{AssetID: "ASSET-1", HolderID: dealerWallet, Balance: 20}
	server := NewServer(bc, ":0")
	requesterToken, _ := server.issueJWT(requesterWallet)
	dealerToken, _ := server.issueJWT(dealerWallet)
	seedApprovedRegistration(server, requesterWallet)
	seedApprovedRegistration(server, dealerWallet)
	seedAPIDesignatedMarketMaker(t, bc, "ASSET-1", dealerWallet, "549300ACMECORP0032")

	createReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests", strings.NewReader(`{"asset_id":"ASSET-1","side":"buy","quantity":5,"limit_price":10,"ttl_seconds":300}`))
	createReq.Header.Set("Authorization", "Bearer "+requesterToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)
	var created gonetwork.RFQRequest
	require.NoError(t, json.NewDecoder(createRec.Body).Decode(&created))

	quoteReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests/"+created.ID+"/quotes", strings.NewReader(`{"price":10,"quantity":5,"ttl_seconds":300}`))
	quoteReq.Header.Set("Authorization", "Bearer "+dealerToken)
	quoteReq.Header.Set("Content-Type", "application/json")
	quoteRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(quoteRec, quoteReq)
	require.Equal(t, http.StatusCreated, quoteRec.Code)
	var quote gonetwork.RFQQuote
	require.NoError(t, json.NewDecoder(quoteRec.Body).Decode(&quote))

	acceptReq := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests/"+created.ID+"/accept", strings.NewReader(`{"quote_id":"`+quote.ID+`"}`))
	acceptReq.Header.Set("Authorization", "Bearer "+requesterToken)
	acceptReq.Header.Set("Content-Type", "application/json")
	acceptRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(acceptRec, acceptReq)
	require.Equal(t, http.StatusOK, acceptRec.Code)
	assert.Len(t, bc.Trades, 1)
	assert.Equal(t, gonetwork.RFQRequestStatusAccepted, bc.RFQRequests[created.ID].Status)

	createReq2 := httptest.NewRequest(http.MethodPost, "/v1/rfq/requests", strings.NewReader(`{"asset_id":"ASSET-1","side":"buy","quantity":2,"limit_price":9,"ttl_seconds":300}`))
	createReq2.Header.Set("Authorization", "Bearer "+requesterToken)
	createReq2.Header.Set("Content-Type", "application/json")
	createRec2 := httptest.NewRecorder()
	server.Routes().ServeHTTP(createRec2, createReq2)
	require.Equal(t, http.StatusCreated, createRec2.Code)
	var created2 gonetwork.RFQRequest
	require.NoError(t, json.NewDecoder(createRec2.Body).Decode(&created2))

	cancelReq := httptest.NewRequest(http.MethodDelete, "/v1/rfq/requests/"+created2.ID, nil)
	cancelReq.Header.Set("Authorization", "Bearer "+requesterToken)
	cancelRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(cancelRec, cancelReq)
	require.Equal(t, http.StatusOK, cancelRec.Code)
	assert.Equal(t, gonetwork.RFQRequestStatusCancelled, bc.RFQRequests[created2.ID].Status)
}
