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

func TestMarketMakerRoutes_AdminOnlyEnforced(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	t.Setenv("GREENHOUSE_ADMIN_WALLET_KEYS", "admin-wallet")

	bc := gonetwork.NewBlockchain(context.Background(), "market-makers-admin-test")
	operatorKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = gonetwork.NewLocalKeyProvider(operatorKey)
	server := NewServer(bc, ":0")
	token, err := server.issueJWT("non-admin-wallet")
	require.NoError(t, err)

	body := `{"asset_id":"ASSET-1","dealer_key":"Zm9v","dealer_lei":"549300ACMECORP0011","fee_rebate_bps":5,"max_spread_bps":50,"min_quote_size":1,"priority_allocation_pct":10}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/market-makers", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMarketMakerRoutes_DealerRolePrecondition(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	t.Setenv("GREENHOUSE_ADMIN_WALLET_KEYS", "admin-wallet")

	bc := gonetwork.NewBlockchain(context.Background(), "market-makers-role-test")
	operatorKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = gonetwork.NewLocalKeyProvider(operatorKey)
	server := NewServer(bc, ":0")
	token, err := server.issueJWT("admin-wallet")
	require.NoError(t, err)
	dealerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())

	body := `{"asset_id":"ASSET-1","dealer_key":"` + dealerKeyStr + `","dealer_lei":"549300ACMECORP0012","fee_rebate_bps":5,"max_spread_bps":50,"min_quote_size":1,"priority_allocation_pct":10}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/market-makers", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestMarketMakerRoutes_CreateListAndRevoke(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	t.Setenv("GREENHOUSE_ADMIN_WALLET_KEYS", "admin-wallet")

	bc := gonetwork.NewBlockchain(context.Background(), "market-makers-happy-test")
	operatorKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	bc.OperatorKeyProvider = gonetwork.NewLocalKeyProvider(operatorKey)
	server := NewServer(bc, ":0")
	adminToken, err := server.issueJWT("admin-wallet")
	require.NoError(t, err)
	userToken, err := server.issueJWT("viewer-wallet")
	require.NoError(t, err)

	dealerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	issuerKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	dealerKeyStr := base64.StdEncoding.EncodeToString(dealerKey.Public().Bytes())
	lei := "549300ACMECORP0013"
	claim, err := gonetwork.NewClaim(gonetwork.ClaimTopicInstitutionalRole, "", dealerKeyStr, gonetwork.EntityRoleClaimData(lei, gonetwork.EntityRoleMarketMaker), 30, issuerKey)
	require.NoError(t, err)
	bc.Claims[dealerKeyStr] = []*gonetwork.Claim{claim}

	body := `{"asset_id":"ASSET-1","dealer_key":"` + dealerKeyStr + `","dealer_lei":"` + lei + `","fee_rebate_bps":5,"max_spread_bps":50,"min_quote_size":2,"priority_allocation_pct":10,"max_position_units":500,"max_position_value":100000,"effective_from":` + json.Number("0").String() + `}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/admin/market-makers", strings.NewReader(body))
	createReq.Header.Set("Authorization", "Bearer "+adminToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()

	server.Routes().ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)
	var created gonetwork.MarketMakerAgreement
	require.NoError(t, json.NewDecoder(createRec.Body).Decode(&created))
	assert.Equal(t, "ASSET-1", created.AssetID)
	assert.Equal(t, dealerKeyStr, created.DealerKey)
	assert.Equal(t, gonetwork.MarketMakerStatusActive, created.Status)
	assert.NotEmpty(t, created.ID)

	listReq := httptest.NewRequest(http.MethodGet, "/v1/market-makers/ASSET-1", nil)
	listReq.Header.Set("Authorization", "Bearer "+userToken)
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	var listed struct {
		AssetID    string                           `json:"asset_id"`
		Agreements []gonetwork.MarketMakerAgreement `json:"agreements"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&listed))
	require.Len(t, listed.Agreements, 1)
	assert.Equal(t, created.ID, listed.Agreements[0].ID)

	revokeReq := httptest.NewRequest(http.MethodDelete, "/v1/admin/market-makers/"+created.ID, nil)
	revokeReq.Header.Set("Authorization", "Bearer "+adminToken)
	revokeRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code)
	assert.Equal(t, gonetwork.MarketMakerStatusRevoked, bc.MarketMakerRegistry.AgreementByID(created.ID).Status)

	listReq2 := httptest.NewRequest(http.MethodGet, "/v1/market-makers/ASSET-1", nil)
	listReq2.Header.Set("Authorization", "Bearer "+userToken)
	listRec2 := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec2, listReq2)
	require.Equal(t, http.StatusOK, listRec2.Code)
	var listedAfter struct {
		Agreements []gonetwork.MarketMakerAgreement `json:"agreements"`
	}
	require.NoError(t, json.NewDecoder(listRec2.Body).Decode(&listedAfter))
	assert.Len(t, listedAfter.Agreements, 0)
	assert.True(t, bc.MarketMakerRegistry.AgreementByID(created.ID).CreatedAt <= time.Now().Unix())
}
