package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gonetwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleProposeCorporateAction_StoresExplicitFields(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "corp-action-fields-test")
	server := NewServer(bc, ":0")

	body := `{"asset_id":"asset-1","action_type":"dividend","record_date":1893456000,"price_per_unit":1.25,"total_units":1000,"required_threshold":0.67}`
	req := httptest.NewRequest(http.MethodPost, "/v1/corporate-actions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), walletKeyCtxKey{}, "issuer-wallet"))
	rec := httptest.NewRecorder()

	server.handleProposeCorporateAction(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	var got gonetwork.CorporateAction
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, "asset-1", got.AssetID)
	assert.Equal(t, gonetwork.CorporateActionType("dividend"), got.Type)
	assert.Equal(t, int64(1893456000), got.DeadlineAt)
	assert.Equal(t, 1.25, got.PricePerUnit)
	assert.Equal(t, 1000.0, got.TotalUnits)
	assert.Equal(t, 0.67, got.RequiredThreshold)
	assert.Equal(t, "issuer-wallet", got.ProposerKey)
	assert.NotZero(t, got.CreatedAt)
	stored, exists := bc.PendingCorporateActions[got.ID]
	assert.True(t, exists)
	require.NotNil(t, stored)
	require.NotNil(t, stored.Responses)
}

func TestHandleProposeCorporateAction_InvalidThreshold_Returns400(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")

	bc := gonetwork.NewBlockchain(context.Background(), "corp-action-threshold-test")
	server := NewServer(bc, ":0")

	body := `{"asset_id":"asset-1","action_type":"rofr","record_date":1893456000,"required_threshold":1.5}`
	req := httptest.NewRequest(http.MethodPost, "/v1/corporate-actions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), walletKeyCtxKey{}, "issuer-wallet"))
	rec := httptest.NewRecorder()

	server.handleProposeCorporateAction(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
