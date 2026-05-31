package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gonetwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMetrics_ExportsLabeledCounters(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "dbft")

	bc := gonetwork.NewBlockchain(context.Background(), "metrics-test")
	server := NewServer(bc, ":0")

	// Trigger mode-gated reject by path="SealBlock" in dbft mode.
	bc.SealBlock(nil, nil, nil)

	// Trigger duplicate rejection reason="already_committed".
	key, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	sender := base64.StdEncoding.EncodeToString(key.Public().Bytes())
	tx := gonetwork.Transaction{Sender: sender, Receiver: "recv", Amount: 10, RequiredSigs: 0, Nonce: 1}
	bc.AddBlock(gonetwork.Block{Transactions: []gonetwork.Transaction{tx}})
	candidate := gonetwork.Block{Transactions: []gonetwork.Transaction{tx}, PrevHash: bc.GetLastBlockHash()}
	assert.False(t, bc.ValidateBlock(candidate))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.handleMetrics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, body, "# TYPE gonetwork_consensus_mode_rejections_total counter")
	assert.Contains(t, body, "gonetwork_consensus_mode_rejections_total 1")
	assert.Contains(t, body, "gonetwork_consensus_mode_rejections_by_path_total{path=\"SealBlock\"} 1")
	assert.Contains(t, body, "gonetwork_duplicate_transaction_rejections_total 1")
	assert.Contains(t, body, "gonetwork_duplicate_transaction_rejections_by_reason_total{reason=\"already_committed\"} 1")
	assert.Contains(t, body, "gonetwork_consensus_mode_active{mode=\"dbft\"} 1")
}

func TestHandleMetrics_EscapesPrometheusLabels(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "dbft")

	bc := gonetwork.NewBlockchain(context.Background(), "metrics-escape-test")
	server := NewServer(bc, ":0")

	// exercise label escape path directly
	escaped := prometheusEscapeLabelValue("path\"x\\y\n")
	require.Equal(t, "path\\\"x\\\\y\\n", escaped)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.handleMetrics(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, strings.Contains(rec.Body.String(), "gonetwork_consensus_mode_active"))
}
