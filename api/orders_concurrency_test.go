package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"gonetwork"

	"github.com/stretchr/testify/require"
)

// TestHandlePlaceOrder_ConcurrentRequests_NoRace exercises the bc.Mu locking
// fix for handlePlaceOrder: many goroutines placing orders against the same
// asset concurrently must not race on s.bc.OrderBooks (previously mutated
// without holding bc.Mu, which could panic the process with "fatal error:
// concurrent map writes" or silently drop orders). Run with `go test -race`
// to verify the fix actually closes the race.
func TestHandlePlaceOrder_ConcurrentRequests_NoRace(t *testing.T) {
	t.Setenv("GONETWORK_NO_P2P", "1")
	t.Setenv("GREENHOUSE_CONSENSUS_MODE", "http")
	bc := gonetwork.NewBlockchain(context.Background(), "concurrency-place-order-test")
	bc.Assets["ASSET-1"] = &gonetwork.Asset{ID: "ASSET-1", Name: "Alpha", Currency: "EUR", TotalSupply: 1_000_000}
	server := NewServer(bc, ":0")

	traderKey, err := gonetwork.GeneratePrivateKey()
	require.NoError(t, err)
	traderWallet := base64.StdEncoding.EncodeToString(traderKey.Public().Bytes())
	token, err := server.issueJWT(traderWallet)
	require.NoError(t, err)
	seedApprovedRegistration(server, traderWallet)

	const numRequests = 50
	var wg sync.WaitGroup
	statusCodes := make([]int, numRequests)
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"asset_id":"ASSET-1","side":"buy","type":"limit","price":10.5,"quantity":%d}`, i+1)
			req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			statusCodes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	for i, code := range statusCodes {
		require.Equalf(t, http.StatusCreated, code, "request %d should succeed", i)
	}

	total := 0
	for _, ob := range bc.OrderBooks {
		total += len(ob.Bids) + len(ob.Asks)
	}
	require.Equal(t, numRequests, total, "every concurrently-placed order must be recorded exactly once")
}
