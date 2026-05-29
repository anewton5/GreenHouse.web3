package gonetwork

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestTunedGossipSubParams_ValidatorSizedMesh(t *testing.T) {
	p := tunedGossipSubParams(5)
	require.Equal(t, 4, p.D)
	require.Equal(t, 3, p.Dlo)
	require.Equal(t, 5, p.Dhi)
	require.Equal(t, 4, p.Dscore)
	require.Equal(t, 1, p.Dout)
	require.Equal(t, 500*time.Millisecond, p.HeartbeatInterval)
}

func TestTunedGossipSubParams_ClampsExtremes(t *testing.T) {
	low := tunedGossipSubParams(1)
	assert.Equal(t, 4, low.D)
	assert.Equal(t, 3, low.Dlo)
	assert.Equal(t, 5, low.Dhi)

	high := tunedGossipSubParams(30)
	assert.Equal(t, 8, high.D)
	assert.Equal(t, 7, high.Dlo)
	assert.Equal(t, 9, high.Dhi)
}

func TestP2PNodeLimiter_ThrottlesBurst(t *testing.T) {
	n := &P2PNode{limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 10)}

	start := time.Now()
	for i := 0; i < 20; i++ {
		require.NoError(t, n.limiter.Wait(t.Context()))
	}
	elapsed := time.Since(start)

	// First 10 tokens are immediate (burst), next 10 are ~100ms each.
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond)
}
