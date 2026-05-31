package gonetwork

// ---------------------------------------------------------------------------
// p2p_dht_production_test.go — Item 17: DHT disabled in production
//
// Acceptance criteria:
//   1. GH_ENV=production + no GREENHOUSE_PEER_MANIFEST → NewP2PNode returns
//      an error containing "GREENHOUSE_PEER_MANIFEST".
//   2. GH_ENV=production + valid manifest file     → NewP2PNode succeeds,
//      node has a working Host and PubSub, no DHT goroutine is launched.
//   3. GH_ENV unset (dev/test mode)               → NewP2PNode succeeds
//      (DHT behaviour unchanged — regression guard).
// ---------------------------------------------------------------------------

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// p2pTestBC returns the smallest valid *Blockchain that NewP2PNode requires.
// We construct it directly (bypassing NewBlockchain) so that tests can set
// GH_ENV=production without triggering the production mock-guard in NewBlockchain.
func p2pTestBC() *Blockchain {
	return &Blockchain{
		// NetworkRegistryKey nil → gater runs in open mode (acceptable for tests)
	}
}

// ---------------------------------------------------------------------------
// Step B — production guard: no manifest → error
// ---------------------------------------------------------------------------

func TestNewP2PNode_Production_NoManifest_ReturnsError(t *testing.T) {
	t.Setenv("GH_ENV", "production")
	// Ensure GREENHOUSE_PEER_MANIFEST is explicitly unset for this test.
	t.Setenv("GREENHOUSE_PEER_MANIFEST", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := NewP2PNode(ctx, p2pTestBC(), "test-topic", nil)
	require.Error(t, err, "production mode without a peer manifest must return an error")
	assert.Contains(t, err.Error(), "GREENHOUSE_PEER_MANIFEST",
		"error must identify the missing env var so operators know how to fix it")
}

// ---------------------------------------------------------------------------
// Step A — production mode with manifest: DHT must NOT be launched
// ---------------------------------------------------------------------------

func TestNewP2PNode_Production_WithManifest_Succeeds(t *testing.T) {
	// Write a minimal valid manifest (empty array — no peers to add).
	manifestFile, err := os.CreateTemp(t.TempDir(), "manifest*.json")
	require.NoError(t, err)
	_, err = manifestFile.WriteString("[]")
	require.NoError(t, err)
	require.NoError(t, manifestFile.Close())

	t.Setenv("GH_ENV", "production")
	t.Setenv("GREENHOUSE_PEER_MANIFEST", manifestFile.Name())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node, err := NewP2PNode(ctx, p2pTestBC(), "test-topic", nil)
	require.NoError(t, err, "production mode with a peer manifest must start successfully")
	defer node.Shutdown(ctx) //nolint:errcheck

	// Core node components must be initialised.
	require.NotNil(t, node.Host, "Host must be initialised in production mode")
	require.NotNil(t, node.PubSub, "PubSub must be initialised in production mode")
	require.NotNil(t, node.Topic, "Topic must be initialised in production mode")

	// cancelBackground must always be set so Shutdown can call it safely.
	require.NotNil(t, node.cancelBackground, "cancelBackground must be set even when DHT is disabled")
}

func TestNewP2PNode_Production_WithManifest_MdnsDisabled(t *testing.T) {
	manifestFile, err := os.CreateTemp(t.TempDir(), "manifest*.json")
	require.NoError(t, err)
	_, err = manifestFile.WriteString("[]")
	require.NoError(t, err)
	require.NoError(t, manifestFile.Close())

	t.Setenv("GH_ENV", "production")
	t.Setenv("GREENHOUSE_PEER_MANIFEST", manifestFile.Name())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node, err := NewP2PNode(ctx, p2pTestBC(), "test-topic", nil)
	require.NoError(t, err)
	defer node.Shutdown(ctx) //nolint:errcheck

	// In production mDNS is also disabled (existing gate from earlier items).
	assert.Nil(t, node.MdnsService, "mDNS must not be started in production mode")
}

// ---------------------------------------------------------------------------
// Step A (regression) — dev/test mode: DHT behaviour unchanged
// ---------------------------------------------------------------------------

func TestNewP2PNode_DevMode_StartsSuccessfully(t *testing.T) {
	// Ensure GH_ENV and peer manifest are NOT set so we exercise dev/test path.
	t.Setenv("GH_ENV", "")
	t.Setenv("GREENHOUSE_PEER_MANIFEST", "")
	t.Setenv("GONETWORK_DISABLE_P2P_DHT", "")
	t.Setenv("GONETWORK_DISABLE_P2P_MDNS", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node, err := NewP2PNode(ctx, p2pTestBC(), "test-topic", nil)
	require.NoError(t, err, "dev mode must start without a manifest")
	defer node.Shutdown(ctx) //nolint:errcheck

	require.NotNil(t, node.Host)
	require.NotNil(t, node.PubSub)
}

// ---------------------------------------------------------------------------
// Shutdown safety — cancelBackground must not panic regardless of DHT state
// ---------------------------------------------------------------------------

func TestNewP2PNode_Production_Shutdown_Safe(t *testing.T) {
	manifestFile, err := os.CreateTemp(t.TempDir(), "manifest*.json")
	require.NoError(t, err)
	_, err = manifestFile.WriteString("[]")
	require.NoError(t, err)
	require.NoError(t, manifestFile.Close())

	t.Setenv("GH_ENV", "production")
	t.Setenv("GREENHOUSE_PEER_MANIFEST", manifestFile.Name())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node, err := NewP2PNode(ctx, p2pTestBC(), "test-topic", nil)
	require.NoError(t, err)

	// Shutdown must not panic even though the DHT goroutine was never started.
	assert.NotPanics(t, func() {
		_ = node.Shutdown(ctx)
	})
}
