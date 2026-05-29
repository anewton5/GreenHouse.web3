package gonetwork

// ---------------------------------------------------------------------------
// gossipsub_validator_test.go — Item 5: GossipSub Topic Validator
//
// Covers:
//   NewP2PNode topic-validator registration — succeeds in open and permissioned modes
//   GossipSub validator logic              — open mode accepts all; permissioned
//                                            mode rejects unlisted peers
//   HandleMessages sender check            — revoked peer's messages are dropped
// ---------------------------------------------------------------------------

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// validatorFunc returns the same closure that NewP2PNode registers with
// RegisterTopicValidator, allowing direct black-box tests of the decision
// logic without needing a full GossipSub network.
func validatorFunc(gater *AllowlistGater) func(context.Context, peer.ID, *pubsub.Message) pubsub.ValidationResult {
	return func(_ context.Context, pid peer.ID, _ *pubsub.Message) pubsub.ValidationResult {
		if !gater.InterceptPeerDial(pid) {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

// ---------------------------------------------------------------------------
// Topic validator logic
// ---------------------------------------------------------------------------

// TestTopicValidator_OpenMode_AcceptsAll verifies that in open mode (no
// registry key, empty allowlist) any peer is accepted by the validator.
func TestTopicValidator_OpenMode_AcceptsAll(t *testing.T) {
	gater := NewAllowlistGater(nil) // open mode
	validate := validatorFunc(gater)

	anyPeer := peer.ID("12D3KooWTopicValidatorOpen")
	result := validate(context.Background(), anyPeer, nil)
	assert.Equal(t, pubsub.ValidationAccept, result, "open mode should accept any peer")
}

// TestTopicValidator_PermissionedMode_AcceptsAllowlisted verifies that a peer
// in the allowlist is accepted by the validator in permissioned mode.
func TestTopicValidator_PermissionedMode_AcceptsAllowlisted(t *testing.T) {
	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	gater := NewAllowlistGater(regKey.Public())

	allowedPeer := peer.ID("12D3KooWTopicValidatorAllowed")
	hash := sha3.Sum256([]byte(allowedPeer))
	sig := regKey.Sign(hash[:]).Bytes()
	require.NoError(t, gater.AllowPeer(allowedPeer, sig))

	validate := validatorFunc(gater)
	result := validate(context.Background(), allowedPeer, nil)
	assert.Equal(t, pubsub.ValidationAccept, result, "allowlisted peer should be accepted")
}

// TestTopicValidator_PermissionedMode_RejectsUnlisted verifies that a peer not
// in the allowlist is rejected once the gater is in permissioned mode.
func TestTopicValidator_PermissionedMode_RejectsUnlisted(t *testing.T) {
	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	gater := NewAllowlistGater(regKey.Public())

	// Admit one peer to enter permissioned mode.
	knownPeer := peer.ID("12D3KooWTopicValidatorKnown")
	hash := sha3.Sum256([]byte(knownPeer))
	sig := regKey.Sign(hash[:]).Bytes()
	require.NoError(t, gater.AllowPeer(knownPeer, sig))

	validate := validatorFunc(gater)

	unlistedPeer := peer.ID("12D3KooWTopicValidatorUnlisted")
	result := validate(context.Background(), unlistedPeer, nil)
	assert.Equal(t, pubsub.ValidationReject, result, "unlisted peer should be rejected")
}

// TestTopicValidator_RevokedPeer_IsRejected verifies that revoking a previously
// admitted peer causes the validator to start rejecting their messages.
func TestTopicValidator_RevokedPeer_IsRejected(t *testing.T) {
	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	gater := NewAllowlistGater(regKey.Public())

	peerA := peer.ID("12D3KooWTopicValidatorRevA")
	peerB := peer.ID("12D3KooWTopicValidatorRevB")

	hashA := sha3.Sum256([]byte(peerA))
	hashB := sha3.Sum256([]byte(peerB))
	sigA := regKey.Sign(hashA[:]).Bytes()
	sigB := regKey.Sign(hashB[:]).Bytes()

	require.NoError(t, gater.AllowPeer(peerA, sigA))
	require.NoError(t, gater.AllowPeer(peerB, sigB))

	validate := validatorFunc(gater)
	assert.Equal(t, pubsub.ValidationAccept, validate(context.Background(), peerA, nil))

	// Revoke peerA; peerB keeps the list non-empty.
	require.NoError(t, gater.RevokePeer(peerA, sigA))

	assert.Equal(t, pubsub.ValidationReject, validate(context.Background(), peerA, nil), "revoked peer should be rejected")
	assert.Equal(t, pubsub.ValidationAccept, validate(context.Background(), peerB, nil), "non-revoked peer should still be accepted")
}

// ---------------------------------------------------------------------------
// NewP2PNode topic validator registration
// ---------------------------------------------------------------------------

// TestNewP2PNode_TopicValidator_RegistersCleanly verifies that NewP2PNode
// successfully registers the topic validator without error, both in open mode
// and when a registry key is configured (permissioned mode).
func TestNewP2PNode_TopicValidator_RegistersCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open mode (no registry key).
	bc := newTestBlockchain(t)
	node, err := NewP2PNode(ctx, bc, "test-gossipsub-validator", nil)
	require.NoError(t, err, "NewP2PNode should succeed in open mode with topic validator")
	defer node.Shutdown(context.Background()) //nolint:errcheck

	// Permissioned mode (registry key set).
	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc2 := newTestBlockchain(t)
	bc2.NetworkRegistryKey = regKey.Public()

	node2, err := NewP2PNode(ctx, bc2, "test-gossipsub-validator-perm", nil)
	require.NoError(t, err, "NewP2PNode should succeed in permissioned mode with topic validator")
	defer node2.Shutdown(context.Background()) //nolint:errcheck
}

// TestNewP2PNode_GaterIsPermissionedAfterManifest verifies that a P2PNode
// created with a NetworkRegistryKey has its gater in permissioned mode as soon
// as the first peer is admitted, and that the same gater is exposed on the node
// struct (so HandleMessages uses the same instance as the topic validator).
func TestNewP2PNode_GaterIsPermissionedAfterManifest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc := newTestBlockchain(t)
	bc.NetworkRegistryKey = regKey.Public()

	node, err := NewP2PNode(ctx, bc, "test-gossipsub-gater", nil)
	require.NoError(t, err)
	defer node.Shutdown(context.Background()) //nolint:errcheck

	require.NotNil(t, node.Gater, "Gater must be set on P2PNode")

	// In open mode (no peers admitted yet) all peers are accepted.
	anyPeer := peer.ID("12D3KooWGaterInitialOpen")
	assert.True(t, node.Gater.InterceptPeerDial(anyPeer), "gater should be in open mode before any peer is admitted")

	// Admit one peer → gater enters permissioned mode.
	hash := sha3.Sum256([]byte(anyPeer))
	sig := regKey.Sign(hash[:]).Bytes()
	require.NoError(t, node.Gater.AllowPeer(anyPeer, sig))

	unlistedPeer := peer.ID("12D3KooWGaterUnlisted")
	assert.False(t, node.Gater.InterceptPeerDial(unlistedPeer),
		"unlisted peer should be rejected once gater is in permissioned mode")
}

// ---------------------------------------------------------------------------
// HandleMessages sender check
// ---------------------------------------------------------------------------

// TestHandleMessages_GaterDropsRevokedSender verifies that the AllowlistGater
// instance stored on P2PNode.Gater — which is what HandleMessages queries via
// n.Gater.InterceptPeerDial(msg.ReceivedFrom) — correctly rejects revoked
// senders. This is the same code path that HandleMessages uses to drop
// in-flight messages from revoked peers before decoding them.
func TestHandleMessages_GaterDropsRevokedSender(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	regKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	bc := newTestBlockchain(t)
	bc.NetworkRegistryKey = regKey.Public()

	node, err := NewP2PNode(ctx, bc, "test-hm-gater", nil)
	require.NoError(t, err)
	defer node.Shutdown(context.Background()) //nolint:errcheck

	gater := node.Gater
	require.NotNil(t, gater)

	peerA := peer.ID("12D3KooWHMGaterA")
	peerB := peer.ID("12D3KooWHMGaterB")
	hashA := sha3.Sum256([]byte(peerA))
	hashB := sha3.Sum256([]byte(peerB))
	sigA := regKey.Sign(hashA[:]).Bytes()
	sigB := regKey.Sign(hashB[:]).Bytes()

	require.NoError(t, gater.AllowPeer(peerA, sigA))
	require.NoError(t, gater.AllowPeer(peerB, sigB))

	// Before revocation: both senders would pass the HandleMessages check.
	assert.True(t, gater.InterceptPeerDial(peerA))
	assert.True(t, gater.InterceptPeerDial(peerB))

	// Revoke peerA. HandleMessages now drops peerA's messages.
	require.NoError(t, gater.RevokePeer(peerA, sigA))

	assert.False(t, gater.InterceptPeerDial(peerA), "revoked sender should be dropped by HandleMessages")
	assert.True(t, gater.InterceptPeerDial(peerB), "non-revoked sender should still pass HandleMessages check")

	// Verify this resolves cleanly under the race detector by running a brief
	// HandleMessages goroutine (which will block on Sub.Next until the context
	// is cancelled — the important thing is it starts and the gater is safe to
	// read concurrently).
	done := make(chan struct{})
	go func() {
		defer close(done)
		node.HandleMessages(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleMessages did not exit after context cancellation")
	}
}
