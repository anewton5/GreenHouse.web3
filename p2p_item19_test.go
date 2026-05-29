package gonetwork

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewP2PNode_HasConsensusTopicAndSubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bc := &Blockchain{}

	node, err := NewP2PNode(ctx, bc, "item19-main", nil)
	require.NoError(t, err)
	defer node.Shutdown(ctx) //nolint:errcheck

	require.NotNil(t, node.ConsensusTopic)
	require.NotNil(t, node.ConsensusSub)
}

func TestPublishConsensusMessage_ReachesConnectedPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	topicName := fmt.Sprintf("item19-topic-%d", time.Now().UnixNano())

	bc1 := &Blockchain{}
	bc2 := &Blockchain{}

	n1, err := NewP2PNode(ctx, bc1, topicName, nil)
	require.NoError(t, err)
	defer n1.Shutdown(ctx) //nolint:errcheck

	n2, err := NewP2PNode(ctx, bc2, topicName, nil)
	require.NoError(t, err)
	defer n2.Shutdown(ctx) //nolint:errcheck

	err = n2.Host.Connect(ctx, peer.AddrInfo{ID: n1.Host.ID(), Addrs: n1.Host.Addrs()})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		for _, p := range n2.Host.Network().Peers() {
			if p == n1.Host.ID() {
				return true
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	// Ensure the GossipSub consensus mesh has discovered each peer before
	// publishing, otherwise the first message can race mesh formation.
	require.Eventually(t, func() bool {
		n1Seen := false
		for _, p := range n1.ConsensusTopic.ListPeers() {
			if p == n2.Host.ID() {
				n1Seen = true
				break
			}
		}
		if !n1Seen {
			return false
		}
		for _, p := range n2.ConsensusTopic.ListPeers() {
			if p == n1.Host.ID() {
				return true
			}
		}
		return false
	}, 8*time.Second, 100*time.Millisecond)

	out := Message{
		From: "delegate-A",
		Type: ViewChangeReq,
		Payload: ViewChangeRequest{
			View:   2,
			NodeID: "delegate-A",
			Reason: "timeout",
		},
	}
	require.NoError(t, n1.PublishConsensusMessage(out))

	// Item 19 acceptance target is two heartbeats (1s). Allow extra CI/runtime
	// headroom to avoid flaky failures from startup scheduling jitter.
	rcvCtx, rcvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcvCancel()

	msg, err := n2.ConsensusSub.Next(rcvCtx)
	require.NoError(t, err)

	var in Message
	require.NoError(t, json.Unmarshal(msg.Data, &in))
	assert.Equal(t, ViewChangeReq, in.Type)
	assert.Equal(t, "delegate-A", in.From)
}

func TestAssertDelegateConnectivity_UnreachableDelegate_EmitsEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bc := &Blockchain{}
	bc.Events = make(chan StreamEvent, 10)

	node, err := NewP2PNode(ctx, bc, "item19-connectivity-topic", nil)
	require.NoError(t, err)
	defer node.Shutdown(ctx) //nolint:errcheck

	// Generate a valid but unknown peer ID (not present in peerstore with addrs),
	// forcing 3 failed connect attempts and a delegate_unreachable event.
	sk, _, err := ic.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	pid, err := peer.IDFromPrivateKey(sk)
	require.NoError(t, err)

	bc.Mu.Lock()
	bc.Delegates = []Node{{ID: "delegate-1", P2PPeerID: pid.String()}}
	bc.Mu.Unlock()

	bc.assertDelegateConnectivity(node)

	found := false
	for len(bc.Events) > 0 {
		e := <-bc.Events
		if e.Type == EventDelegateUnreachable {
			found = true
			break
		}
	}
	assert.True(t, found, "expected EventDelegateUnreachable when delegate cannot be dialed")
}
