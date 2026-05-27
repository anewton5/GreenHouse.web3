package gonetwork

// ---------------------------------------------------------------------------
// p2p_broadcast_test.go — MockP2PNode coverage
//
// Covers:
//   MockP2PNode.AddPeer / GetPeers (both at 0%)
//   MockP2PNode.BroadcastTransaction / BroadcastBlock
//   MockP2PNode.SendMessage / SendPing
//   MockP2PNode.HandleMessages
//   MockP2PNode.Shutdown
//   NewMockP2PNode constructor
// ---------------------------------------------------------------------------

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMockP2P returns a MockP2PNode without needing a real libp2p host.
func newTestMockP2P(t *testing.T) *MockP2PNode {
	t.Helper()
	bc := NewBlockchain(context.Background(), "p2p-test")
	node, err := NewMockP2PNode(context.Background(), bc, "test-topic", nil)
	require.NoError(t, err)
	require.NotNil(t, node)
	return node
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewMockP2PNode_HasTopicAndID(t *testing.T) {
	m := newTestMockP2P(t)
	assert.NotEmpty(t, m.NodeID)
	assert.NotNil(t, m.Topic)
	assert.Empty(t, m.Peers)
}

// ---------------------------------------------------------------------------
// AddPeer / GetPeers
// ---------------------------------------------------------------------------

func TestMockP2PNode_GetPeers_EmptyInitially(t *testing.T) {
	m := newTestMockP2P(t)
	assert.Empty(t, m.GetPeers())
}

func TestMockP2PNode_AddPeer_AppendsPeerID(t *testing.T) {
	m1 := newTestMockP2P(t)
	m2 := newTestMockP2P(t)

	m1.AddPeer(m2)

	peers := m1.GetPeers()
	require.Len(t, peers, 1)
	assert.Equal(t, m2.NodeID, peers[0])
}

func TestMockP2PNode_AddPeer_MultiplepeersAccumulate(t *testing.T) {
	m1 := newTestMockP2P(t)
	m2 := newTestMockP2P(t)
	m3 := newTestMockP2P(t)

	m1.AddPeer(m2)
	m1.AddPeer(m3)

	assert.Len(t, m1.GetPeers(), 2)
}

// ---------------------------------------------------------------------------
// Broadcast methods
// ---------------------------------------------------------------------------

func TestMockP2PNode_BroadcastTransaction_NoError(t *testing.T) {
	m := newTestMockP2P(t)
	tx := Transaction{Sender: "A", Receiver: "B", Amount: 1}
	err := m.BroadcastTransaction(tx)
	assert.NoError(t, err)
}

func TestMockP2PNode_BroadcastBlock_NoError(t *testing.T) {
	m := newTestMockP2P(t)
	block := Block{Transactions: []Transaction{{Sender: "A", Receiver: "B", Amount: 1}}}
	err := m.BroadcastBlock(block)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Messaging helpers
// ---------------------------------------------------------------------------

func TestMockP2PNode_SendMessage_NoError(t *testing.T) {
	m := newTestMockP2P(t)
	err := m.SendMessage("peer-1", "hello")
	assert.NoError(t, err)
}

func TestMockP2PNode_SendPing_NoError(t *testing.T) {
	m := newTestMockP2P(t)
	err := m.SendPing("peer-1")
	assert.NoError(t, err)
}

func TestMockP2PNode_ID_ReturnsNodeID(t *testing.T) {
	m := newTestMockP2P(t)
	assert.Equal(t, m.NodeID, m.ID())
}

// ---------------------------------------------------------------------------
// HandleMessages
// ---------------------------------------------------------------------------

func TestMockP2PNode_HandleMessages_NoOp(t *testing.T) {
	m := newTestMockP2P(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled — just verifying no panic
	m.HandleMessages(ctx)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

func TestMockP2PNode_Shutdown_ClearsPeers(t *testing.T) {
	m1 := newTestMockP2P(t)
	m2 := newTestMockP2P(t)
	m1.AddPeer(m2)
	require.Len(t, m1.GetPeers(), 1)

	err := m1.Shutdown(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, m1.Peers)
	assert.Nil(t, m1.Topic)
}
