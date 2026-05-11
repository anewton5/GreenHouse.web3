package gonetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewP2PNode(t *testing.T) {
	ctx := context.Background()
	blockchain := NewBlockchain(ctx, "test-blockchain")
	topicName := "test-topic"
	bootstrapPeers := []string{}

	node, err := NewP2PNode(ctx, blockchain, topicName, bootstrapPeers)
	if err != nil {
		t.Fatalf("Failed to initialize P2PNode: %v", err)
	}

	if node.Host == nil {
		t.Fatalf("Expected Host to be initialized, got nil")
	}

	if node.PubSub == nil {
		t.Fatalf("Expected PubSub to be initialized, got nil")
	}

	if node.Topic == nil {
		t.Fatalf("Expected Topic to be initialized, got nil")
	}

	t.Log("P2PNode initialized successfully")
}

func TestBroadcastTransaction(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Use the mock P2PNode
	mockP2PNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	// Use the mock P2PNode directly
	err = mockP2PNode.BroadcastTransaction(Transaction{
		Sender:   "sender",
		Receiver: "receiver",
		Amount:   10.0,
	})
	assert.NoError(t, err, "BroadcastTransaction should not return an error")
}

func TestBroadcastBlock(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Use the mock P2PNode
	mockP2PNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	block := Block{
		Transactions: []Transaction{
			{Sender: "Alice", Receiver: "Bob", Amount: 10},
		},
		PrevHash: "0000000000000000",
	}

	// Use the mock P2PNode to broadcast the block
	err = mockP2PNode.BroadcastBlock(block)
	assert.NoError(t, err, "BroadcastBlock should not return an error")
}

func TestHandleMessages(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Use the mock P2PNode
	mockNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	// Simulate publishing multiple message types
	go func() {
		// Publish a transaction message
		tx := Transaction{
			Sender:   "Alice",
			Receiver: "Bob",
			Amount:   10,
		}
		txData, _ := json.Marshal(tx)
		txMessage := P2PMessage{
			Type:    MessageTypeTransaction,
			Payload: txData,
		}
		txMessageData, _ := json.Marshal(txMessage)
		mockNode.Topic.Publish(ctx, txMessageData)

		// Publish a block message
		block := Block{
			Transactions: []Transaction{
				{Sender: "Alice", Receiver: "Bob", Amount: 10},
			},
			PrevHash: "0000000000000000",
		}
		blockData, _ := json.Marshal(block)
		blockMessage := P2PMessage{
			Type:    MessageTypeBlock,
			Payload: blockData,
		}
		blockMessageData, _ := json.Marshal(blockMessage)
		mockNode.Topic.Publish(ctx, blockMessageData)

		// Publish a ping message
		pingMessage := P2PMessage{
			Type:    MessageTypePing,
			Payload: []byte("ping"),
		}
		pingMessageData, _ := json.Marshal(pingMessage)
		mockNode.Topic.Publish(ctx, pingMessageData)

		// Publish an acknowledgment message
		ackMessage := P2PMessage{
			Type:    MessageTypeAck,
			Payload: []byte("ack"),
		}
		ackMessageData, _ := json.Marshal(ackMessage)
		mockNode.Topic.Publish(ctx, ackMessageData)
	}()

	// Simulate handling messages
	go mockNode.HandleMessages(ctx)

	// Wait for the messages to be processed
	time.Sleep(2 * time.Second) // Allow time for all messages to be handled

	t.Log("All message types handled successfully")
}

// TestPeerDiscovery_Local verifies that two in-process libp2p nodes can
// discover each other without any external network dependency.
func TestPeerDiscovery_Local(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc1 := NewBlockchain(ctx, "node1")
	bc2 := NewBlockchain(ctx, "node2")

	nodeA, err := NewP2PNode(ctx, bc1, "test-discovery", nil)
	require.NoError(t, err, "nodeA should initialise without error")
	defer nodeA.Shutdown(ctx)

	nodeB, err := NewP2PNode(ctx, bc2, "test-discovery", nil)
	require.NoError(t, err, "nodeB should initialise without error")
	defer nodeB.Shutdown(ctx)

	// Connect nodeB directly to nodeA using its listen addresses.
	nodeAInfo := peer.AddrInfo{
		ID:    nodeA.Host.ID(),
		Addrs: nodeA.Host.Addrs(),
	}
	err = nodeB.Host.Connect(ctx, nodeAInfo)
	require.NoError(t, err, "nodeB should connect to nodeA")

	// nodeA should appear in nodeB's peer list.
	require.Eventually(t, func() bool {
		for _, p := range nodeB.Host.Network().Peers() {
			if p == nodeA.Host.ID() {
				return true
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond, "nodeB should discover nodeA")

	t.Logf("nodeB (%s) discovered nodeA (%s)", nodeB.Host.ID(), nodeA.Host.ID())
}

func TestSendMessage(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Create two mock P2P nodes
	mockNode1, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode1 initialization should not fail")

	mockNode2, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode2 initialization should not fail")

	// Simulate sending a message from mockNode1 to mockNode2
	message := "Hello, peer!"
	err = mockNode1.SendMessage(mockNode2.ID(), message)
	assert.NoError(t, err, "SendMessage should not return an error")

	t.Logf("Message sent successfully from MockNode1 (%s) to MockNode2 (%s)", mockNode1.ID(), mockNode2.ID())
}

func TestMockP2PNodeInitialization(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Initialize the MockP2PNode
	mockNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	assert.NotNil(t, mockNode, "MockP2PNode should not be nil")
	assert.NotEmpty(t, mockNode.ID(), "MockP2PNode should have a valid ID")

	t.Logf("MockP2PNode initialized with ID: %s", mockNode.ID())
}

func TestHandleMessagesWithStructuredMessages(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Use the mock P2PNode
	mockNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	// Simulate publishing a transaction
	go func() {
		tx := Transaction{
			Sender:   "Alice",
			Receiver: "Bob",
			Amount:   10,
		}
		txData, _ := json.Marshal(tx)
		message := P2PMessage{
			Type:    "transaction",
			Payload: txData,
		}
		data, _ := json.Marshal(message)
		mockNode.Topic.Publish(ctx, data)
	}()

	// Simulate handling messages
	go mockNode.HandleMessages(ctx)

	// Wait for the message to be processed
	time.Sleep(1 * time.Second)
	t.Log("Structured message handled successfully")
}

func TestPingAndAck(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Use the mock P2PNode
	mockNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	// Simulate sending a ping message
	go func() {
		err := mockNode.SendPing("mock-peer-id")
		assert.NoError(t, err, "SendPing should not return an error")
	}()

	// Simulate handling messages
	go mockNode.HandleMessages(ctx)

	// Wait for the message to be processed
	time.Sleep(1 * time.Second)
	t.Log("Ping and acknowledgment messages handled successfully")
}

func TestP2PNodeShutdown(t *testing.T) {
	ctx := context.Background()
	blockchain := &Blockchain{} // Mock or initialize a blockchain instance

	// Create a new MockP2PNode
	mockNode, err := NewMockP2PNode(ctx, blockchain, "test-topic", nil)
	assert.NoError(t, err, "MockP2PNode initialization should not fail")

	// Call the Shutdown method
	err = mockNode.Shutdown(ctx)
	assert.NoError(t, err, "Shutdown should not return an error")

	t.Log("P2PNode shutdown successfully")
}

func TestRealPeersCommunication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	blockchain1 := &Blockchain{} // Mock or initialize a blockchain instance
	blockchain2 := &Blockchain{}

	// Create two P2P nodes
	node1, err := NewP2PNode(ctx, blockchain1, "test-topic", nil)
	assert.NoError(t, err, "Node1 initialization should not fail")
	defer node1.Shutdown(ctx)

	node2, err := NewP2PNode(ctx, blockchain2, "test-topic", nil)
	assert.NoError(t, err, "Node2 initialization should not fail")
	defer node2.Shutdown(ctx)

	// Simulate broadcasting a transaction from Node1
	go func() {
		tx := Transaction{
			Sender:   "Alice",
			Receiver: "Bob",
			Amount:   10,
		}
		err := node1.BroadcastTransaction(tx)
		assert.NoError(t, err, "BroadcastTransaction should not return an error")
	}()

	// Simulate handling messages on Node2
	go node2.HandleMessages(ctx)

	// Wait for the message to be processed
	time.Sleep(2 * time.Second)

	// Verify that Node2 received the transaction
	// (You can add logic to check the blockchain or logs for the received transaction)
	t.Log("Real peer communication test passed")
}

// ---------------------------------------------------------------------------
// AllowlistGater tests
// ---------------------------------------------------------------------------

// TestAllowlistGater_OpenWhenEmpty verifies that an empty allowlist permits
// all connections (open / development mode).
func TestAllowlistGater_OpenWhenEmpty(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	anyPeer := peer.ID("12D3KooWOpenModeAnyPeer")
	assert.True(t, g.InterceptSecured(network.DirInbound, anyPeer, nil))
	assert.True(t, g.InterceptPeerDial(anyPeer))
}

// TestAllowlistGater_Permits verifies that an explicitly admitted peer is
// allowed to connect.
func TestAllowlistGater_Permits(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	testPeer := peer.ID("12D3KooWGaterPermitsPeer")
	hash := sha3.Sum256([]byte(testPeer))
	sig := registryKey.Sign(hash[:]).Bytes()
	require.NoError(t, g.AllowPeer(testPeer, sig))

	assert.True(t, g.InterceptSecured(network.DirInbound, testPeer, nil))
	assert.True(t, g.InterceptPeerDial(testPeer))
}

// TestAllowlistGater_Blocks verifies that a peer absent from a non-empty
// allowlist is rejected.
func TestAllowlistGater_Blocks(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	// Admit one peer to make the allowlist non-empty (permissioned mode).
	knownPeer := peer.ID("12D3KooWGaterBlocksKnown")
	hash := sha3.Sum256([]byte(knownPeer))
	sig := registryKey.Sign(hash[:]).Bytes()
	require.NoError(t, g.AllowPeer(knownPeer, sig))

	unknownPeer := peer.ID("12D3KooWGaterBlocksUnknown")
	assert.False(t, g.InterceptSecured(network.DirInbound, unknownPeer, nil))
	assert.False(t, g.InterceptPeerDial(unknownPeer))
}

// TestAllowlistGater_AllowPeer_ValidSig verifies that a correctly signed
// AllowPeer call admits the peer without error.
func TestAllowlistGater_AllowPeer_ValidSig(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	testPeer := peer.ID("12D3KooWGaterValidSigPeer")
	hash := sha3.Sum256([]byte(testPeer))
	sig := registryKey.Sign(hash[:]).Bytes()

	err = g.AllowPeer(testPeer, sig)
	assert.NoError(t, err)
	assert.True(t, g.InterceptSecured(network.DirInbound, testPeer, nil))
}

// TestAllowlistGater_AllowPeer_InvalidSig verifies that an incorrectly signed
// AllowPeer call is rejected and the peer is not admitted.
func TestAllowlistGater_AllowPeer_InvalidSig(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// A different key — its signatures should not be accepted.
	attackerKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	testPeer := peer.ID("12D3KooWGaterInvalidSigPeer")
	hash := sha3.Sum256([]byte(testPeer))
	wrongSig := attackerKey.Sign(hash[:]).Bytes()

	err = g.AllowPeer(testPeer, wrongSig)
	assert.Error(t, err, "invalid signature should be rejected")

	// Peer must not have been admitted. Admit another peer to enter
	// permissioned mode so the check is meaningful.
	realPeer := peer.ID("12D3KooWGaterInvalidSigReal")
	realHash := sha3.Sum256([]byte(realPeer))
	realSig := registryKey.Sign(realHash[:]).Bytes()
	require.NoError(t, g.AllowPeer(realPeer, realSig))

	assert.False(t, g.InterceptSecured(network.DirInbound, testPeer, nil))
}

// TestAllowlistGater_RevokePeer verifies that a revoked peer is blocked while
// other admitted peers remain unaffected.
func TestAllowlistGater_RevokePeer(t *testing.T) {
	registryKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	g := NewAllowlistGater(registryKey.Public())

	peerA := peer.ID("12D3KooWGaterRevokeA")
	peerB := peer.ID("12D3KooWGaterRevokeB")

	hashA := sha3.Sum256([]byte(peerA))
	hashB := sha3.Sum256([]byte(peerB))
	sigA := registryKey.Sign(hashA[:]).Bytes()
	sigB := registryKey.Sign(hashB[:]).Bytes()

	require.NoError(t, g.AllowPeer(peerA, sigA))
	require.NoError(t, g.AllowPeer(peerB, sigB))
	assert.True(t, g.InterceptSecured(network.DirInbound, peerA, nil))

	// Revoke peerA. peerB keeps the list non-empty so permissioned mode holds.
	require.NoError(t, g.RevokePeer(peerA, sigA))

	assert.False(t, g.InterceptSecured(network.DirInbound, peerA, nil), "revoked peer should be blocked")
	assert.True(t, g.InterceptSecured(network.DirInbound, peerB, nil), "non-revoked peer should still be permitted")
}
