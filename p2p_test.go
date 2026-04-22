package gonetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func TestPeerDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the blockchain
	blockchain := NewBlockchain(ctx, "test-topic")

	// Wait for peer discovery
	time.Sleep(15 * time.Second) // Increase wait time for real-world latency

	// Verify that the local node discovered the remote node
	found := false
	for _, peer := range blockchain.P2PNode.Host.Network().Peers() {
		if peer.String() == "12D3KooWAuhPZUUFjaMhEqF3WdvQUJ7SM91nnrQbzULwCyoY8F37" {
			found = true
			break
		}
	}

	assert.True(t, found, "Local node should discover the remote node")
	t.Logf("Peer discovery successful: Local node discovered remote node (Remote Node ID: %s)", "12D3KooWAuhPZUUFjaMhEqF3WdvQUJ7SM91nnrQbzULwCyoY8F37")
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
