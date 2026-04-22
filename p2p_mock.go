package gonetwork

import (
	"context"
	"fmt"
	"time"
)

// MockTopic is a mock implementation of the pubsub.Topic
type MockTopic struct{}

func (m *MockTopic) Publish(ctx context.Context, data []byte, opts ...interface{}) error {
	fmt.Println("MockTopic: Publish called")
	return nil
}

// MockP2PNode is a mock implementation of the P2PNode
type MockP2PNode struct {
	Topic  *MockTopic
	Peers  []string // Simulate a list of peers
	NodeID string   // Unique identifier for the mock node
}

func (m *MockP2PNode) BroadcastTransaction(tx Transaction) error {
	fmt.Println("MockP2PNode: BroadcastTransaction called")
	data := []byte("mock transaction data") // Mock serialized transaction
	return m.Topic.Publish(context.Background(), data)
}

func (m *MockP2PNode) BroadcastBlock(block Block) error {
	fmt.Println("MockP2PNode: BroadcastBlock called")
	data := []byte("mock block data") // Mock serialized block
	return m.Topic.Publish(context.Background(), data)
}

func (m *MockP2PNode) AddPeer(peer *MockP2PNode) {
	m.Peers = append(m.Peers, peer.NodeID)
}

func (m *MockP2PNode) GetPeers() []string {
	return m.Peers
}

func (m *MockP2PNode) ID() string {
	return m.NodeID
}

func NewMockP2PNode(ctx context.Context, blockchain *Blockchain, topicName string, bootstrapPeers []string) (*MockP2PNode, error) {
	fmt.Println("MockP2PNode: Initialized")

	// Create a mock topic
	mockTopic := &MockTopic{}

	// Generate a unique ID for the mock node
	nodeID := fmt.Sprintf("mock-node-%d", time.Now().UnixNano())

	return &MockP2PNode{
		Topic:  mockTopic,
		Peers:  []string{},
		NodeID: nodeID,
	}, nil
}

func (m *MockP2PNode) SendMessage(peerID string, message string) error {
	fmt.Printf("MockP2PNode: SendMessage called to peer %s with message: %s\n", peerID, message)
	return nil
}

func (m *MockP2PNode) HandleMessages(ctx context.Context) {
	fmt.Println("MockP2PNode: HandleMessages called")
	// Simulate message handling
}

func (m *MockP2PNode) SendPing(peerID string) error {
	fmt.Printf("MockP2PNode: SendPing called to peer %s\n", peerID)
	return nil
}

func (m *MockP2PNode) Shutdown(ctx context.Context) error {
	fmt.Println("MockP2PNode: Shutdown called")
	// Simulate cleanup logic, such as closing connections or releasing resources
	m.Peers = nil
	m.Topic = nil
	return nil
}
