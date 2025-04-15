package gonetwork

import (
	"fmt"
)

type MessageType string

const (
	BlockProposal MessageType = "BlockProposal"
	Vote          MessageType = "Vote"
	Consensus     MessageType = "Consensus"
)

type Message struct {
	From    string
	To      string
	Type    MessageType
	Payload interface{}
}

type Network struct {
	ID    string           // Unique identifier for the network
	Nodes map[string]*Node // Map of node IDs to nodes
}

func NewNetwork(id string) *Network {
	return &Network{
		ID:    id,
		Nodes: make(map[string]*Node),
	}
}

// RegisterNode adds a node to the network
func (n *Network) RegisterNode(node *Node) {
	n.Nodes[node.ID] = node
}

// SendMessage sends a message to a specific node or broadcasts it
func (n *Network) SendMessage(network *Network, msg Message) {
	if msg.To == "" {
		// Gossip-based broadcasting
		for _, node := range network.Nodes {
			if node.ID != n.ID { // Avoid sending to self
				go func(targetNode *Node) {
					targetNode.ReceiveMessage(msg)
				}(node)
			}
		}
	} else if recipient, exists := network.Nodes[msg.To]; exists {
		recipient.ReceiveMessage(msg)
	}
}
func (n *Network) BroadcastTransaction(tx Transaction) {
	msg := Message{
		From:    "",
		To:      "",
		Type:    "Transaction",
		Payload: tx,
	}
	fmt.Printf("Broadcasting transaction: %+v\n", tx)
	n.SendMessage(n, msg)
}
