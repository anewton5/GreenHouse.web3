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
	Nodes map[string]*Node // Map of node IDs to nodes
}

func NewNetwork() *Network {
	return &Network{
		Nodes: make(map[string]*Node),
	}
}

// RegisterNode adds a node to the network
func (n *Network) RegisterNode(node *Node) {
	n.Nodes[node.ID] = node
}

// SendMessage sends a message to a specific node or broadcasts it
func (n *Network) SendMessage(msg Message) {
	if msg.To == "" {
		// Broadcast to all nodes
		for _, node := range n.Nodes {
			node.ReceiveMessage(msg)
		}
	} else if recipient, exists := n.Nodes[msg.To]; exists {
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
	n.SendMessage(msg)
}
