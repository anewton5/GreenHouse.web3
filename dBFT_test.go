package gonetwork

import (
	"encoding/base64"
	"testing"
)

func TestVoteForDelegates(t *testing.T) {
	// Generate keys for wallets
	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()

	pubKey1 := privKey1.Public()
	pubKey2 := privKey2.Public()

	// Setup blockchain with nodes and locked wallets
	bc := Blockchain{
		Nodes: []Node{
			{ID: "node1", Stake: 100},
			{ID: "node2", Stake: 200},
			{ID: "node3", Stake: 50},
		},
		LockedWallets: GetLockedWallets(),
		PublicKeyToID: map[string]string{
			base64.StdEncoding.EncodeToString(pubKey1.Bytes()): "node1",
			base64.StdEncoding.EncodeToString(pubKey2.Bytes()): "node2",
		},
		UserIDToDelegateID: map[string]string{
			"node1": "node1",
			"node2": "node2",
		},
	}

	// Lock currency for wallets
	wallet1 := &Wallet{PublicKey: pubKey1, PrivateKey: privKey1, Balance: 100}
	wallet2 := &Wallet{PublicKey: pubKey2, PrivateKey: privKey2, Balance: 200}

	err := wallet1.LockCurrency(50)
	if err != nil {
		t.Fatalf("Failed to lock currency for wallet1: %v", err)
	}

	err = wallet2.LockCurrency(100)
	if err != nil {
		t.Fatalf("Failed to lock currency for wallet2: %v", err)
	}

	// Create a Network instance
	network := &Network{}

	// Call VoteForDelegates
	bc.VoteForDelegates(network)

	// Verify delegates
	if len(bc.Delegates) != 2 {
		t.Errorf("Expected 2 delegates, got %d", len(bc.Delegates))
	}

	if bc.Delegates[0].ID != "node1" || bc.Delegates[1].ID != "node2" {
		t.Errorf("Unexpected delegates: %+v", bc.Delegates)
	}
}

func TestAchieveConsensus(t *testing.T) {

	network := &Network{}
	// Setup blockchain with delegates
	bc := Blockchain{
		Delegates: []Node{
			{ID: "delegate1"},
			{ID: "delegate2"},
			{ID: "delegate3"},
		},
	}

	// Create a dummy block
	block := Block{}

	// Call AchieveConsensus
	result := bc.AchieveConsensus(block, network)

	// Verify consensus result
	if !result {
		t.Errorf("Expected consensus to be achieved, but it was not")
	}
}

func TestCreateBlock(t *testing.T) {
	// Generate keys for wallets
	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()

	pubKey1 := privKey1.Public()
	pubKey2 := privKey2.Public()

	network := &Network{}

	// Setup blockchain with wallets and delegates
	bc := Blockchain{
		Wallets: map[string]*Wallet{
			"wallet1": {PublicKey: pubKey1, PrivateKey: privKey1, Balance: 100},
			"wallet2": {PublicKey: pubKey2, PrivateKey: privKey2, Balance: 0},
		},
		Delegates: []Node{
			{ID: "delegate1"},
			{ID: "delegate2"},
		},
	}

	// Call createBlock
	bc.createBlock(network)

	// Verify block creation
	if len(bc.Blocks) != 1 {
		t.Errorf("Expected 1 block, got %d", len(bc.Blocks))
	}

	if len(bc.Blocks[0].Transactions) == 0 {
		t.Errorf("Expected transactions in the block, but found none")
	}
}

func TestNetworkConsensus(t *testing.T) {
	network := NewNetwork()

	// Create nodes
	node1 := NewNode("node1")
	node2 := NewNode("node2")
	node3 := NewNode("node3")

	// Register nodes to the network
	network.RegisterNode(node1)
	network.RegisterNode(node2)
	network.RegisterNode(node3)

	// Setup blockchain with delegates
	bc := Blockchain{
		Delegates: []Node{
			*node1,
			*node2,
			*node3,
		},
	}

	// Start consensus
	bc.startConsensus(network)
}
