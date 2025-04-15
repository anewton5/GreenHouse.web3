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
	blockchain := &Blockchain{
		Delegates: []Node{
			{ID: "delegate1", Stake: 100},
			{ID: "delegate2", Stake: 100},
			{ID: "delegate3", Stake: 100},
		},
	}
	network := NewNetwork("default-network")

	block := Block{
		Transactions: []Transaction{
			{Sender: "wallet1", Receiver: "wallet2", Amount: 10},
		},
	}

	achieved := blockchain.AchieveConsensus(block, network)
	if !achieved {
		t.Errorf("Expected consensus to be achieved, but it was not")
	}
}

func TestCreateBlock(t *testing.T) {
	// Initialize the blockchain with a genesis block
	blockchain := NewBlockchain()

	// Initialize shards
	blockchain.InitializeShards(3) // Create 3 shards

	// Create a network
	network := NewNetwork("default-network")

	// Add wallets with private keys
	privKey1, _ := GeneratePrivateKey()
	pubKey1 := privKey1.Public()
	wallet1 := &Wallet{PublicKey: pubKey1, PrivateKey: privKey1, Balance: 100}

	privKey2, _ := GeneratePrivateKey()
	pubKey2 := privKey2.Public()
	wallet2 := &Wallet{PublicKey: pubKey2, PrivateKey: privKey2, Balance: 100}

	blockchain.Wallets["wallet1"] = wallet1
	blockchain.Wallets["wallet2"] = wallet2

	// Add transactions to the blockchain
	senderPubKeyBase64 := base64.StdEncoding.EncodeToString(wallet1.PublicKey.Bytes())
	tx1 := Transaction{Sender: senderPubKeyBase64, Receiver: "wallet2", Amount: 10}
	tx1.GenerateNonce()
	blockchain.AddTransaction(tx1)

	tx2 := Transaction{Sender: senderPubKeyBase64, Receiver: "wallet2", Amount: 20}
	tx2.GenerateNonce()
	blockchain.AddTransaction(tx2)

	// Verify that transactions are assigned to shards
	totalTransactions := 0
	for _, shard := range blockchain.Shards {
		totalTransactions += len(shard.TransactionPool)
	}
	if totalTransactions != 2 {
		t.Fatalf("Expected 2 transactions across shards, but found %d", totalTransactions)
	}

	// Setup delegates with voting strategies
	blockchain.Delegates = []Node{
		{ID: "delegate1", Blockchain: blockchain, VotingStrategy: &DefaultVotingStrategy{}},
		{ID: "delegate2", Blockchain: blockchain, VotingStrategy: &DefaultVotingStrategy{}},
	}

	if len(blockchain.Delegates) == 0 {
		t.Fatalf("No delegates were set up for the blockchain")
	}

	// Log the initial state of the blockchain
	t.Logf("Initial blockchain state: %+v", blockchain)

	// Call createBlock
	blockchain.createBlock(network)

	// Check if consensus was achieved
	if len(blockchain.Blocks) <= 1 { // Genesis block + new block
		t.Fatalf("Expected at least 2 blocks (including genesis), but got %d", len(blockchain.Blocks))
	}

	// Verify transactions in the block
	if len(blockchain.Blocks[1].Transactions) != 2 {
		t.Errorf("Expected 2 transactions in the block, but found %d", len(blockchain.Blocks[1].Transactions))
	}

	// Verify that transactions were cleared from shards
	for _, shard := range blockchain.Shards {
		if len(shard.TransactionPool) != 0 {
			t.Errorf("Expected shard %d transaction pool to be empty, but found %d transactions", shard.ID, len(shard.TransactionPool))
		}
	}

	// Log the final state of the blockchain
	t.Logf("Final blockchain state: %+v", blockchain)
}

func TestNetworkConsensus(t *testing.T) {
	// Create a blockchain
	blockchain := &Blockchain{
		Blocks:             []Block{},
		LockedWallets:      make(map[[32]byte]*LockedWallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
		TransactionPool:    []Transaction{},
	}

	// Create a network
	network := NewNetwork("default-network")

	// Create nodes
	node1 := NewNode("node1", blockchain)
	node2 := NewNode("node2", blockchain)
	node3 := NewNode("node3", blockchain)

	// Register nodes to the network
	network.RegisterNode(node1)
	network.RegisterNode(node2)
	network.RegisterNode(node3)

	// Setup blockchain with delegates
	blockchain.Delegates = []Node{
		*node1,
		*node2,
		*node3,
	}

	// Start consensus
	blockchain.startConsensus(network)
}

func TestVoteOnBlock(t *testing.T) {
	// Create a blockchain
	blockchain := &Blockchain{
		Blocks:          []Block{},
		TransactionPool: []Transaction{},
	}

	// Create a delegate node with a voting strategy
	delegate := Node{
		ID:         "delegate1",
		Blockchain: blockchain,
		VotingStrategy: &FuncVotingStrategy{
			VoteFunc: func(block Block) bool { return len(block.Transactions) > 0 }, // Vote YES if the block has transactions
		},
	}

	// Test valid block
	validBlock := Block{
		Transactions: []Transaction{{Sender: "wallet1", Receiver: "wallet2", Amount: 10}},
	}
	if !delegate.VoteOnBlock(validBlock) {
		t.Errorf("Expected delegate to vote YES on valid block, but voted NO")
	}

	// Test invalid block (missing transactions)
	invalidBlock := Block{
		Transactions: []Transaction{},
	}
	if delegate.VoteOnBlock(invalidBlock) {
		t.Errorf("Expected delegate to vote NO on invalid block, but voted YES")
	}
}

func TestAchieveConsensusWithMixedVotes(t *testing.T) {
	// Create a blockchain
	blockchain := &Blockchain{
		Blocks:          []Block{},
		TransactionPool: []Transaction{},
	}

	// Create a network
	network := NewNetwork("default-network")

	// Setup blockchain with delegates
	blockchain.Delegates = []Node{
		{ID: "delegate1", Blockchain: blockchain, VotingStrategy: &FuncVotingStrategy{VoteFunc: func(block Block) bool { return true }}},  // YES
		{ID: "delegate2", Blockchain: blockchain, VotingStrategy: &FuncVotingStrategy{VoteFunc: func(block Block) bool { return true }}},  // YES
		{ID: "delegate3", Blockchain: blockchain, VotingStrategy: &FuncVotingStrategy{VoteFunc: func(block Block) bool { return false }}}, // NO
	}

	// Create a valid block
	validBlock := Block{
		Transactions: []Transaction{{Sender: "wallet1", Receiver: "wallet2", Amount: 10}},
	}

	// Call AchieveConsensus
	result := blockchain.AchieveConsensus(validBlock, network)

	// Verify consensus result
	if !result {
		t.Errorf("Expected consensus to be achieved, but it was not")
	}

	// Test with insufficient votes
	blockchain.Delegates[1].VotingStrategy = &FuncVotingStrategy{VoteFunc: func(block Block) bool { return false }} // Change to NO
	result = blockchain.AchieveConsensus(validBlock, network)
	if result {
		t.Errorf("Expected consensus to fail, but it was achieved")
	}
}
