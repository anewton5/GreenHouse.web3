package gonetwork

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestAddBlock(t *testing.T) {
	bc := Blockchain{}
	transactions := []Transaction{
		{Sender: "Alice", Receiver: "Bob", Amount: 10, RequiredSigs: 1},
	}
	prevHash := "0000000000000000" // Example previous hash
	prevHashBytes := [][]byte{[]byte(prevHash)}

	bc.AddBlock(transactions, prevHashBytes)

	if len(bc.Blocks) != 1 {
		t.Errorf("Expected 1 block, got %d", len(bc.Blocks))
	}

	if bc.Blocks[0].PrevHash != prevHash {
		t.Errorf("Expected previous hash to be %s, got %s", prevHash, bc.Blocks[0].PrevHash)
	}
}

func TestSignTransaction(t *testing.T) {
	// Generate a new key pair using the custom GeneratePrivateKey function
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	publicKey := privateKey.Public()

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(publicKey.Bytes()),
		Receiver:     "Bob",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()

	// Sign the transaction
	err = tx.SignTransaction(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	if len(tx.Signatures) == 0 {
		t.Error("Expected at least one signature after signing")
	}

	// Verify the signature
	pubKeys := []*PublicKey{publicKey}
	if !tx.VerifyMultiSignature(pubKeys) {
		t.Error("Multi-signature verification failed")
	}
}

func TestInvalidTransactionPublicKey(t *testing.T) {
	blockchain := NewBlockchain()

	// Create a transaction with an invalid sender public key
	tx := Transaction{
		Sender:   "invalid_base64_key",
		Receiver: "receiverPublicKey",
		Amount:   10,
	}

	blockchain.AddTransaction(tx)

	if len(blockchain.TransactionPool) != 0 {
		t.Fatalf("Invalid transaction was added to the pool")
	}

	t.Logf("Invalid transaction was correctly rejected")
}
func TestBlockValidationWithSignatures(t *testing.T) {
	blockchain := NewBlockchain()

	// Generate private and public keys for delegates
	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()

	// Extract the ed25519.PrivateKey and ed25519.PublicKey from the custom PrivateKey type
	edPrivKey1 := privKey1.key // Assuming `key` is the underlying ed25519.PrivateKey
	edPubKey1 := privKey1.Public().key
	edPrivKey2 := privKey2.key
	edPubKey2 := privKey2.Public().key

	// Create delegates with both private and public keys
	delegate1 := Node{ID: "delegate1", PrivateKey: edPrivKey1, PublicKey: edPubKey1}
	delegate2 := Node{ID: "delegate2", PrivateKey: edPrivKey2, PublicKey: edPubKey2}
	blockchain.Delegates = []Node{delegate1, delegate2}

	// Generate a valid key pair for the sender
	senderPrivKey, _ := GeneratePrivateKey()
	senderPubKey := senderPrivKey.Public()
	senderPubKeyBase64 := base64.StdEncoding.EncodeToString(senderPubKey.Bytes())
	// Create a block with a valid transaction
	block := Block{
		Transactions: []Transaction{
			{Sender: senderPubKeyBase64, Receiver: "receiver", Amount: 10},
		},
		PrevHash: blockchain.GetLastBlockHash(),
	}

	// Sign the block using the delegates' private keys
	block.Signatures = [][]byte{
		ed25519.Sign(delegate1.PrivateKey, []byte(block.CalculateHash())),
		ed25519.Sign(delegate2.PrivateKey, []byte(block.CalculateHash())),
	}

	// Validate the block
	if !blockchain.ValidateBlock(block) {
		t.Fatalf("Block validation failed")
	}

	t.Logf("Block validated successfully")
}
func TestSignedTransaction(t *testing.T) {
	wallet, _ := NewWallet()
	receiverPublicKey := "receiverPublicKeyBase64"

	tx, err := wallet.CreateTransaction(receiverPublicKey, 10)
	if err != nil {
		t.Fatalf("Failed to create transaction: %v", err)
	}

	if len(tx.Signatures) == 0 {
		t.Fatalf("Transaction is not signed")
	}

	t.Logf("Transaction signed successfully: %+v", tx)
}

func TestSortTransactionPool(t *testing.T) {
	blockchain := NewBlockchain()

	// Add transactions with different timestamps and amounts
	blockchain.TransactionPool = []Transaction{
		{Sender: "A", Receiver: "B", Amount: 50, Nonce: 2},
		{Sender: "C", Receiver: "D", Amount: 100, Nonce: 1},
		{Sender: "E", Receiver: "F", Amount: 75, Nonce: 1},
	}

	blockchain.SortTransactionPool()

	// Verify the order of transactions
	if blockchain.TransactionPool[0].Amount != 100 || blockchain.TransactionPool[1].Amount != 75 {
		t.Fatalf("Transaction pool not sorted correctly: %+v", blockchain.TransactionPool)
	}

	t.Logf("Transaction pool sorted correctly: %+v", blockchain.TransactionPool)
}
func TestValidateBlock(t *testing.T) {
	// Setup blockchain
	bc := Blockchain{}

	// Generate a key pair for the sender
	privateKey, _ := GeneratePrivateKey()
	publicKey := privateKey.Public()
	senderPublicKey := base64.StdEncoding.EncodeToString(publicKey.Bytes())
	fmt.Printf("Generated sender public key (Base64): %s\n", senderPublicKey)

	// Add delegates to the blockchain
	delegatePrivKey1, _ := GeneratePrivateKey()
	delegatePubKey1 := delegatePrivKey1.Public()
	delegatePrivKey2, _ := GeneratePrivateKey()
	delegatePubKey2 := delegatePrivKey2.Public()

	bc.Delegates = []Node{
		{ID: "delegate1", PrivateKey: delegatePrivKey1.key, PublicKey: delegatePubKey1.key},
		{ID: "delegate2", PrivateKey: delegatePrivKey2.key, PublicKey: delegatePubKey2.key},
	}

	// Add a valid block to the chain
	validTransaction := Transaction{
		Sender:       senderPublicKey,
		Receiver:     "receiver1",
		Amount:       10,
		RequiredSigs: 1,
	}
	validTransaction.GenerateNonce()
	validTransaction.SignTransaction(privateKey)

	validBlock := Block{
		Transactions: []Transaction{validTransaction},
		PrevHash:     "",
	}
	bc.Blocks = append(bc.Blocks, validBlock)

	// Test valid block
	newTransaction := Transaction{
		Sender:       senderPublicKey,
		Receiver:     "receiver2",
		Amount:       20,
		RequiredSigs: 1,
	}
	newTransaction.GenerateNonce()
	newTransaction.SignTransaction(privateKey)

	newBlock := Block{
		Transactions: []Transaction{newTransaction},
		PrevHash:     validBlock.CalculateHash(),
	}

	// Sign the block with delegate private keys
	newBlock.Signatures = [][]byte{
		ed25519.Sign(delegatePrivKey1.key, []byte(newBlock.CalculateHash())),
		ed25519.Sign(delegatePrivKey2.key, []byte(newBlock.CalculateHash())),
	}

	if !bc.ValidateBlock(newBlock) {
		t.Errorf("Expected block to be valid, but it was invalid")
	}

	// Test invalid block (missing transactions)
	invalidBlock := Block{
		Transactions: []Transaction{},
		PrevHash:     validBlock.CalculateHash(),
	}
	if bc.ValidateBlock(invalidBlock) {
		t.Errorf("Expected block to be invalid, but it was valid")
	}

	// Test invalid block (incorrect previous hash)
	invalidBlock.PrevHash = "invalid_hash"
	if bc.ValidateBlock(invalidBlock) {
		t.Errorf("Expected block to be invalid, but it was valid")
	}

	// Test invalid block (invalid transaction)
	invalidTransaction := Transaction{
		Sender:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Base64-encoded "invalid_sender"
		Receiver:     "receiver3",
		Amount:       30,
		RequiredSigs: 1,
	}
	invalidTransaction.GenerateNonce()
	invalidTransaction.Signatures = append(invalidTransaction.Signatures, []byte("invalid_signature"))

	invalidTransactionBlock := Block{
		Transactions: []Transaction{invalidTransaction},
		PrevHash:     validBlock.CalculateHash(),
	}
	if bc.ValidateBlock(invalidTransactionBlock) {
		t.Errorf("Expected block to be invalid due to invalid transaction, but it was valid")
	}
}

func TestMultiSignatureTransaction(t *testing.T) {
	// Generate private keys for multiple signers
	privateKey1, _ := GeneratePrivateKey()
	privateKey2, _ := GeneratePrivateKey()

	// Get corresponding public keys
	publicKey1 := privateKey1.Public()
	publicKey2 := privateKey2.Public()

	// Create a multi-signature transaction
	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(publicKey1.Bytes()),
		Receiver:     "receiver_address",
		Amount:       100,
		RequiredSigs: 2, // Require 2 valid signatures
	}
	tx.GenerateNonce()

	// Sign the transaction with both private keys
	tx.SignTransaction(privateKey1)
	tx.SignTransaction(privateKey2)

	// Verify the transaction
	pubKeys := []*PublicKey{publicKey1, publicKey2}
	if !tx.VerifyMultiSignature(pubKeys) {
		t.Errorf("Expected transaction to be valid, but it was invalid")
	}

	// Test with insufficient signatures
	tx.Signatures = tx.Signatures[:1] // Remove one signature
	if tx.VerifyMultiSignature(pubKeys) {
		t.Errorf("Expected transaction to be invalid due to insufficient signatures, but it was valid")
	}
}
func TestAchieveConsensusBasic(t *testing.T) {
	blockchain := NewBlockchain()

	// Add delegates
	blockchain.Delegates = []Node{
		{ID: "delegate1", VotingStrategy: &DefaultVotingStrategy{}},
		{ID: "delegate2", VotingStrategy: &DefaultVotingStrategy{}},
		{ID: "delegate3", VotingStrategy: &DefaultVotingStrategy{}},
	}

	// Create a block
	block := Block{
		Transactions: []Transaction{
			{Sender: "A", Receiver: "B", Amount: 10},
		},
	}

	// Achieve consensus
	network := NewNetwork("test-network")
	if !blockchain.AchieveConsensus(block, network) {
		t.Fatalf("Failed to achieve consensus")
	}

	t.Logf("Consensus achieved successfully")
}

func TestSharding(t *testing.T) {
	bc := NewBlockchain()
	bc.InitializeShards(3)

	tx1 := Transaction{Sender: "A", Receiver: "B", Amount: 10}
	tx2 := Transaction{Sender: "C", Receiver: "D", Amount: 20}
	tx3 := Transaction{Sender: "E", Receiver: "F", Amount: 30}

	bc.AssignTransactionToShard(tx1)
	bc.AssignTransactionToShard(tx2)
	bc.AssignTransactionToShard(tx3)

	for _, shard := range bc.Shards {
		fmt.Printf("Shard %d transactions: %+v\n", shard.ID, shard.TransactionPool)
	}
}

func TestParallelTransactionValidation(t *testing.T) {
	bc := NewBlockchain()
	// Add transactions to the pool
	for i := 0; i < 100; i++ {
		tx := Transaction{
			Sender:   fmt.Sprintf("Sender%d", i),
			Receiver: fmt.Sprintf("Receiver%d", i),
			Amount:   float64(i + 1),
		}
		tx.GenerateNonce()
		bc.TransactionPool = append(bc.TransactionPool, tx)
	}

	bc.ValidateTransactionsInParallel()
}

func TestNodeRecovery(t *testing.T) {
	// Create two nodes
	node1 := NewNode("node1", NewBlockchain())
	node2 := NewNode("node2", NewBlockchain())

	// Add a block to node1's blockchain
	tx := Transaction{Sender: "A", Receiver: "B", Amount: 10}
	node1.Blockchain.AddBlock([]Transaction{tx}, nil)

	// Sync node2 with node1
	node2.SyncBlockchain(node1)

	// Verify that node2's blockchain matches node1's
	if len(node2.Blockchain.Blocks) != len(node1.Blockchain.Blocks) {
		t.Fatalf("Node2 failed to sync blockchain with Node1")
	}
}

func TestForkResolution(t *testing.T) {
	// Create two blockchains
	bc1 := NewBlockchain()
	bc2 := NewBlockchain()

	// Add blocks to bc1
	tx1 := Transaction{Sender: "A", Receiver: "B", Amount: 10}
	bc1.AddBlock([]Transaction{tx1}, nil)

	// Add more blocks to bc2
	tx2 := Transaction{Sender: "C", Receiver: "D", Amount: 20}
	bc2.AddBlock([]Transaction{tx1}, nil)
	bc2.AddBlock([]Transaction{tx2}, nil)

	// Resolve fork
	if !bc1.ResolveFork(bc2.Blocks) {
		t.Fatalf("Failed to resolve fork")
	}

	// Verify that bc1 now matches bc2
	if len(bc1.Blocks) != len(bc2.Blocks) {
		t.Fatalf("Fork resolution failed: chains do not match")
	}
}
