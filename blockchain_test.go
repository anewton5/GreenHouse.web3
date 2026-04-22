package gonetwork

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
)

type Network struct {
	Name string
}

func TestAddBlock(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain") // Blockchain starts with a genesis block

	transactions := []Transaction{
		{Sender: "Alice", Receiver: "Bob", Amount: 10, RequiredSigs: 1},
	}
	prevHash := bc.Blocks[len(bc.Blocks)-1].CalculateHash() // Use the hash of the last block (genesis block)

	bc.AddBlock(transactions, [][]byte{[]byte(prevHash)})

	// Expect 2 blocks: genesis block + the new block
	if len(bc.Blocks) != 2 {
		t.Fatalf("Expected 2 blocks, got %d", len(bc.Blocks))
	}

	if bc.Blocks[1].PrevHash != prevHash {
		t.Fatalf("Expected previous hash to be %s, got %s", prevHash, bc.Blocks[1].PrevHash)
	}

	t.Log("Block added successfully")
}

func TestSignTransaction(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := privateKey.Public()

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(publicKey.Bytes()),
		Receiver:     "Bob",
		Amount:       10,
		RequiredSigs: 1,
	}
	tx.GenerateNonce()

	err = tx.SignTransaction(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	if len(tx.Signatures) == 0 {
		t.Fatalf("Expected at least one signature, got none")
	}

	pubKeys := []*PublicKey{publicKey}
	if !tx.VerifyMultiSignature(pubKeys) {
		t.Fatalf("Multi-signature verification failed")
	}
}

func TestInvalidTransactionPublicKey(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain")

	tx := Transaction{
		Sender:   "invalid_base64_key",
		Receiver: "receiverPublicKey",
		Amount:   10,
	}

	bc.AddTransaction(tx)

	if len(bc.TransactionPool) != 0 {
		t.Fatalf("Invalid transaction was added to the pool")
	}

	t.Log("Invalid transaction was correctly rejected")
}

func TestBlockValidationWithSignatures(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain")

	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()

	delegate1 := Node{ID: "delegate1", PrivateKey: privKey1.key, PublicKey: privKey1.Public().key}
	delegate2 := Node{ID: "delegate2", PrivateKey: privKey2.key, PublicKey: privKey2.Public().key}
	bc.Delegates = []Node{delegate1, delegate2}

	senderPrivKey, _ := GeneratePrivateKey()
	senderPubKey := senderPrivKey.Public()
	senderPubKeyBase64 := base64.StdEncoding.EncodeToString(senderPubKey.Bytes())

	block := Block{
		Transactions: []Transaction{
			{Sender: senderPubKeyBase64, Receiver: "receiver", Amount: 10},
		},
		PrevHash: bc.GetLastBlockHash(),
	}

	block.Signatures = [][]byte{
		ed25519.Sign(delegate1.PrivateKey, []byte(block.CalculateHash())),
		ed25519.Sign(delegate2.PrivateKey, []byte(block.CalculateHash())),
	}

	if !bc.ValidateBlock(block) {
		t.Fatalf("Block validation failed")
	}

	t.Log("Block validated successfully")
}

func TestSortTransactionPool(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain")

	bc.TransactionPool = []Transaction{
		{Sender: "A", Receiver: "B", Amount: 50, Nonce: 2},
		{Sender: "C", Receiver: "D", Amount: 100, Nonce: 1},
		{Sender: "E", Receiver: "F", Amount: 75, Nonce: 1},
	}

	bc.SortTransactionPool()

	if bc.TransactionPool[0].Amount != 100 || bc.TransactionPool[1].Amount != 75 {
		t.Fatalf("Transaction pool not sorted correctly: %+v", bc.TransactionPool)
	}

	t.Log("Transaction pool sorted correctly")
}

func TestValidateBlock(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain")

	privateKey, _ := GeneratePrivateKey()
	publicKey := privateKey.Public()
	senderPublicKey := base64.StdEncoding.EncodeToString(publicKey.Bytes())

	delegatePrivKey1, _ := GeneratePrivateKey()
	delegatePrivKey2, _ := GeneratePrivateKey()

	bc.Delegates = []Node{
		{ID: "delegate1", PrivateKey: delegatePrivKey1.key, PublicKey: delegatePrivKey1.Public().key},
		{ID: "delegate2", PrivateKey: delegatePrivKey2.key, PublicKey: delegatePrivKey2.Public().key},
	}

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

	newBlock.Signatures = [][]byte{
		ed25519.Sign(delegatePrivKey1.key, []byte(newBlock.CalculateHash())),
		ed25519.Sign(delegatePrivKey2.key, []byte(newBlock.CalculateHash())),
	}

	if !bc.ValidateBlock(newBlock) {
		t.Fatalf("Expected block to be valid, but it was invalid")
	}

	invalidBlock := Block{
		Transactions: []Transaction{},
		PrevHash:     validBlock.CalculateHash(),
	}
	if bc.ValidateBlock(invalidBlock) {
		t.Fatalf("Expected block to be invalid, but it was valid")
	}
}

func TestMultiSignatureTransaction(t *testing.T) {
	privateKey1, _ := GeneratePrivateKey()
	privateKey2, _ := GeneratePrivateKey()

	publicKey1 := privateKey1.Public()
	publicKey2 := privateKey2.Public()

	tx := Transaction{
		Sender:       base64.StdEncoding.EncodeToString(publicKey1.Bytes()),
		Receiver:     "receiver_address",
		Amount:       100,
		RequiredSigs: 2,
	}
	tx.GenerateNonce()

	tx.SignTransaction(privateKey1)
	tx.SignTransaction(privateKey2)

	pubKeys := []*PublicKey{publicKey1, publicKey2}
	if !tx.VerifyMultiSignature(pubKeys) {
		t.Fatalf("Expected transaction to be valid, but it was invalid")
	}

	tx.Signatures = tx.Signatures[:1]
	if tx.VerifyMultiSignature(pubKeys) {
		t.Fatalf("Expected transaction to be invalid due to insufficient signatures, but it was valid")
	}
}

func TestAchieveConsensusBasic(t *testing.T) {
	ctx := context.Background()
	bc := NewBlockchain(ctx, "test-blockchain")

	// Add delegates
	bc.Delegates = []Node{
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

	// Call AchieveConsensus with the block
	if !bc.AchieveConsensus(block) {
		t.Fatalf("Failed to achieve consensus")
	}

	t.Log("Consensus achieved successfully")
}

func TestSharding(t *testing.T) {
	bc := NewBlockchain(context.Background(), "test-blockchain")
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
	bc := NewBlockchain(context.Background(), "test-blockchain")
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
	node1 := NewNode("node1", NewBlockchain(context.Background(), "node1-blockchain"))
	node2 := NewNode("node2", NewBlockchain(context.Background(), "node2-blockchain"))

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
	bc1 := NewBlockchain(context.Background(), "bc1-blockchain")
	bc2 := NewBlockchain(context.Background(), "bc2-blockchain")

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
