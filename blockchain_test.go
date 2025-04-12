package gonetwork

import (
	"encoding/base64"
	"testing"
)

func TestAddBlock(t *testing.T) {
	bc := Blockchain{}
	transactions := []Transaction{
		{Sender: "Alice", Receiver: "Bob", Amount: 10},
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

	tx := Transaction{Sender: base64.StdEncoding.EncodeToString(publicKey.Bytes()), Receiver: "Bob", Amount: 10}
	// Serialize and hash the transaction for signing
	txHash := tx.hash()

	// Sign the transaction hash
	signature := privateKey.Sign(txHash)

	if len(signature.Bytes()) == 0 {
		t.Error("Expected signature to be non-empty after signing")
	}

	// Store the signature in the transaction
	tx.Signature = signature.Bytes()

	// Verify the signature
	if !signature.Verify(publicKey, txHash) {
		t.Error("Signature verification failed")
	}
}

func TestValidateBlock(t *testing.T) {
	// Setup blockchain
	bc := Blockchain{}

	// Generate a key pair for the sender
	privateKey, _ := GeneratePrivateKey()
	publicKey := privateKey.Public()
	senderPublicKey := base64.StdEncoding.EncodeToString(publicKey.Bytes())

	// Add a valid block to the chain
	validTransaction := Transaction{
		Sender:   senderPublicKey,
		Receiver: "receiver1",
		Amount:   10,
	}
	validTransaction.SignTransaction(privateKey)

	validBlock := Block{
		Transactions: []Transaction{validTransaction},
		PrevHash:     "",
	}
	bc.Blocks = append(bc.Blocks, validBlock)

	// Test valid block
	newTransaction := Transaction{
		Sender:   senderPublicKey,
		Receiver: "receiver2",
		Amount:   20,
	}
	newTransaction.SignTransaction(privateKey)

	newBlock := Block{
		Transactions: []Transaction{newTransaction},
		PrevHash:     validBlock.CalculateHash(),
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
		Sender:    "invalid_sender",
		Receiver:  "receiver3",
		Amount:    30,
		Signature: []byte("invalid_signature"),
	}
	invalidTransactionBlock := Block{
		Transactions: []Transaction{invalidTransaction},
		PrevHash:     validBlock.CalculateHash(),
	}
	if bc.ValidateBlock(invalidTransactionBlock) {
		t.Errorf("Expected block to be invalid due to invalid transaction, but it was valid")
	}
}
