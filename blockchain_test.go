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

	bc.AddBlock(transactions, prevHash)

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
