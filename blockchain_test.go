package gonetwork

import (
	"encoding/base64"
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

func TestValidateBlock(t *testing.T) {
	// Setup blockchain
	bc := Blockchain{}

	// Generate a key pair for the sender
	privateKey, _ := GeneratePrivateKey()
	publicKey := privateKey.Public()
	senderPublicKey := base64.StdEncoding.EncodeToString(publicKey.Bytes())

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
		Sender:       "invalid_sender",
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
