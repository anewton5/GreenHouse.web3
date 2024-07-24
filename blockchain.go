package gonetwork

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

type Transaction struct {
	Sender    string // Use public key as string
	Receiver  string // Use public key as string
	Amount    float64
	Signature []byte // Signature to ensure authenticity
}

// Verifies the transaction by checking the signature against the sender's public key
func (t *Transaction) VerifyTransaction(senderPublicKey *PublicKey) bool {
	txHash := t.hash()
	fmt.Printf("Debug: Transaction Hash: %x\n", txHash)
	signature := &Signature{value: t.Signature}
	fmt.Printf("Debug: Signature: %x\n", signature.Bytes())
	return signature.Verify(senderPublicKey, txHash)
}

// Defines the structure of a block Lock in the BLockchain
type Block struct {
	Transactions []Transaction
	PrevHash     string
	Nonce        int
	Signatures   [][]byte
}

type Blockchain struct {
	Blocks []Block
	Nodes  []Node
}

func (bc *Blockchain) AddBlock(transactions []Transaction, prevHash string) {
	block := Block{Transactions: transactions, PrevHash: prevHash, Nonce: 0}
	// Here, you'd implement your consensus mechanism
	bc.Blocks = append(bc.Blocks, block)
}

// Serializes the transaction and hashes it. Encodes the signature as a byte slice
func (t *Transaction) SignTransaction(privateKey *PrivateKey) error {
	txHash := t.hash()
	signature := privateKey.Sign(txHash)
	t.Signature = signature.Bytes()
	return nil
}

func (t *Transaction) hash() []byte {
	txBytes, _ := json.Marshal(t)
	hash := sha256.Sum256(txBytes)
	return hash[:]
}
