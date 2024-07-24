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
func (t *Transaction) VerifyTransaction() bool {
	// Decode the sender's public key from base64
	pubKey, err := PublicKeyFromString(t.Sender)
	if err != nil {
		fmt.Println("Error decoding sender's public key:", err)
		return false
	}

	// Recompute the transaction hash
	txHash := t.hash()

	// Create a Signature object from the signature bytes
	signature := &Signature{value: t.Signature}

	// Verify the signature
	return signature.Verify(pubKey, txHash)
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

// SignTransaction signs the transaction with the given private key
func (t *Transaction) SignTransaction(privateKey *PrivateKey) error {
	txHash := t.hash()
	signature := privateKey.Sign(txHash)
	t.Signature = signature.Bytes()
	return nil
}

// hash returns the SHA-256 hash of the transaction data (excluding the signature)
func (t *Transaction) hash() []byte {
	txCopy := *t
	txCopy.Signature = nil
	txBytes, _ := json.Marshal(txCopy)
	hash := sha256.Sum256(txBytes)
	return hash[:]
}
