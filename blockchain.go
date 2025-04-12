package gonetwork

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Transaction struct {
	Sender    string
	Receiver  string
	Amount    float64
	Signature []byte
}

// Verifies the transaction by checking the signature against the sender's public key
func (t *Transaction) VerifyTransaction() (bool, error) {
	// Validate transaction fields
	if t.Amount <= 0 {
		return false, fmt.Errorf("invalid transaction: amount must be greater than zero")
	}

	if t.Sender == "" || t.Receiver == "" {
		return false, fmt.Errorf("invalid transaction: sender and receiver must not be empty")
	}

	// Decode the sender's public key
	pubKey, err := PublicKeyFromString(t.Sender)
	if err != nil {
		return false, fmt.Errorf("error decoding sender's public key: %w", err)
	}

	// Calculate the transaction hash
	txHash := t.hash()

	// Verify the transaction signature
	signature := &Signature{value: t.Signature}
	if !signature.Verify(pubKey, txHash) {
		return false, fmt.Errorf("transaction signature verification failed")
	}

	return true, nil
}

type Block struct {
	Transactions []Transaction
	PrevHash     string
	Nonce        int
	Signatures   [][]byte
}

func (b *Block) CalculateHash() string {
	blockData, _ := json.Marshal(b)
	hash := sha256.Sum256(blockData)
	return hex.EncodeToString(hash[:])
}

type View struct {
	Number int
}

type Blockchain struct {
	Blocks             []Block
	Nodes              []Node
	LockedWallets      map[[32]byte]*LockedWallet
	Delegates          []Node
	PublicKeyToID      map[string]string
	UserIDToDelegateID map[string]string
	currentView        View
	currentSpeaker     int
	Wallets            map[string]*Wallet
	Nonce              int
}

func (bc *Blockchain) AddBlock(transactions []Transaction, signatures [][]byte) {
	var prevHash string
	if len(signatures) > 0 {
		prevHash = string(signatures[0])
	} else if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	}

	newBlock := Block{
		Transactions: transactions,
		PrevHash:     prevHash,
		Nonce:        bc.Nonce,
		Signatures:   signatures,
	}

	bc.Blocks = append(bc.Blocks, newBlock)
	bc.Nonce++
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

func (bc *Blockchain) ValidateBlock(block Block) bool {
	// Check if the block's previous hash matches the hash of the last block in the chain
	if len(bc.Blocks) > 0 {
		lastBlock := bc.Blocks[len(bc.Blocks)-1]
		if block.PrevHash != lastBlock.CalculateHash() {
			fmt.Println("Invalid block: previous hash does not match")
			return false
		}
	}

	// Check if the block contains at least one transaction
	if len(block.Transactions) == 0 {
		fmt.Println("Invalid block: no transactions")
		return false
	}

	// Verify all transactions in the block
	for _, tx := range block.Transactions {
		valid, err := tx.VerifyTransaction()
		if !valid {
			fmt.Printf("Invalid block: contains invalid transaction (%v)\n", err)
			return false
		}
	}

	// Additional validation rules can be added here
	return true
}

// This main function is not implemented correctly, for testing only.
func main() {
	bc := &Blockchain{
		Blocks:             []Block{},
		LockedWallets:      make(map[[32]byte]*LockedWallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
	}

	// Add a genesis block
	genesisTransactions := []Transaction{
		{Sender: "genesis", Receiver: "user1", Amount: 100},
	}
	bc.AddBlock(genesisTransactions, nil)

	newTransactions := []Transaction{
		{Sender: "user1", Receiver: "user2", Amount: 50},
	}
	bc.AddBlock(newTransactions, nil)

	for _, block := range bc.Blocks {
		fmt.Printf("PrevHash: %s\n", block.PrevHash)
		fmt.Printf("Transactions: %+v\n", block.Transactions)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Signatures: %x\n", block.Signatures)
		fmt.Println()
	}
}
