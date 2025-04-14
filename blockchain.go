package gonetwork

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

type Transaction struct {
	Sender       string
	Receiver     string
	Amount       float64
	Signatures   [][]byte
	RequiredSigs int
	Nonce        int64
}

func (t *Transaction) GenerateNonce() {
	t.Nonce = time.Now().UnixNano()
}

func (t *Transaction) AddSignature(signature []byte) {
	t.Signatures = append(t.Signatures, signature)
}

func (t *Transaction) VerifyMultiSignature(pubKeys []*PublicKey) bool {
	// Ensure the number of signatures meets the required threshold
	if len(t.Signatures) < t.RequiredSigs {
		return false
	}

	validSigs := 0
	txHash := t.hash()

	// Verify each signature against the corresponding public key
	for i, sig := range t.Signatures {
		if i >= len(pubKeys) {
			break
		}
		if ed25519.Verify(pubKeys[i].key, txHash, sig) {
			validSigs++
		}
	}

	// Check if the number of valid signatures meets the required threshold
	return validSigs >= t.RequiredSigs
}

// Verifies the transaction by checking the signature against the sender's public key
func (t *Transaction) VerifyTransaction(pubKeys []*PublicKey) (bool, error) {
	// Validate transaction fields
	if t.Amount <= 0 {
		return false, fmt.Errorf("invalid transaction: amount must be greater than zero")
	}

	if t.Sender == "" || t.Receiver == "" {
		return false, fmt.Errorf("invalid transaction: sender and receiver must not be empty")
	}

	// Ensure the number of signatures meets the required threshold
	if len(t.Signatures) < t.RequiredSigs {
		return false, fmt.Errorf("insufficient signatures: required %d, got %d", t.RequiredSigs, len(t.Signatures))
	}

	// Calculate the transaction hash
	txHash := t.hash()

	// Verify each signature against the corresponding public key
	validSigs := 0
	for i, sig := range t.Signatures {
		if i >= len(pubKeys) {
			break
		}
		if ed25519.Verify(pubKeys[i].key, txHash, sig) {
			validSigs++
		}
	}

	// Check if the number of valid signatures meets the required threshold
	if validSigs < t.RequiredSigs {
		return false, fmt.Errorf("insufficient valid signatures: required %d, got %d", t.RequiredSigs, validSigs)
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
	hash := sha3.Sum256(blockData)
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
	t.AddSignature(signature.Bytes())
	return nil
}

// hash returns the SHA-256 hash of the transaction data (excluding the signature)
func (t *Transaction) hash() []byte {
	txCopy := *t
	txCopy.Signatures = nil
	txBytes, _ := json.Marshal(txCopy)
	hash := sha3.Sum256(txBytes)
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
		// Decode public keys for multi-signature verification
		pubKeys := []*PublicKey{}
		for _, sender := range []string{tx.Sender} { // Extend this logic for multiple senders if needed
			pubKey, err := PublicKeyFromString(sender)
			if err != nil {
				fmt.Printf("Invalid block: error decoding sender's public key (%v)\n", err)
				return false
			}
			pubKeys = append(pubKeys, pubKey)
		}

		// Verify multi-signature
		if !tx.VerifyMultiSignature(pubKeys) {
			fmt.Println("Invalid block: contains invalid multi-signature transaction")
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
