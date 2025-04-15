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
	TransactionPool    []Transaction
	Shards             []*Shard
}

func (bc *Blockchain) AddBlock(transactions []Transaction, signatures [][]byte) {
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		prevHash = "0000000000000000" // Set genesis block's PrevHash
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
	if privateKey == nil {
		return fmt.Errorf("private key is not initialized")
	}
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
			fmt.Printf("Invalid block: previous hash does not match (expected: %s, got: %s)\n", lastBlock.CalculateHash(), block.PrevHash)
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
		fmt.Printf("Validating transaction from %s to %s\n", tx.Sender, tx.Receiver)

		// Decode sender's public key
		pubKey, err := PublicKeyFromString(tx.Sender)
		if err != nil {
			fmt.Printf("Invalid block: error decoding sender's public key (%v)\n", err)
			return false
		}

		pubKeys := []*PublicKey{pubKey}

		// Verify transaction signatures
		if !tx.VerifyMultiSignature(pubKeys) {
			fmt.Println("Invalid block: contains invalid multi-signature transaction")
			return false
		}

		// Verify transaction fields
		if tx.Amount <= 0 {
			fmt.Println("Invalid block: transaction amount must be greater than zero")
			return false
		}
		if tx.Sender == "" || tx.Receiver == "" {
			fmt.Println("Invalid block: transaction sender or receiver is empty")
			return false
		}
	}
	// Verify block signatures
	if len(block.Signatures) < len(bc.Delegates)/2+1 { // Majority required
		fmt.Println("Invalid block: insufficient delegate signatures")
		return false
	}

	fmt.Println("Block validated successfully")

	return true
}

func (bc *Blockchain) GetLastBlockHash() string {
	if len(bc.Blocks) == 0 {
		return ""
	}
	return bc.Blocks[len(bc.Blocks)-1].CalculateHash()
}

type Shard struct {
	ID              int
	TransactionPool []Transaction
	Blocks          []Block
}

func NewShard(id int) *Shard {
	return &Shard{
		ID:              id,
		TransactionPool: []Transaction{},
		Blocks:          []Block{},
	}
}

func (bc *Blockchain) InitializeShards(numShards int) {
	for i := 0; i < numShards; i++ {
		bc.Shards = append(bc.Shards, NewShard(i))
	}
	fmt.Printf("Initialized %d shards\n", numShards)
}

func (bc *Blockchain) AssignTransactionToShard(tx Transaction) {
	// Use a hash of the sender's public key to determine the shard
	shardID := int(sha3.Sum256([]byte(tx.Sender))[0]) % len(bc.Shards)
	bc.Shards[shardID].TransactionPool = append(bc.Shards[shardID].TransactionPool, tx)
	fmt.Printf("Assigned transaction %+v to shard %d\n", tx, shardID)
}

func (shard *Shard) ValidateShardTransactions() {
	for _, tx := range shard.TransactionPool {
		// Perform transaction validation (reuse existing logic)
		pubKey, err := PublicKeyFromString(tx.Sender)
		if err != nil || !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
			fmt.Printf("Invalid transaction in shard %d: %+v\n", shard.ID, tx)
			continue
		}
		fmt.Printf("Valid transaction in shard %d: %+v\n", shard.ID, tx)
	}
}

func (bc *Blockchain) ValidateTransactionsInParallel() {
	if len(bc.TransactionPool) == 0 {
		fmt.Println("No transactions to validate.")
		return
	}

	numWorkers := 4                                                      // Number of goroutines
	chunkSize := (len(bc.TransactionPool) + numWorkers - 1) / numWorkers // Ensure chunkSize is valid

	results := make(chan bool, len(bc.TransactionPool))

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		if start >= len(bc.TransactionPool) { // Prevent out-of-bounds access
			break
		}
		end := start + chunkSize
		if end > len(bc.TransactionPool) {
			end = len(bc.TransactionPool)
		}

		go func(transactions []Transaction) {
			for _, tx := range transactions {
				pubKey, err := PublicKeyFromString(tx.Sender)
				if err != nil || !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
					results <- false
					continue
				}
				results <- true
			}
		}(bc.TransactionPool[start:end])
	}

	// Collect results
	validCount := 0
	for i := 0; i < len(bc.TransactionPool); i++ {
		if <-results {
			validCount++
		}
	}

	fmt.Printf("%d/%d transactions are valid\n", validCount, len(bc.TransactionPool))
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

func NewBlockchain() *Blockchain {
	bc := &Blockchain{
		Blocks:             []Block{},
		TransactionPool:    []Transaction{},
		LockedWallets:      make(map[[32]byte]*LockedWallet),
		PublicKeyToID:      make(map[string]string),
		UserIDToDelegateID: make(map[string]string),
		Wallets:            make(map[string]*Wallet),
	}

	// Add the genesis block
	genesisBlock := Block{
		Transactions: []Transaction{},    // No transactions in the genesis block
		PrevHash:     "0000000000000000", // Predefined hash for the genesis block
		Nonce:        0,
		Signatures:   [][]byte{},
	}
	bc.Blocks = append(bc.Blocks, genesisBlock)
	fmt.Println("Genesis block added to the blockchain.")
	return bc
}
