package gonetwork

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

// Simplified Node structure
type Node struct {
	ID             string
	IsDelegate     bool
	Stake          int
	Votes          int
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
	Inbox          chan Message `json:"-"`
	VotingStrategy VotingStrategy
	Blockchain     *Blockchain
}

// VoteForDelegates selects delegates based on staked currency
func (bc *Blockchain) VoteForDelegates(p2pNode *P2PNode) {
	// Reset delegates
	bc.Mu.Lock()
	bc.Delegates = []Node{}

	votes := make(map[string]float64)

	// Calculate votes based on locked wallets
	for _, lockedWallet := range bc.LockedWallets {
		// Get the voter's ID and their chosen delegate's ID
		voterID := bc.getVoterID(lockedWallet.OwnerPublicKey)
		delegateID := bc.getDelegateID(voterID)

		if delegateID != "" {
			votes[delegateID] += lockedWallet.Balance
		}
	}

	// Assign votes to nodes and select delegates
	for i := range bc.Nodes {
		node := &bc.Nodes[i]
		if votes[node.ID] > 0 {
			node.Votes = int(votes[node.ID])
			node.IsDelegate = true
			bc.Delegates = append(bc.Delegates, *node)
		}
	}
	bc.Mu.Unlock()

	// Log the elected delegates
	for _, delegate := range bc.Delegates {
		fmt.Printf("Delegate %s received %d votes\n", delegate.ID, delegate.Votes)
	}

	// Start the consensus process
	if len(bc.Delegates) > 0 {
		bc.startConsensus(p2pNode)
	} else {
		fmt.Println("No delegates elected. Consensus cannot start.")
	}
}

// Get voter ID from public key
func (bc *Blockchain) getVoterID(publicKey [32]byte) string {
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey[:])
	return bc.PublicKeyToID[publicKeyStr]
}

// Get delegate ID from voter ID
func (bc *Blockchain) getDelegateID(voterID string) string {
	return bc.UserIDToDelegateID[voterID]
}

// RegisterDelegateVote records that voter userID delegates their consensus
// voting power to delegateID. Call with userID == delegateID for self-delegation
// (the default for any wallet that participates in consensus directly).
// This populates UserIDToDelegateID so that getDelegateID returns the correct
// entry (H-6: previously the map was initialised but never written to).
func (bc *Blockchain) RegisterDelegateVote(userID, delegateID string) {
	if userID == "" || delegateID == "" {
		return
	}
	bc.Mu.Lock()
	bc.UserIDToDelegateID[userID] = delegateID
	bc.Mu.Unlock()
}

// Start the consensus process
func (bc *Blockchain) startConsensus(p2pNode *P2PNode) {
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()

	// Snapshot the transaction pool under the read lock so the block content
	// is consistent and no concurrent AddTransaction call races on the slice.
	bc.Mu.RLock()
	txSnapshot := make([]Transaction, len(bc.TransactionPool))
	copy(txSnapshot, bc.TransactionPool)
	prevHash := bc.GetLastBlockHash()
	bc.Mu.RUnlock()

	block := Block{
		Transactions: txSnapshot,
		PrevHash:     prevHash,
	}

	// Validate the block before broadcasting
	if !bc.ValidateBlock(block) {
		fmt.Println("Proposed block is invalid. Consensus cannot proceed.")
		return
	}

	// Broadcast block proposal
	if err := p2pNode.BroadcastBlock(block); err != nil {
		fmt.Printf("Failed to broadcast block proposal: %v\n", err)
		return
	}

	// Clear the transaction pool after proposing the block
	bc.Mu.Lock()
	bc.TransactionPool = []Transaction{}
	bc.Mu.Unlock()
}

type FuncVotingStrategy struct {
	VoteFunc func(block Block) bool
}

func (f *FuncVotingStrategy) Vote(block Block) bool {
	return f.VoteFunc(block)
}

type VotingStrategy interface {
	Vote(block Block) bool
}

type DefaultVotingStrategy struct{}

func (d *DefaultVotingStrategy) Vote(block Block) bool {
	// A block with no content of any kind is not worth voting yes on.
	if len(block.Transactions) == 0 && len(block.AssetTransactions) == 0 &&
		len(block.OrderTransactions) == 0 && len(block.CredentialTransactions) == 0 {
		return false
	}
	// Validate each base transaction's signature when signatures are required.
	// Transactions with RequiredSigs == 0 are legacy or internal entries that
	// do not carry end-user signatures and are accepted without verification.
	for _, tx := range block.Transactions {
		if tx.RequiredSigs == 0 {
			continue
		}
		pubKey, err := PublicKeyFromString(tx.Sender)
		if err != nil {
			return false
		}
		if !tx.VerifyMultiSignature([]*PublicKey{pubKey}) {
			return false
		}
	}
	return true
}

// Select the speaker (proposer) for the current view
func (bc *Blockchain) selectSpeaker() {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to select a speaker.")
		return
	}
	bc.currentSpeaker = int(bc.currentView.Number) % len(bc.Delegates)
	fmt.Printf("Speaker for view %d is %s\n", bc.currentView.Number, bc.Delegates[bc.currentSpeaker].ID)
}

// AchieveConsensus collects votes from all delegates and finalises the block
// if a BFT supermajority (⌈2n/3⌉) approves it.
//
// M-2: if bc.ConsensusTimeout > 0 the entire vote round is bounded by that
// duration; a timeout triggers a view-change and returns false.
func (bc *Blockchain) AchieveConsensus(block Block) bool {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates registered; consensus not applicable.")
		return false
	}

	type voteResult struct{ yes bool }
	ch := make(chan voteResult, len(bc.Delegates))

	// voteCtx is cancelled when AchieveConsensus returns (via defer voteCancel).
	// This allows in-flight delegate goroutines to exit cleanly instead of
	// blocking on a channel send after the caller has already returned.
	voteCtx, voteCancel := context.WithCancel(context.Background())
	defer voteCancel()

	for _, delegate := range bc.Delegates {
		d := delegate // capture loop variable
		go func() {
			result := d.VoteOnBlock(block) // may block; cannot be interrupted
			select {
			case ch <- voteResult{yes: result}:
			case <-voteCtx.Done(): // consensus already returned; discard result
			}
		}()
	}

	// M-2: apply view-change timeout when configured.
	var deadline <-chan time.Time
	if bc.ConsensusTimeout > 0 {
		deadline = time.After(bc.ConsensusTimeout)
	}

	yesVotes := 0
	noVotes := 0
	consensusThreshold := int(math.Ceil(float64(2*len(bc.Delegates)) / 3.0))

	for collected := 0; collected < len(bc.Delegates); collected++ {
		select {
		case v := <-ch:
			if v.yes {
				yesVotes++
			} else {
				noVotes++
			}
		case <-deadline:
			fmt.Printf("Consensus timed out after %v — triggering view-change (M-2)\n", bc.ConsensusTimeout)
			return false
		}
	}

	if yesVotes >= consensusThreshold {
		fmt.Printf("Consensus achieved with %d yes votes out of %d\n", yesVotes, len(bc.Delegates))
		bc.finalizeBlock(block)
		return true
	}

	fmt.Printf("Consensus not achieved. Yes votes: %d, No votes: %d\n", yesVotes, noVotes)
	return false
}

func (bc *Blockchain) AddTransaction(tx Transaction) {
	fmt.Printf("Attempting to add transaction: %+v\n", tx)

	// Decode sender's public key
	pubKey, err := PublicKeyFromString(tx.Sender)
	if err != nil {
		fmt.Printf("Invalid transaction: error decoding sender's public key (%v)\n", err)
		return
	}

	pubKeys := []*PublicKey{pubKey}

	// Verify transaction signatures
	if !tx.VerifyMultiSignature(pubKeys) {
		fmt.Println("Invalid transaction: contains invalid multi-signature")
		return
	}

	// Verify transaction fields
	if tx.Amount <= 0 {
		fmt.Println("Invalid transaction: amount must be greater than zero")
		return
	}
	if tx.Sender == "" || tx.Receiver == "" {
		fmt.Println("Invalid transaction: sender or receiver is empty")
		return
	}

	// Check for duplicate nonce and enforce the per-wallet sequence counter
	// under a single lock to eliminate the TOCTOU race between the two checks.
	bc.Mu.Lock()
	for _, shard := range bc.Shards {
		for _, existingTx := range shard.TransactionPool {
			if existingTx.Nonce == tx.Nonce && existingTx.Sender == tx.Sender {
				bc.Mu.Unlock()
				fmt.Println("Invalid transaction: duplicate nonce detected")
				return
			}
		}
	}

	// M-9: per-wallet sequence counter enforcement.
	// tx.Nonce must be strictly greater than the last accepted nonce for this sender.
	lastSeq := bc.WalletSequences[tx.Sender]
	if tx.Nonce <= lastSeq {
		bc.Mu.Unlock()
		fmt.Printf("Invalid transaction: nonce %d is not greater than last sequence %d for sender %s\n", tx.Nonce, lastSeq, tx.Sender)
		return
	}
	bc.WalletSequences[tx.Sender] = tx.Nonce

	// Assign the transaction to a shard (still under lock to avoid concurrent appends).
	shardID := int(sha3.Sum256([]byte(tx.Sender))[0]) % len(bc.Shards)
	bc.Shards[shardID].TransactionPool = append(bc.Shards[shardID].TransactionPool, tx)
	bc.Mu.Unlock()
	fmt.Printf("Transaction assigned to shard %d: %+v\n", shardID, tx)

	// Broadcast the transaction
	if bc.P2PNode != nil {
		if err := bc.P2PNode.BroadcastTransaction(tx); err != nil {
			fmt.Printf("Failed to broadcast transaction: %v\n", err)
		}
	}
}

// SortTransactionPool sorts the transaction pool by priority (timestamp and amount)
func (bc *Blockchain) SortTransactionPool() {
	sort.SliceStable(bc.TransactionPool, func(i, j int) bool {
		// Higher priority for older transactions and higher amounts
		if bc.TransactionPool[i].Nonce == bc.TransactionPool[j].Nonce {
			return bc.TransactionPool[i].Amount > bc.TransactionPool[j].Amount
		}
		return bc.TransactionPool[i].Nonce < bc.TransactionPool[j].Nonce
	})
}

// Delegate votes on a block (simplified logic)
func (n *Node) VoteOnBlock(block Block) bool {
	if n.VotingStrategy != nil {
		return n.VotingStrategy.Vote(block)
	}
	// Default to "yes" if no strategy is set
	return true
}

// finalizeBlock appends a consensus-approved block to the chain and applies its
// state transitions. It is always called from AchieveConsensus after reaching
// the BFT supermajority threshold.
func (bc *Blockchain) finalizeBlock(block Block) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Set chain-linking fields and append. Do not use AddBlock here because
	// the block's signatures were collected before appending; we only need to
	// stamp its Index and chain reference.
	block.Index = len(bc.Blocks)
	block.Nonce = bc.Nonce
	if len(bc.Blocks) > 0 {
		block.PrevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		block.PrevHash = strings.Repeat("0", 64)
	}
	block.SetPayloadHash()

	bc.Blocks = append(bc.Blocks, block)
	bc.Nonce++

	bc.emitEvent(EventBlockFinalised, map[string]any{
		"block_index": len(bc.Blocks) - 1,
		"hash":        block.CalculateHash(),
		"tx_count":    len(block.Transactions),
	})

	// Apply all transaction state (order matching, DVP, prospectus counts, etc.)
	bc.applyBlockState(&bc.Blocks[len(bc.Blocks)-1])
}

// createBlock proposes a new block from the current transaction pool,
// collects delegate signatures, and attempts consensus.
func (bc *Blockchain) createBlock(p2pNode *P2PNode) {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to create a block.")
		return
	}

	// Collect transactions from all shards.
	collectedTransactions := []Transaction{}
	for _, shard := range bc.Shards {
		collectedTransactions = append(collectedTransactions, shard.TransactionPool...)
	}
	if len(collectedTransactions) == 0 {
		fmt.Println("No transactions to include in the block.")
		return
	}

	bc.TransactionPool = collectedTransactions
	bc.ValidateTransactionsInParallel()

	// Collect placeholder signatures (real Ed25519 signing added in Step 11).
	signatures := [][]byte{}
	for _, delegate := range bc.Delegates {
		signatures = append(signatures, []byte(delegate.ID))
	}

	block := Block{
		Transactions: bc.TransactionPool,
		Signatures:   signatures,
	}
	if bc.AchieveConsensus(block) {
		// finalizeBlock appended the block; clear the shard pools.
		for _, shard := range bc.Shards {
			shard.TransactionPool = []Transaction{}
		}
		fmt.Printf("Block %d created with signatures: %v\n", len(bc.Blocks)-1, signatures)
	} else {
		fmt.Println("Failed to achieve consensus. Block not added.")
	}

	bc.currentView = View{Number: bc.currentView.Number + 1}
	bc.selectSpeaker()
}

// NewNode creates a new node
func NewNode(id string, blockchain *Blockchain) *Node {
	return &Node{
		ID:         id,
		Inbox:      make(chan Message, 10), // Buffered channel for messages
		Blockchain: blockchain,             // Initialize the blockchain reference
	}
}

func (n *Node) SyncBlockchain(peer *Node) {
	fmt.Printf("Node %s syncing blockchain from peer %s\n", n.ID, peer.ID)
	n.Blockchain = peer.Blockchain
	fmt.Printf("Node %s successfully synced blockchain\n", n.ID)
}

func (n *Node) PeriodicStateSaving(ctx context.Context, filename string) {
	go func() {
		for {
			err := n.Blockchain.SaveBlockchain(filename)
			if err != nil {
				fmt.Printf("Node %s failed to save blockchain: %v\n", n.ID, err)
			} else {
				fmt.Printf("Node %s successfully saved blockchain state\n", n.ID)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
}

func (n *Node) HandleFork(peer *Node) {
	fmt.Printf("Node %s checking for fork with peer %s\n", n.ID, peer.ID)
	if len(peer.Blockchain.Blocks) > len(n.Blockchain.Blocks) {
		if n.Blockchain.ResolveFork(peer.Blockchain.Blocks) {
			fmt.Printf("Node %s resolved fork and updated its blockchain\n", n.ID)
		} else {
			fmt.Printf("Node %s detected invalid chain from peer %s\n", n.ID, peer.ID)
		}
	}
}

// SendMessage sends a message to the network
func (n *Node) SendMessage(p2pNode *P2PNode, msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("Failed to serialize message: %v\n", err)
		return
	}

	if err := p2pNode.Topic.Publish(context.Background(), data); err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
	}
}

// ReceiveMessage handles incoming messages
func (n *Node) ReceiveMessage(msg Message) {
	// Use a non-blocking send: if Inbox (cap 10) is full the message is
	// dropped rather than leaving a goroutine permanently blocked on the send.
	go func() {
		select {
		case n.Inbox <- msg:
		default:
			fmt.Printf("Node %s inbox full — message dropped\n", n.ID)
		}
	}()
}

func (n *Node) ProcessMessages() {
	for msg := range n.Inbox {
		switch msg.Type {
		case BlockProposal:
			fmt.Printf("Node %s received block proposal: %+v\n", n.ID, msg.Payload)
		case Vote:
			fmt.Printf("Node %s received vote: %+v\n", n.ID, msg.Payload)
		case Consensus:
			fmt.Printf("Node %s received consensus result: %+v\n", n.ID, msg.Payload)
		case "Transaction":
			tx, ok := msg.Payload.(Transaction)
			if ok {
				n.Blockchain.AddTransaction(tx)
			}
		}
	}
}
