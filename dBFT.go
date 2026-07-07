package gonetwork

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

// ViewChangeRequest is sent by a delegate when its AchieveConsensus round fails,
// requesting all peers to advance to a new view and elect a fresh speaker.
// Item 9 Step A.
type ViewChangeRequest struct {
	View   int    `json:"view"`    // proposed new view number
	NodeID string `json:"node_id"` // ID of the requesting node
	Reason string `json:"reason"`  // human-readable reason, e.g. "timeout"
}

// Simplified Node structure
type Node struct {
	ID              string
	P2PPeerID       string
	IsDelegate      bool
	Stake           int
	Votes           int
	PrivateKey      ed25519.PrivateKey
	PublicKey       ed25519.PublicKey
	Inbox           chan Message `json:"-"`
	droppedMessages uint64       `json:"-"`
	VotingStrategy  VotingStrategy
	Blockchain      *Blockchain
	// viewChangeRequests accumulates incoming view-change request counts, keyed by
	// proposed view number. Accessed only inside ProcessMessages (a single goroutine)
	// so no separate mutex is required.
	viewChangeRequests map[int]int
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

	// Persist the elected delegate set so it survives a node restart (Item 10).
	if bc.BlockStore != nil {
		if err := bc.BlockStore.SaveDelegates(bc.Delegates); err != nil {
			log.Printf("VoteForDelegates: SaveDelegates: %v", err)
		}
	}

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
	if bc.ConsensusMode == ConsensusModeHTTP {
		bc.recordConsensusModeReject("startConsensus", ConsensusModeDBFT)
		log.Printf("startConsensus: disabled in %q consensus mode", ConsensusModeHTTP)
		return
	}

	bc.currentView = View{Number: 0}
	bc.selectSpeaker()
	bc.assertDelegateConnectivity(p2pNode)

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

type DefaultVotingStrategy struct {
	Blockchain *Blockchain
}

func (d *DefaultVotingStrategy) Vote(block Block) bool {
	// A block with no content of any kind is not worth voting yes on.
	if len(block.Transactions) == 0 && len(block.AssetTransactions) == 0 &&
		len(block.OrderTransactions) == 0 && len(block.CredentialTransactions) == 0 &&
		len(block.RFQTransactions) == 0 &&
		len(block.MarketMakerTransactions) == 0 {
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
	return d.Blockchain.validateTypedTransactions(block)
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
// if a BFT supermajority (⌈2n/3⌉) approves it. Delegates with a PrivateKey
// that vote yes also sign block.PayloadHash with Ed25519; those signatures are
// collected and stored on the block before it is finalised (Item 8 Step A).
//
// M-2: if bc.ConsensusTimeout > 0 the entire vote round is bounded by that
// duration; a timeout triggers a view-change and returns false.
func (bc *Blockchain) AchieveConsensus(block Block) bool {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates registered; consensus not applicable.")
		return false
	}

	type voteResult struct {
		yes bool
		sig []byte // non-nil when delegate voted yes and holds a PrivateKey
	}
	ch := make(chan voteResult, len(bc.Delegates))

	// voteCtx is cancelled when AchieveConsensus returns (via defer voteCancel).
	// This allows in-flight delegate goroutines to exit cleanly instead of
	// blocking on a channel send after the caller has already returned.
	voteCtx, voteCancel := context.WithCancel(context.Background())
	defer voteCancel()

	for _, delegate := range bc.Delegates {
		d := delegate // capture loop variable
		go func() {
			voted := d.VoteOnBlock(block) // may block; cannot be interrupted
			var sig []byte
			// Item 8 Step A: if the delegate approved the block and holds an
			// Ed25519 private key, sign the PayloadHash bytes so the block
			// carries a real cryptographic proof of approval.
			if voted && len(d.PrivateKey) > 0 && block.PayloadHash != "" {
				hashBytes, err := hex.DecodeString(block.PayloadHash)
				if err == nil {
					sig = ed25519.Sign(d.PrivateKey, hashBytes)
				}
			}
			select {
			case ch <- voteResult{yes: voted, sig: sig}:
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
	var collectedSigs [][]byte

	for collected := 0; collected < len(bc.Delegates); collected++ {
		select {
		case v := <-ch:
			if v.yes {
				yesVotes++
				if v.sig != nil {
					collectedSigs = append(collectedSigs, v.sig)
				}
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
		block.Signatures = collectedSigs
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
		if s, ok := n.VotingStrategy.(*DefaultVotingStrategy); ok {
			if s.Blockchain == nil {
				copy := *s
				copy.Blockchain = n.Blockchain
				return copy.Vote(block)
			}
		}
		return n.VotingStrategy.Vote(block)
	}
	// Default to "yes" if no strategy is set
	return true
}

// finalizeBlock appends a consensus-approved block to the chain and applies its
// state transitions. It is always called from AchieveConsensus after reaching
// the BFT supermajority threshold.
//
// Item 8: if createBlock pre-computed the chain-linking fields and called
// SetPayloadHash before delegates signed, the PayloadHash produced here will
// match the pre-computed one and the delegate signatures are preserved.
// If a concurrent chain modification invalidated the pre-computed hash (should
// not occur in normal single-speaker dBFT), the signatures are discarded.
func (bc *Blockchain) finalizeBlock(block Block) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Snapshot the pre-computed values so we can detect whether chain state
	// changed between createBlock's proposal and this finalization.
	precomputedPayloadHash := block.PayloadHash
	precomputedSignatures := block.Signatures

	// Set chain-linking fields. When createBlock pre-computes these under an
	// RLock snapshot, the values will match what we derive here from the live
	// chain state, making SetPayloadHash() produce the same hash both times.
	block.Index = len(bc.Blocks)
	block.Nonce = bc.Nonce
	if len(bc.Blocks) > 0 {
		block.PrevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		block.PrevHash = strings.Repeat("0", 64)
	}
	block.SetPayloadHash()

	// Restore pre-collected delegate signatures if the PayloadHash is still
	// valid. If the hash changed (concurrent insertion — should not occur in
	// normal operation), discard the signatures and log a warning.
	if precomputedPayloadHash != "" {
		if block.PayloadHash == precomputedPayloadHash {
			block.Signatures = precomputedSignatures
		} else {
			log.Printf("finalizeBlock: PayloadHash changed during finalization — pre-collected delegate signatures discarded")
			block.Signatures = nil
		}
	}

	// Item 24: co-sign every dBFT-finalized block with the operator key so both
	// HTTP and dBFT production paths emit a consistent signature set.
	if bc.OperatorKeyProvider != nil {
		payloadBytes, err := hex.DecodeString(block.PayloadHash)
		if err == nil {
			sig, err := bc.OperatorKeyProvider.Sign(payloadBytes)
			if err == nil {
				block.Signatures = append(block.Signatures, sig)
			} else {
				log.Printf("finalizeBlock: operator signing failed: %v", err)
			}
		}
	}

	bc.Blocks = append(bc.Blocks, block)
	bc.markCommittedTxHashes(&bc.Blocks[len(bc.Blocks)-1])
	bc.Nonce++

	bc.emitEvent(EventBlockFinalised, map[string]any{
		"block_index": len(bc.Blocks) - 1,
		"hash":        block.CalculateHash(),
		"tx_count":    len(block.Transactions),
	})

	// Apply all transaction state (order matching, DVP, prospectus counts, etc.)
	bc.applyBlockState(&bc.Blocks[len(bc.Blocks)-1])

	// C-4: persist state snapshot so chain state survives restarts.
	if bc.BlockStore != nil {
		idx := len(bc.Blocks) - 1
		if err := bc.BlockStore.SaveState(bc, idx); err != nil {
			log.Printf("finalizeBlock: state snapshot failed: %v", err)
		}
	}
}

// createBlock proposes a new block from the current transaction pool,
// pre-computes all chain-linking fields and PayloadHash, then collects real
// Ed25519 delegate signatures via AchieveConsensus (Item 8 Step A).
func (bc *Blockchain) createBlock(p2pNode *P2PNode) {
	if bc.ConsensusMode == ConsensusModeHTTP {
		bc.recordConsensusModeReject("createBlock", ConsensusModeDBFT)
		log.Printf("createBlock: disabled in %q consensus mode", ConsensusModeHTTP)
		return
	}

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

	// Snapshot chain-linking fields under a read-lock so the PayloadHash is
	// stable before delegates sign. finalizeBlock will derive the same values
	// (assuming no concurrent block insertion, which cannot happen in normal
	// single-speaker dBFT) and therefore produce an identical PayloadHash,
	// preserving the pre-collected signatures.
	bc.Mu.RLock()
	nextIndex := len(bc.Blocks)
	nextNonce := bc.Nonce
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		prevHash = strings.Repeat("0", 64)
	}
	bc.Mu.RUnlock()

	block := Block{
		Index:        nextIndex,
		Nonce:        nextNonce,
		PrevHash:     prevHash,
		Transactions: bc.TransactionPool,
		SealedAt:     time.Now().UnixMicro(),
	}
	if bc.OperatorKeyProvider != nil {
		block.KeyVersion = bc.OperatorKeyProvider.PublicKeyString()
	}
	// Compute a stable PayloadHash before delegates sign. AchieveConsensus
	// will have each approving delegate sign this hash with their Ed25519 key.
	block.SetPayloadHash()

	// Item 9 Step D: retry consensus across all possible speakers before
	// giving up. Each failed attempt triggers a view-change (Step B) so that
	// nodes running ProcessMessages can track the advancing view number.
	maxAttempts := len(bc.Delegates)
	sealed := false
	for attempt := 0; attempt < maxAttempts; attempt++ {
		bc.selectSpeaker()

		if bc.AchieveConsensus(block) {
			// finalizeBlock appended the block; clear the shard pools.
			for _, shard := range bc.Shards {
				shard.TransactionPool = []Transaction{}
			}
			fmt.Printf("Block %d created with %d delegate signature(s)\n",
				len(bc.Blocks)-1, len(bc.Blocks[len(bc.Blocks)-1].Signatures))
			sealed = true
			break
		}

		// Item 9 Step B: broadcast a ViewChangeRequest to all delegate inboxes
		// so that nodes running ProcessMessages can advance their own view state.
		speakerID := bc.Delegates[bc.currentSpeaker].ID
		nextView := bc.currentView.Number + 1
		vcReq := ViewChangeRequest{
			View:   nextView,
			NodeID: speakerID,
			Reason: "timeout",
		}
		for i := range bc.Delegates {
			bc.Delegates[i].ReceiveMessage(Message{
				From:    speakerID,
				Type:    ViewChangeReq,
				Payload: vcReq,
			})
		}
		bc.currentView = View{Number: nextView}
	}

	if !sealed {
		fmt.Println("Failed to achieve consensus after all view attempts. Block not added.")
		bc.emitEvent(EventConsensusFailure, map[string]any{
			"attempts": maxAttempts,
			"view":     bc.currentView.Number,
		})
	}

	// Advance to the next view for the following block round.
	bc.currentView = View{Number: bc.currentView.Number + 1}
	bc.selectSpeaker()
}

// NewNode creates a new node
func NewNode(id string, blockchain *Blockchain) *Node {
	return &Node{
		ID:                 id,
		Inbox:              make(chan Message, 1000), // Buffered channel for consensus bursts
		Blockchain:         blockchain,               // Initialize the blockchain reference
		viewChangeRequests: make(map[int]int),
	}
}

// DroppedMessages returns the cumulative number of messages dropped because
// the node inbox was full.
func (n *Node) DroppedMessages() uint64 {
	if n == nil {
		return 0
	}
	return atomic.LoadUint64(&n.droppedMessages)
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

// HandleFork is a no-op under dBFT (Item 12). dBFT provides single-path
// irreversible finality: once ⌈2n/3⌉ delegates have signed a block it
// cannot be replaced. A peer presenting a longer chain is either
// out-of-sync (it should catch up via SyncBlockchain) or Byzantine.
// Longest-chain fork resolution has been removed — see blockchain.go.
func (n *Node) HandleFork(peer *Node) {
	if len(peer.Blockchain.Blocks) > len(n.Blockchain.Blocks) {
		log.Printf("[dBFT] HandleFork: peer %s has a longer chain (%d > %d) — "+
			"dBFT provides single-path finality; no fork resolution will be attempted. "+
			"If this node is behind, use SyncBlockchain instead.",
			peer.ID, len(peer.Blockchain.Blocks), len(n.Blockchain.Blocks))
	}
}

// SendMessage sends a message to the network
func (n *Node) SendMessage(p2pNode *P2PNode, msg Message) {
	if p2pNode == nil {
		fmt.Println("Failed to send message: p2p node is nil")
		return
	}
	if p2pNode.Topic == nil {
		fmt.Println("Failed to send message: p2p topic is nil")
		return
	}

	if msg.Type == BlockProposal || msg.Type == Vote || msg.Type == ViewChangeReq || msg.Type == ViewChangeResp {
		if err := p2pNode.PublishConsensusMessage(msg); err != nil {
			fmt.Printf("Failed to send consensus message: %v\n", err)
		}
		return
	}
	if err := p2pNode.ensureOpen(); err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("Failed to serialize message: %v\n", err)
		return
	}

	if err := p2pNode.Topic.Publish(p2pNode.publishCtx(), data); err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
	}
}

// assertDelegateConnectivity checks that delegates with configured P2P peer IDs
// are reachable before consensus starts. Each delegate gets up to 3 dial
// attempts; unreachable delegates emit EventDelegateUnreachable (warning only).
func (bc *Blockchain) assertDelegateConnectivity(p2pNode *P2PNode) {
	if p2pNode == nil || p2pNode.Host == nil {
		return
	}

	bc.Mu.RLock()
	delegates := make([]Node, len(bc.Delegates))
	copy(delegates, bc.Delegates)
	bc.Mu.RUnlock()

	for _, d := range delegates {
		if d.P2PPeerID == "" {
			continue
		}
		pid, err := peer.Decode(d.P2PPeerID)
		if err != nil {
			bc.emitEvent(EventDelegateUnreachable, map[string]any{
				"delegate_id": d.ID,
				"peer_id":     d.P2PPeerID,
				"reason":      "invalid_peer_id",
			})
			continue
		}

		if p2pNode.Host.Network().Connectedness(pid) == network.Connected {
			continue
		}

		reachable := false
		for attempt := 1; attempt <= 3; attempt++ {
			pi := p2pNode.Host.Peerstore().PeerInfo(pid)
			if pi.ID == "" {
				pi.ID = pid
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = p2pNode.Host.Connect(ctx, pi)
			cancel()
			if err == nil || p2pNode.Host.Network().Connectedness(pid) == network.Connected {
				reachable = true
				break
			}
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
		if !reachable {
			bc.emitEvent(EventDelegateUnreachable, map[string]any{
				"delegate_id": d.ID,
				"peer_id":     d.P2PPeerID,
				"reason":      "unreachable_after_3_attempts",
			})
		}
	}
}

// ReceiveMessage handles incoming messages
func (n *Node) ReceiveMessage(msg Message) {
	// Use a non-blocking send: if Inbox is full the message is
	// dropped rather than leaving a goroutine permanently blocked on the send.
	go func() {
		select {
		case n.Inbox <- msg:
		default:
			dropped := atomic.AddUint64(&n.droppedMessages, 1)
			log.Printf("Node %s inbox full — dropping message type %q (dropped=%d)", n.ID, msg.Type, dropped)
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
		// Item 9 Step C: accumulate view-change requests and advance the view
		// when f+1 matching requests are received for the same proposed view.
		case ViewChangeReq:
			req, ok := msg.Payload.(ViewChangeRequest)
			if !ok {
				fmt.Printf("Node %s received malformed ViewChangeRequest\n", n.ID)
				break
			}
			if n.viewChangeRequests == nil {
				n.viewChangeRequests = make(map[int]int)
			}
			n.viewChangeRequests[req.View]++
			if n.Blockchain == nil {
				break
			}
			n.Blockchain.Mu.RLock()
			numDelegates := len(n.Blockchain.Delegates)
			n.Blockchain.Mu.RUnlock()
			if numDelegates == 0 {
				break
			}
			f := (numDelegates - 1) / 3
			if n.viewChangeRequests[req.View] >= f+1 {
				delete(n.viewChangeRequests, req.View)
				n.Blockchain.Mu.Lock()
				if n.Blockchain.currentView.Number < req.View {
					n.Blockchain.currentView = View{Number: req.View}
					n.Blockchain.selectSpeaker()
					fmt.Printf("Node %s: view-change to view %d — new speaker index %d\n",
						n.ID, req.View, n.Blockchain.currentSpeaker)
				}
				n.Blockchain.Mu.Unlock()
			}
		}
	}
}
