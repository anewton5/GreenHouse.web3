package gonetwork

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
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

// Start the consensus process
func (bc *Blockchain) startConsensus(p2pNode *P2PNode) {
	bc.currentView = View{Number: 0}
	bc.selectSpeaker()

	// Access the speaker directly
	block := Block{
		Transactions: bc.TransactionPool, // Use transactions from the pool
		PrevHash:     bc.GetLastBlockHash(),
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
	bc.TransactionPool = []Transaction{}
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
	// Example: Vote "yes" if the block contains at least one transaction
	return len(block.Transactions) > 0
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

// AchieveConsensus ensures consensus is reached among delegates
func (bc *Blockchain) AchieveConsensus(block Block) bool {
	yesVotes := 0
	noVotes := 0

	// Aggregate votes from delegates
	for _, delegate := range bc.Delegates {
		vote := delegate.VoteOnBlock(block)
		fmt.Printf("Delegate %s voted %v on the block\n", delegate.ID, vote)

		if vote {
			yesVotes++
		} else {
			noVotes++
		}
	}

	consensusThreshold := (2 * len(bc.Delegates)) / 3
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

	// Check for duplicate nonce (replay protection)
	for _, shard := range bc.Shards {
		for _, existingTx := range shard.TransactionPool {
			if existingTx.Nonce == tx.Nonce && existingTx.Sender == tx.Sender {
				fmt.Println("Invalid transaction: duplicate nonce detected")
				return
			}
		}
	}

	// Assign the transaction to a shard
	shardID := int(sha3.Sum256([]byte(tx.Sender))[0]) % len(bc.Shards)
	bc.Shards[shardID].TransactionPool = append(bc.Shards[shardID].TransactionPool, tx)
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
func (bc *Blockchain) finalizeBlock(block Block) {
	fmt.Printf("Finalizing block with hash: %s\n", block.CalculateHash())

	// 1. Append to chain
	bc.Blocks = append(bc.Blocks, block)
	bc.emitEvent(EventBlockFinalised, map[string]any{
		"block_index": len(bc.Blocks) - 1,
		"hash":        block.CalculateHash(),
		"tx_count":    len(block.Transactions),
	})

	// 2. Apply asset transactions from this block
	for _, tx := range block.AssetTransactions {
		if err := tx.Validate(bc.Assets, bc.Holdings, bc.Credentials, bc.PendingCorporateActions, bc.AMLScreener); err != nil {
			fmt.Printf("Skipping invalid asset tx: %v\n", err)
			continue
		}
		if err := ApplyAssetTransaction(&tx, bc.Assets, bc.Holdings); err != nil {
			fmt.Printf("Failed to apply asset tx: %v\n", err)
		}
	}

	// 3. Apply credential transactions
	for _, ct := range block.CredentialTransactions {
		bc.Credentials[ct.Attestation.WalletPublicKey] = &ct.Attestation
		bc.emitEvent(EventCredentialIssued, map[string]any{
			"wallet_key":     ct.Attestation.WalletPublicKey,
			"investor_class": ct.Attestation.InvestorClass,
			"kyc_status":     ct.Attestation.KYCStatus,
			"expires_at":     ct.Attestation.ExpiresAt,
		})
	}

	// 4. Apply new orders to order books
	for _, ot := range block.OrderTransactions {
		if ot.IsCancellation {
			if ob, ok := bc.OrderBooks[ot.Order.AssetID]; ok {
				if err := ob.CancelOrder(ot.Order.ID, ot.Tx.Sender); err != nil {
					fmt.Printf("Failed to cancel order %s: %v\n", ot.Order.ID, err)
				}
			}
			bc.emitEvent(EventOrderCancelled, map[string]any{
				"order_id": ot.Order.ID,
				"asset_id": ot.Order.AssetID,
			})
			continue
		}
		if _, ok := bc.OrderBooks[ot.Order.AssetID]; !ok {
			bc.OrderBooks[ot.Order.AssetID] = NewOrderBook(ot.Order.AssetID)
		}
		pubKey, err := PublicKeyFromString(ot.Tx.Sender)
		if err != nil {
			fmt.Printf("Failed to decode order placer key: %v\n", err)
			continue
		}
		if err := bc.OrderBooks[ot.Order.AssetID].AddOrder(&ot.Order, pubKey); err != nil {
			fmt.Printf("Failed to add order to book: %v\n", err)
		} else {
			bc.emitEvent(EventOrderPlaced, map[string]any{
				"order_id": ot.Order.ID,
				"asset_id": ot.Order.AssetID,
				"side":     ot.Order.Side,
				"price":    ot.Order.Price,
				"quantity": ot.Order.Quantity,
			})
		}
	}

	// 5. Run matching engine for all order books.
	// If the WindowManager has registered windows for an asset, matching is
	// suppressed here — Tick() already ran MatchOrders when the window closed.
	if bc.WindowManager != nil {
		windowResults := bc.WindowManager.Tick(bc)
		bc.WindowResults = append(bc.WindowResults, windowResults...)
	}

	for assetID, ob := range bc.OrderBooks {
		// Skip assets managed by the WindowManager — they match on window close only.
		if bc.WindowManager != nil && bc.WindowManager.IsManaged(assetID) {
			continue
		}

		asset, ok := bc.Assets[assetID]
		if !ok {
			continue
		}
		trades, assetTxs, err := ob.MatchOrders(assetID, asset.Currency)
		if err != nil {
			fmt.Printf("MatchOrders error for asset %s: %v\n", assetID, err)
			continue
		}

		for i, trade := range trades {
			bc.Trades = append(bc.Trades, trade)
			bc.emitEvent(EventTradeExecuted, map[string]any{
				"trade_id":  trade.ID,
				"asset_id":  trade.AssetID,
				"quantity":  trade.Quantity,
				"price":     trade.Price,
				"currency":  trade.Currency,
				"buyer_id":  trade.BuyerID,
				"seller_id": trade.SellerID,
			})

			// 6. Issue PaymentInstruction for each trade
			instruction := &PaymentInstruction{
				TradeID:       trade.ID,
				AssetID:       trade.AssetID,
				Quantity:      trade.Quantity,
				PricePerUnit:  trade.Price,
				TotalAmount:   trade.Price * trade.Quantity,
				Currency:      trade.Currency,
				Method:        SettlementSEPA,
				PayerWalletID: trade.BuyerID,
				PayeeWalletID: trade.SellerID,
				Reference:     fmt.Sprintf("GH-%s", trade.ID[:8]),
				ExpiresAt:     time.Now().Unix() + 86400, // 24 h to pay
			}
			instruction, _ = bc.OracleService.SignInstruction(instruction)
			bc.PendingInstructions[trade.ID] = instruction

			// 7. Simulate payment confirmation (MockPaymentProvider confirms instantly)
			_ = bc.PaymentProvider.ConfirmPayment(
				instruction.Reference,
				instruction.TotalAmount,
				instruction.Currency,
			)
			status, _ := bc.PaymentProvider.GetPaymentStatus(instruction.Reference)
			if status == PaymentStatusConfirmed {
				confirmation := &PaymentConfirmation{
					InstructionID:   trade.ID,
					Reference:       instruction.Reference,
					ConfirmedAmount: instruction.TotalAmount,
					Currency:        instruction.Currency,
					ConfirmedAt:     time.Now().Unix(),
				}
				confirmation, _ = bc.OracleService.SignConfirmation(confirmation)
				bc.ConfirmedPayments[trade.ID] = confirmation
				bc.emitEvent(EventPaymentConfirmed, map[string]any{
					"trade_id":  trade.ID,
					"reference": instruction.Reference,
					"amount":    instruction.TotalAmount,
					"currency":  instruction.Currency,
				})

				// 8. DVP: apply asset transfer now that payment is confirmed
				// AssetTransactions from MatchOrders are unsigned (seller key not in scope here).
				// ApplyAssetTransaction is called directly, bypassing Validate's signature check.
				atx := assetTxs[i]
				if err := ApplyAssetTransaction(atx, bc.Assets, bc.Holdings); err != nil {
					fmt.Printf("DVP apply failed for trade %s: %v\n", trade.ID, err)
				}
			}
		}
	}

	// 9. Update prospectus retail counts and emit threshold warnings.
	for _, pe := range bc.ProspectusExemptions {
		UpdateRetailCounts(pe, bc.Holdings, bc.Credentials)
	}
	CheckProspectusThresholds(bc, bc.ProspectusExemptions)
}

// Create a new block and add it to the blockchain
func (bc *Blockchain) createBlock(p2pNode *P2PNode) {
	if len(bc.Delegates) == 0 {
		fmt.Println("No delegates available to create a block.")
		return
	}

	// Collect transactions from all shards
	collectedTransactions := []Transaction{}
	for _, shard := range bc.Shards {
		collectedTransactions = append(collectedTransactions, shard.TransactionPool...)
	}

	// Check if there are transactions to validate
	if len(collectedTransactions) == 0 {
		fmt.Println("No transactions to include in the block.")
		return
	}

	// Validate transactions in parallel
	bc.TransactionPool = collectedTransactions // Temporarily set the transaction pool
	bc.ValidateTransactionsInParallel()

	// Log the transaction pool
	fmt.Printf("Transaction pool before block creation: %+v\n", bc.TransactionPool)

	// Collect signatures from delegates
	signatures := [][]byte{}
	for _, delegate := range bc.Delegates {
		signatures = append(signatures, []byte(delegate.ID))
	}

	// Attempt to achieve consensus
	block := Block{
		Transactions: bc.TransactionPool,
		PrevHash:     bc.GetLastBlockHash(),
		Signatures:   signatures,
	}
	if bc.AchieveConsensus(block) {
		bc.AddBlock(block.Transactions, signatures)

		// Clear transaction pools in all shards
		for _, shard := range bc.Shards {
			shard.TransactionPool = []Transaction{}
		}

		fmt.Printf("Block %d created with signatures: %v\n", len(bc.Blocks)-1, signatures)
	} else {
		fmt.Println("Failed to achieve consensus. Block not added.")
	}

	// Move to the next view
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

func (n *Node) PeriodicStateSaving(filename string) {
	go func() {
		for {
			err := n.Blockchain.SaveBlockchain(filename)
			if err != nil {
				fmt.Printf("Node %s failed to save blockchain: %v\n", n.ID, err)
			} else {
				fmt.Printf("Node %s successfully saved blockchain state\n", n.ID)
			}
			time.Sleep(10 * time.Second)
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
	go func() {
		n.Inbox <- msg
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
